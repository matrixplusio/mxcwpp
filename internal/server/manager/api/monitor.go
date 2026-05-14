// Package api 提供 HTTP API 处理器
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/IBM/sarama"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
	"github.com/imkerbos/mxsec-platform/internal/server/prometheus"
)

// monitorStartTime 记录 Manager 进程启动时间，用于计算运行时长
var monitorStartTime = time.Now()

const consumerGroupID = "mxsec-consumer"

// MonitorHandler 是系统监控 API 处理器
type MonitorHandler struct {
	cfg              *config.Config
	db               *gorm.DB
	chConn           chdriver.Conn      // 可为 nil
	prometheusClient *prometheus.Client // 可为 nil
	acRegistry       *sd.Registry
	logger           *zap.Logger
	redisClient      *redis.Client // 可为 nil
	sfGroup          singleflight.Group
}

// NewMonitorHandler 创建 MonitorHandler
func NewMonitorHandler(cfg *config.Config, db *gorm.DB, chConn chdriver.Conn, promClient *prometheus.Client, acRegistry *sd.Registry, logger *zap.Logger, redisClient *redis.Client) *MonitorHandler {
	return &MonitorHandler{
		cfg:              cfg,
		db:               db,
		chConn:           chConn,
		prometheusClient: promClient,
		acRegistry:       acRegistry,
		logger:           logger,
		redisClient:      redisClient,
	}
}

// ---- /monitor/host ----

// GetHostMonitor godoc
// GET /api/v1/monitor/host?range=1h|6h|24h
// 返回全局主机资源使用概览 + 时间序列趋势（聚合所有在线 Agent 上报数据）
func (h *MonitorHandler) GetHostMonitor(c *gin.Context) {
	rangeParam := c.DefaultQuery("range", "1h")
	var duration time.Duration
	var cacheTTL time.Duration
	switch rangeParam {
	case "6h":
		duration = 6 * time.Hour
		cacheTTL = 3 * time.Minute
	case "24h":
		duration = 24 * time.Hour
		cacheTTL = 10 * time.Minute
	default:
		rangeParam = "1h"
		duration = 1 * time.Hour
		cacheTTL = 60 * time.Second
	}

	ctx := c.Request.Context()
	cacheKey := "mxsec:cache:monitor:host:" + rangeParam

	// 尝试从 Redis 缓存读取
	if h.redisClient != nil {
		if cached, err := h.redisClient.Get(ctx, cacheKey).Bytes(); err == nil {
			c.Data(http.StatusOK, "application/json; charset=utf-8", cached)
			return
		}
	}

	// singleflight：防止缓存过期惊群
	jsonBytes, err, _ := h.sfGroup.Do(cacheKey, func() (interface{}, error) {
		now := time.Now()
		start := now.Add(-duration)
		overview, cpu, memory, disk, network := h.queryHostMetrics(ctx, start, now, duration)
		return json.Marshal(gin.H{
			"code": 0,
			"data": gin.H{
				"overview":   overview,
				"cpu":        cpu,
				"memory":     memory,
				"disk":       disk,
				"network":    network,
				"partitions": []gin.H{},
			},
		})
	})
	if err != nil {
		h.logger.Error("计算 Monitor 指标失败", zap.Error(err))
		InternalError(c, "指标查询失败")
		return
	}

	data := jsonBytes.([]byte)

	// 写入 Redis 缓存
	if h.redisClient != nil {
		h.redisClient.Set(ctx, cacheKey, data, cacheTTL)
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

type hostOverview struct {
	CPU             float64 `json:"cpu"`
	Memory          float64 `json:"memory"`
	Disk            float64 `json:"disk"`
	Load            float64 `json:"load"`
	CPUTrend        float64 `json:"cpuTrend"`
	MemoryTrend     float64 `json:"memoryTrend"`
	DiskTrend       float64 `json:"diskTrend"`
	LoadTrend       float64 `json:"loadTrend"`
	AgentCPU        float64 `json:"agentCpu"`
	AgentMemMB      float64 `json:"agentMemMB"`
	AgentMemPercent float64 `json:"agentMemPercent"`
}

type metricPoint struct {
	Time  string  `json:"time"`
	Usage float64 `json:"usage,omitempty"`
	Read  float64 `json:"read,omitempty"`
	Write float64 `json:"write,omitempty"`
	In    float64 `json:"inbound,omitempty"`
	Out   float64 `json:"outbound,omitempty"`
}

// queryHostMetrics 查全局指标，统一走 Prometheus
func (h *MonitorHandler) queryHostMetrics(ctx context.Context, start, end time.Time, duration time.Duration) (
	overview *hostOverview, cpu, memory, disk, network []metricPoint,
) {
	overview = &hostOverview{}
	cpu = []metricPoint{}
	memory = []metricPoint{}
	disk = []metricPoint{}
	network = []metricPoint{}

	if h.prometheusClient != nil {
		return h.queryHostMetricsFromPrometheus(ctx, start, end, duration)
	}
	return
}

// queryHostMetricsFromPrometheus 通过 PromQL 查询全局（所有主机）聚合指标
func (h *MonitorHandler) queryHostMetricsFromPrometheus(ctx context.Context, start, end time.Time, duration time.Duration) (
	overview *hostOverview, cpu, memory, disk, network []metricPoint,
) {
	overview = &hostOverview{}
	cpu = []metricPoint{}
	memory = []metricPoint{}
	disk = []metricPoint{}
	network = []metricPoint{}

	var step string
	var timeFmt string
	switch {
	case duration <= 2*time.Hour:
		step = "5m"
		timeFmt = "15:04"
	case duration <= 12*time.Hour:
		step = "15m"
		timeFmt = "15:04"
	default:
		step = "1h"
		timeFmt = "01-02 15:04"
	}

	// 聚合所有主机的平均值
	queries := map[string]string{
		"cpu":               `avg(mxsec_host_cpu_usage)`,
		"mem":               `avg(mxsec_host_mem_usage)`,
		"disk_usage":        `avg(mxsec_host_disk_usage)`,
		"net_in":            `sum(mxsec_host_net_in)`,
		"net_out":           `sum(mxsec_host_net_out)`,
		"disk_read":         `sum(mxsec_host_disk_read_bytes)`,
		"disk_write":        `sum(mxsec_host_disk_write_bytes)`,
		"agent_cpu":         `avg(mxsec_agent_cpu_usage)`,
		"agent_mem":         `avg(mxsec_agent_mem_rss)`,
		"agent_mem_percent": `avg(mxsec_agent_mem_percent)`,
	}

	type point struct {
		t time.Time
		v float64
	}
	results := make(map[string][]point)
	for key, q := range queries {
		res, err := h.prometheusClient.QueryRange(ctx, q, start, end, step)
		if err != nil {
			h.logger.Warn("Prometheus 查询失败", zap.String("query", q), zap.Error(err))
			continue
		}
		if len(res.Data.Result) == 0 {
			continue
		}
		for _, v := range res.Data.Result[0].Values {
			if len(v) < 2 {
				continue
			}
			ts, ok := v[0].(float64)
			if !ok {
				continue
			}
			var val float64
			switch sv := v[1].(type) {
			case string:
				if _, scanErr := fmt.Sscanf(sv, "%f", &val); scanErr != nil {
					continue
				}
			case float64:
				val = sv
			default:
				continue
			}
			results[key] = append(results[key], point{time.Unix(int64(ts), 0), val})
		}
	}

	// 以 cpu 时间序列为基准构建时间轴
	for _, p := range results["cpu"] {
		t := p.t.Format(timeFmt)
		cpu = append(cpu, metricPoint{Time: t, Usage: p.v})
	}
	for _, p := range results["mem"] {
		memory = append(memory, metricPoint{Time: p.t.Format(timeFmt), Usage: p.v})
	}

	drMap := make(map[string]float64)
	for _, p := range results["disk_read"] {
		drMap[p.t.Format(timeFmt)] = p.v / 1024
	}
	for _, p := range results["disk_write"] {
		t := p.t.Format(timeFmt)
		disk = append(disk, metricPoint{Time: t, Read: drMap[t], Write: p.v / 1024})
	}

	niMap := make(map[string]float64)
	for _, p := range results["net_in"] {
		niMap[p.t.Format(timeFmt)] = p.v / 1024
	}
	for _, p := range results["net_out"] {
		t := p.t.Format(timeFmt)
		network = append(network, metricPoint{Time: t, In: niMap[t], Out: p.v / 1024})
	}

	// 取最后一个点作为 overview，保留 1 位小数
	if len(results["cpu"]) > 0 {
		overview.CPU = math.Round(results["cpu"][len(results["cpu"])-1].v*10) / 10
	}
	if len(results["mem"]) > 0 {
		overview.Memory = math.Round(results["mem"][len(results["mem"])-1].v*10) / 10
	}
	if len(results["disk_usage"]) > 0 {
		overview.Disk = math.Round(results["disk_usage"][len(results["disk_usage"])-1].v*10) / 10
	}
	if len(results["agent_cpu"]) > 0 {
		overview.AgentCPU = math.Round(results["agent_cpu"][len(results["agent_cpu"])-1].v*10) / 10
	}
	if len(results["agent_mem"]) > 0 {
		// bytes -> MB
		overview.AgentMemMB = math.Round(results["agent_mem"][len(results["agent_mem"])-1].v/1024/1024*10) / 10
	}
	if len(results["agent_mem_percent"]) > 0 {
		overview.AgentMemPercent = math.Round(results["agent_mem_percent"][len(results["agent_mem_percent"])-1].v*10) / 10
	}
	return
}

// ---- /monitor/services ----

// GetServicesMonitor godoc
// GET /api/v1/monitor/services?range=1h|6h|24h
// 返回后端服务状态与连接统计
func (h *MonitorHandler) GetServicesMonitor(c *gin.Context) {
	services := h.collectServiceStatus()
	connections := h.collectConnectionStats()

	Success(c, gin.H{
		"services":    services,
		"qps":         []gin.H{}, // QPS 需要 Prometheus 集成，当前返回空
		"latency":     []gin.H{}, // 延迟分位数同上
		"connections": connections,
	})
}

type serviceInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	QPS     int    `json:"qps"`
	CPU     int    `json:"cpu"`
	Memory  string `json:"memory"`
	PID     string `json:"pid"`
	Uptime  string `json:"uptime"`
	Version string `json:"version"`
	Detail  string `json:"detail,omitempty"`
}

func (h *MonitorHandler) collectServiceStatus() []serviceInfo {
	services := []serviceInfo{{
		Name:    "Manager",
		Status:  "healthy",
		PID:     fmt.Sprintf("%d", os.Getpid()),
		Uptime:  formatUptime(time.Since(monitorStartTime)),
		Version: BuildVersion,
		Memory:  currentMemUsage(),
	}}

	services = append(services, h.checkACStatus(), h.checkConsumerStatus(), h.checkMySQLStatus(), h.checkRedisStatus(), h.checkClickHouseStatus(), h.checkPrometheusStatus())
	if h.cfg != nil && h.cfg.Kafka.Enabled && len(h.cfg.Kafka.Brokers) > 0 {
		services = append(services, h.checkKafkaStatus())
	}

	return services
}

func (h *MonitorHandler) checkACStatus() serviceInfo {
	info := serviceInfo{Name: "AgentCenter", PID: "--", Uptime: "--", Version: "--", Memory: "--"}
	if h.acRegistry == nil {
		info.Status = "error"
		return info
	}
	instances := h.acRegistry.ListAll()
	if len(instances) == 0 {
		info.Status = "error"
		return info
	}
	healthy := h.acRegistry.ListHealthy()
	if len(healthy) == 0 {
		info.Status = "warning"
	} else {
		info.Status = "healthy"
	}
	// 统计所有 AC 实例的在线连接数之和
	var totalConn int64
	for _, inst := range instances {
		totalConn += inst.ConnCount
	}
	info.QPS = int(totalConn) // 用连接数作为 QPS 的近似（无 Prometheus 时）
	info.Memory = fmt.Sprintf("%d 实例", len(instances))
	info.Version = fmt.Sprintf("%d healthy", len(healthy))
	info.Detail = "展示 AC 注册实例数与在线连接情况"
	return info
}

func (h *MonitorHandler) checkConsumerStatus() serviceInfo {
	info := serviceInfo{
		Name:    "Consumer",
		PID:     "--",
		Uptime:  "--",
		Version: consumerGroupID,
		Memory:  "--",
	}
	if h.cfg == nil || !h.cfg.Kafka.Enabled || len(h.cfg.Kafka.Brokers) == 0 {
		info.Status = "error"
		info.Detail = "Kafka 未启用，Consumer 不可用"
		return info
	}

	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = sarama.V2_6_0_0
	saramaCfg.Net.DialTimeout = 2 * time.Second
	saramaCfg.Net.ReadTimeout = 2 * time.Second
	saramaCfg.Net.WriteTimeout = 2 * time.Second
	saramaCfg.Metadata.Timeout = 3 * time.Second

	client, err := sarama.NewClient(h.cfg.Kafka.Brokers, saramaCfg)
	if err != nil {
		info.Status = "error"
		info.Detail = "无法连接 Kafka 获取 Consumer Group 状态"
		return info
	}
	defer client.Close()

	admin, err := sarama.NewClusterAdminFromClient(client)
	if err != nil {
		info.Status = "error"
		info.Detail = "无法创建 Kafka Admin 客户端"
		return info
	}
	defer admin.Close()

	descriptions, err := admin.DescribeConsumerGroups([]string{consumerGroupID})
	if err != nil || len(descriptions) == 0 {
		info.Status = "error"
		info.Detail = "未发现 Consumer Group"
		return info
	}

	desc := descriptions[0]
	memberCount := len(desc.Members)
	info.QPS = memberCount
	info.Version = desc.State

	var lag int64
	if offsets, offsetErr := admin.ListConsumerGroupOffsets(consumerGroupID, nil); offsetErr == nil {
		for topic, partitions := range offsets.Blocks {
			for partition, block := range partitions {
				if block == nil || block.Offset < 0 {
					continue
				}
				newest, newestErr := client.GetOffset(topic, partition, sarama.OffsetNewest)
				if newestErr != nil {
					continue
				}
				if newest > block.Offset {
					lag += newest - block.Offset
				}
			}
		}
	}

	info.Memory = fmt.Sprintf("lag %d", lag)
	info.Detail = fmt.Sprintf("group=%s, members=%d", consumerGroupID, memberCount)

	switch {
	case memberCount == 0:
		info.Status = "error"
	case lag > 1000 || !strings.EqualFold(desc.State, "Stable"):
		info.Status = "warning"
	default:
		info.Status = "healthy"
	}

	return info
}

func (h *MonitorHandler) checkMySQLStatus() serviceInfo {
	info := serviceInfo{Name: "MySQL", PID: "--", Uptime: "--", Version: "8.0+", Memory: "--"}
	if h.db == nil {
		info.Status = "error"
		return info
	}
	sqlDB, err := h.db.DB()
	if err != nil {
		info.Status = "error"
		return info
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		info.Status = "error"
		return info
	}
	stats := sqlDB.Stats()
	info.Status = "healthy"
	info.QPS = stats.InUse
	info.Memory = fmt.Sprintf("%d 连接", stats.OpenConnections)
	info.Detail = mysqlAddress(h.cfg)
	return info
}

func (h *MonitorHandler) checkRedisStatus() serviceInfo {
	info := serviceInfo{Name: "Redis", PID: "--", Uptime: "--", Version: "--", Memory: "--"}
	if h.redisClient == nil {
		info.Status = "error"
		return info
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.redisClient.Ping(ctx).Err(); err != nil {
		info.Status = "error"
		return info
	}

	serverInfo, err := h.redisClient.Info(ctx, "server").Result()
	if err == nil {
		if version := redisInfoValue(serverInfo, "redis_version"); version != "" {
			info.Version = version
		}
		if uptime := redisInfoValue(serverInfo, "uptime_in_seconds"); uptime != "" {
			if seconds, convErr := strconv.ParseInt(uptime, 10, 64); convErr == nil {
				info.Uptime = formatUptime(time.Duration(seconds) * time.Second)
			}
		}
	}

	statsInfo, err := h.redisClient.Info(ctx, "stats").Result()
	if err == nil {
		if ops := redisInfoValue(statsInfo, "instantaneous_ops_per_sec"); ops != "" {
			if value, convErr := strconv.Atoi(ops); convErr == nil {
				info.QPS = value
			}
		}
	}

	clientsInfo, err := h.redisClient.Info(ctx, "clients").Result()
	if err == nil {
		if connected := redisInfoValue(clientsInfo, "connected_clients"); connected != "" {
			info.Memory = connected + " 客户端"
		}
	}

	memoryInfo, err := h.redisClient.Info(ctx, "memory").Result()
	if err == nil {
		if used := redisInfoValue(memoryInfo, "used_memory_human"); used != "" {
			info.Memory = used
		}
	}

	info.Status = "healthy"
	info.Detail = redisAddress(h.cfg)
	return info
}

func (h *MonitorHandler) checkClickHouseStatus() serviceInfo {
	info := serviceInfo{Name: "ClickHouse", PID: "--", Uptime: "--", Version: "--", Memory: "--"}
	if h.chConn == nil {
		info.Status = "error"
		return info
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var version string
	if err := h.chConn.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		info.Status = "error"
		return info
	}
	info.Version = version

	var queryCount uint64
	if err := h.chConn.QueryRow(ctx, "SELECT value FROM system.metrics WHERE metric = 'Query'").Scan(&queryCount); err == nil {
		info.QPS = int(queryCount)
	}

	var memoryBytes uint64
	if err := h.chConn.QueryRow(ctx, "SELECT value FROM system.asynchronous_metrics WHERE metric = 'MemoryResident'").Scan(&memoryBytes); err == nil && memoryBytes > 0 {
		info.Memory = humanizeBytes(memoryBytes)
	}

	info.Status = "healthy"
	info.Detail = clickHouseAddress(h.cfg)
	return info
}

func (h *MonitorHandler) checkPrometheusStatus() serviceInfo {
	info := serviceInfo{Name: "Prometheus", PID: "--", Uptime: "--", Version: "--", Memory: "--"}
	if h.prometheusClient == nil {
		info.Status = "error"
		return info
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	buildInfo, err := h.prometheusClient.QueryInstant(ctx, "prometheus_build_info", nil)
	if err != nil {
		info.Status = "error"
		return info
	}

	info.Status = "healthy"
	if len(buildInfo.Data.Result) > 0 {
		if version := buildInfo.Data.Result[0].Metric["version"]; version != "" {
			info.Version = version
		}
	}

	upResult, err := h.prometheusClient.QueryInstant(ctx, "up", nil)
	if err == nil {
		info.Memory = fmt.Sprintf("%d targets", len(upResult.Data.Result))
	}

	info.Detail = "Prometheus 数据源在线"
	return info
}

func (h *MonitorHandler) checkKafkaStatus() serviceInfo {
	totalBrokers := len(h.cfg.Kafka.Brokers)
	info := serviceInfo{
		Name:    "Kafka",
		PID:     "--",
		Uptime:  "--",
		Version: "KRaft",
		Memory:  fmt.Sprintf("0/%d brokers", totalBrokers),
	}

	saramaCfg := sarama.NewConfig()
	saramaCfg.Version = sarama.V2_6_0_0
	saramaCfg.Net.DialTimeout = 2 * time.Second
	saramaCfg.Net.ReadTimeout = 2 * time.Second
	saramaCfg.Net.WriteTimeout = 2 * time.Second
	saramaCfg.Metadata.Timeout = 3 * time.Second

	client, err := sarama.NewClient(h.cfg.Kafka.Brokers, saramaCfg)
	if err != nil {
		info.Status = "error"
		return info
	}
	defer client.Close()

	brokers := client.Brokers()
	info.Memory = fmt.Sprintf("%d/%d brokers", len(brokers), totalBrokers)
	info.QPS = len(brokers)

	if _, err := client.Controller(); err != nil {
		info.Status = "warning"
		info.Detail = "Controller 未就绪"
		return info
	}

	if len(brokers) < totalBrokers {
		info.Status = "warning"
		info.Detail = "部分 broker 未就绪"
		return info
	}

	info.Status = "healthy"
	info.Detail = strings.Join(h.cfg.Kafka.Brokers, ", ")
	return info
}

type connectionStat struct {
	Service           string `json:"service"`
	Protocol          string `json:"protocol"`
	Address           string `json:"address"`
	ActiveConnections int    `json:"activeConnections"`
	TotalConnections  int    `json:"totalConnections"`
	Status            string `json:"status"`
}

func (h *MonitorHandler) collectConnectionStats() []connectionStat {
	var stats []connectionStat
	mysqlService := h.checkMySQLStatus()
	redisService := h.checkRedisStatus()
	clickHouseService := h.checkClickHouseStatus()
	kafkaStatus := "active"
	consumerService := h.checkConsumerStatus()
	if h.cfg != nil && h.cfg.Kafka.Enabled && len(h.cfg.Kafka.Brokers) > 0 {
		kafkaStatus = connectionStatusFromService(h.checkKafkaStatus().Status)
	}

	managerAddress := "0.0.0.0:8080"
	if h.cfg != nil {
		managerAddress = h.cfg.Server.HTTP.Address()
	}
	stats = append(stats, connectionStat{
		Service:           "Manager",
		Protocol:          "HTTP",
		Address:           managerAddress,
		ActiveConnections: 0,
		TotalConnections:  0,
		Status:            "active",
	})

	if h.db != nil {
		if sqlDB, err := h.db.DB(); err == nil {
			dbStats := sqlDB.Stats()
			stats = append(stats, connectionStat{
				Service:           "MySQL",
				Protocol:          "TCP",
				Address:           mysqlAddress(h.cfg),
				ActiveConnections: dbStats.InUse,
				TotalConnections:  dbStats.OpenConnections,
				Status:            connectionStatusFromService(mysqlService.Status),
			})
		}
	}

	// AgentCenter gRPC 连接（来自 SD 注册表）
	if h.acRegistry != nil {
		for _, inst := range h.acRegistry.ListAll() {
			status := "active"
			if !inst.Healthy {
				status = "warning"
			}
			stats = append(stats, connectionStat{
				Service:           fmt.Sprintf("AgentCenter(%s)", inst.ID),
				Protocol:          "gRPC",
				Address:           inst.GRPCAddr,
				ActiveConnections: int(inst.ConnCount),
				TotalConnections:  int(inst.ConnCount),
				Status:            status,
			})
		}
	}

	if h.redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		active := 0
		if info, err := h.redisClient.Info(ctx, "clients").Result(); err == nil {
			if connected := redisInfoValue(info, "connected_clients"); connected != "" {
				if value, convErr := strconv.Atoi(connected); convErr == nil {
					active = value
				}
			}
		}
		stats = append(stats, connectionStat{
			Service:           "Redis",
			Protocol:          "TCP",
			Address:           redisAddress(h.cfg),
			ActiveConnections: active,
			TotalConnections:  active,
			Status:            connectionStatusFromService(redisService.Status),
		})
		cancel()
	}

	if h.chConn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		active := 0
		if err := h.chConn.QueryRow(ctx, "SELECT value FROM system.metrics WHERE metric = 'TCPConnection'").Scan(&active); err != nil {
			active = 0
		}
		stats = append(stats, connectionStat{
			Service:           "ClickHouse",
			Protocol:          "TCP",
			Address:           clickHouseAddress(h.cfg),
			ActiveConnections: active,
			TotalConnections:  active,
			Status:            connectionStatusFromService(clickHouseService.Status),
		})
		cancel()
	}

	if h.cfg != nil && h.cfg.Kafka.Enabled {
		stats = append(stats, connectionStat{
			Service:           "Consumer",
			Protocol:          "Kafka Group",
			Address:           consumerGroupID,
			ActiveConnections: consumerService.QPS,
			TotalConnections:  consumerService.QPS,
			Status:            connectionStatusFromService(consumerService.Status),
		})
		for _, broker := range h.cfg.Kafka.Brokers {
			stats = append(stats, connectionStat{
				Service:           "Kafka",
				Protocol:          "TCP",
				Address:           broker,
				ActiveConnections: 0,
				TotalConnections:  0,
				Status:            kafkaStatus,
			})
		}
	}

	if stats == nil {
		stats = []connectionStat{}
	}
	return stats
}

func redisInfoValue(info, key string) string {
	scanner := bufio.NewScanner(strings.NewReader(info))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func mysqlAddress(cfg *config.Config) string {
	if cfg == nil {
		return "mysql:3306"
	}
	return fmt.Sprintf("%s:%d", cfg.Database.MySQL.Host, cfg.Database.MySQL.Port)
}

func redisAddress(cfg *config.Config) string {
	if cfg == nil {
		return "redis:6379"
	}
	return cfg.Redis.Addr
}

func clickHouseAddress(cfg *config.Config) string {
	if cfg == nil || len(cfg.ClickHouse.Addrs) == 0 {
		return "clickhouse:9000"
	}
	return strings.Join(cfg.ClickHouse.Addrs, ", ")
}

func humanizeBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func connectionStatusFromService(status string) string {
	switch status {
	case "healthy":
		return "active"
	case "warning":
		return "warning"
	default:
		return "error"
	}
}

// ---- /monitor/service-alerts ----

// GetServiceAlerts 获取服务告警列表
// GET /api/v1/monitor/service-alerts
func (h *MonitorHandler) GetServiceAlerts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	severity := c.Query("severity")
	service := c.Query("service")
	status := c.Query("status")
	search := c.Query("search")

	query := h.db.Model(&model.Alert{}).Where("category = ?", "service")

	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if service != "" {
		query = query.Where("title = ?", service)
	}
	if status != "" {
		if status == "firing" {
			query = query.Where("status = ?", model.AlertStatusActive)
		} else {
			query = query.Where("status = ?", status)
		}
	}
	if search != "" {
		query = query.Where("description LIKE ?", "%"+search+"%")
	}

	var total int64
	query.Count(&total)

	var alerts []model.Alert
	offset := (page - 1) * pageSize
	query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&alerts)

	// 构建前端格式
	items := make([]gin.H, 0, len(alerts))
	for _, a := range alerts {
		st := "firing"
		if a.Status == model.AlertStatusResolved {
			st = "resolved"
		}
		item := gin.H{
			"id":        a.ID,
			"createdAt": a.CreatedAt,
			"severity":  a.Severity,
			"service":   a.Title,
			"message":   a.Description,
			"status":    st,
		}
		if a.ResolvedAt != nil {
			item["resolvedAt"] = a.ResolvedAt
		}
		items = append(items, item)
	}

	// 统计各级别数量
	var statRows []struct {
		Status   string `gorm:"column:status"`
		Severity string `gorm:"column:severity"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	h.db.Model(&model.Alert{}).
		Select("status, severity, COUNT(*) as cnt").
		Where("category = ?", "service").
		Group("status, severity").
		Scan(&statRows)

	var critical, warning, info, resolved int64
	for _, r := range statRows {
		if r.Status == string(model.AlertStatusResolved) {
			resolved += r.Cnt
		} else {
			switch r.Severity {
			case "critical":
				critical += r.Cnt
			case "warning":
				warning += r.Cnt
			case "info":
				info += r.Cnt
			}
		}
	}

	Success(c, gin.H{
		"items": items,
		"total": total,
		"stats": gin.H{
			"critical": critical,
			"warning":  warning,
			"info":     info,
			"resolved": resolved,
		},
	})
}

// AckServiceAlert 确认服务告警
// POST /api/v1/monitor/service-alerts/:id/ack
func (h *MonitorHandler) AckServiceAlert(c *gin.Context) {
	id := c.Param("id")

	now := time.Now()
	result := h.db.Model(&model.Alert{}).
		Where("id = ? AND category = ? AND status = ?", id, "service", model.AlertStatusActive).
		Updates(map[string]interface{}{
			"status":      model.AlertStatusResolved,
			"resolved_at": now,
		})

	if result.Error != nil {
		h.logger.Error("确认服务告警失败", zap.String("id", id), zap.Error(result.Error))
		InternalError(c, "操作失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "告警不存在或已处理")
		return
	}

	SuccessMessage(c, "已确认")
}

// ---- 工具函数 ----

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func currentMemUsage() string {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	mb := ms.Alloc / 1024 / 1024
	return fmt.Sprintf("%d MB", mb)
}
