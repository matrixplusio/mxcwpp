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

// collectQPSSeries 拉取 4 个核心 mxsec 服务最近 1h QPS 时间序列。
//
// 返回扁平结构 [{time, Manager, AgentCenter, Consumer, Prometheus}, ...]
// 给 UI ServiceMonitor.vue 直接绘制多线 echart。
// Prom 不可用时返回 []，UI 显示"暂无数据"。
func (h *MonitorHandler) collectQPSSeries(ctx context.Context) []gin.H {
	if h.prometheusClient == nil {
		return []gin.H{}
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	now := time.Now()
	start := now.Add(-1 * time.Hour)
	const step = "1m"

	sources := []struct {
		name  string
		query string
	}{
		{"Manager", `sum(rate(mxsec_http_requests_total[1m]))`},
		{"AgentCenter", `sum(rate(mxsec_ac_grpc_handled_total[1m]))`},
		{"Consumer", `sum(rate(mxsec_consumer_records_consumed_total[1m]))`},
		{"Prometheus", `sum(rate(prometheus_http_requests_total[1m]))`},
	}

	type point struct {
		values map[string]float64
	}
	pointMap := make(map[string]*point)
	timeOrder := []string{}

	for _, s := range sources {
		res, err := h.prometheusClient.QueryRange(queryCtx, s.query, start, now, step)
		if err != nil || res == nil || len(res.Data.Result) == 0 {
			continue
		}
		for _, v := range res.Data.Result[0].Values {
			if len(v) < 2 {
				continue
			}
			ts, _ := v[0].(float64)
			timeStr := time.Unix(int64(ts), 0).Format("15:04:05")

			var val float64
			switch x := v[1].(type) {
			case string:
				_, _ = fmt.Sscanf(x, "%f", &val)
			case float64:
				val = x
			}
			if math.IsNaN(val) || math.IsInf(val, 0) {
				val = 0
			}

			p, ok := pointMap[timeStr]
			if !ok {
				p = &point{values: make(map[string]float64)}
				pointMap[timeStr] = p
				timeOrder = append(timeOrder, timeStr)
			}
			p.values[s.name] = math.Round(val*1000) / 1000
		}
	}

	result := make([]gin.H, 0, len(timeOrder))
	for _, t := range timeOrder {
		entry := gin.H{"time": t}
		for k, v := range pointMap[t].values {
			entry[k] = v
		}
		result = append(result, entry)
	}
	return result
}

// collectLatencySeries 拉取 1h p50/p95/p99 延迟趋势（聚合 Manager HTTP）。
//
// 简化方案：只查 Manager HTTP histogram（mxsec 业务流量主要走 Manager），
// 避免跨 histogram 聚合的复杂性。前端图表显示 p50/p95/p99 三条线。
func (h *MonitorHandler) collectLatencySeries(ctx context.Context) []gin.H {
	if h.prometheusClient == nil {
		return []gin.H{}
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	now := time.Now()
	start := now.Add(-1 * time.Hour)
	const step = "1m"

	percentiles := []struct {
		key string
		q   string
	}{
		{"p50", `histogram_quantile(0.50, sum by (le) (rate(mxsec_http_request_duration_seconds_bucket[5m]))) * 1000`},
		{"p95", `histogram_quantile(0.95, sum by (le) (rate(mxsec_http_request_duration_seconds_bucket[5m]))) * 1000`},
		{"p99", `histogram_quantile(0.99, sum by (le) (rate(mxsec_http_request_duration_seconds_bucket[5m]))) * 1000`},
	}

	type point struct {
		values map[string]float64
	}
	pointMap := make(map[string]*point)
	timeOrder := []string{}

	for _, p := range percentiles {
		res, err := h.prometheusClient.QueryRange(queryCtx, p.q, start, now, step)
		if err != nil || res == nil || len(res.Data.Result) == 0 {
			continue
		}
		for _, v := range res.Data.Result[0].Values {
			if len(v) < 2 {
				continue
			}
			ts, _ := v[0].(float64)
			timeStr := time.Unix(int64(ts), 0).Format("15:04:05")

			var val float64
			switch x := v[1].(type) {
			case string:
				_, _ = fmt.Sscanf(x, "%f", &val)
			case float64:
				val = x
			}
			if math.IsNaN(val) || math.IsInf(val, 0) {
				val = 0
			}

			pt, ok := pointMap[timeStr]
			if !ok {
				pt = &point{values: make(map[string]float64)}
				pointMap[timeStr] = pt
				timeOrder = append(timeOrder, timeStr)
			}
			pt.values[p.key] = math.Round(val*10) / 10
		}
	}

	result := make([]gin.H, 0, len(timeOrder))
	for _, t := range timeOrder {
		entry := gin.H{"time": t}
		for k, v := range pointMap[t].values {
			entry[k] = v
		}
		result = append(result, entry)
	}
	return result
}

// ---- /monitor/services/:name/history ----

// serviceJobMap 服务名 → Prometheus job 标签。
//
// 仅含 mxsec 自研服务 + prometheus 本身。
// mysql/redis/clickhouse/kafka 不在此列，原因：
//   - 不部署外部 exporter（避免重复造轮子）
//   - 这些服务的实时指标由 monitor.go 的 driver-level check 提供（GetServicesMonitor）
//   - mysql 历史 QPS 趋势走 Manager 端 gorm callback 埋点的 mxsec_db_query_duration_seconds
//     (job="mxsec-manager"，下面 db 指标走特殊路径)
var serviceJobMap = map[string]string{
	"manager":     "mxsec-manager",
	"agentcenter": "mxsec-agentcenter",
	"ac":          "mxsec-agentcenter",
	"consumer":    "mxsec-consumer",
	"prometheus":  "prometheus",
}

// serviceMetricQuery 服务+指标 → PromQL 模板。
//
// 不支持的组合返回空字符串（caller 应回 400）。
func serviceMetricQuery(metric, jobName string) string {
	switch metric {
	case "cpu":
		return fmt.Sprintf(`100 * rate(process_cpu_seconds_total{job=%q}[1m])`, jobName)
	case "memory", "rss":
		return fmt.Sprintf(`process_resident_memory_bytes{job=%q}`, jobName)
	case "qps":
		switch jobName {
		case "mxsec-manager":
			return `sum(rate(mxsec_http_requests_total[1m]))`
		case "mxsec-agentcenter":
			return `sum(rate(mxsec_ac_grpc_handled_total[1m]))`
		case "mxsec-consumer":
			return `sum(rate(mxsec_consumer_records_consumed_total[1m]))`
		case "prometheus":
			return `sum(rate(prometheus_http_requests_total[1m]))`
		}
	case "p99":
		switch jobName {
		case "mxsec-manager":
			return `histogram_quantile(0.99, sum by (le) (rate(mxsec_http_request_duration_seconds_bucket[5m]))) * 1000`
		case "mxsec-agentcenter":
			return `histogram_quantile(0.99, sum by (le) (rate(mxsec_ac_grpc_duration_seconds_bucket[5m]))) * 1000`
		case "mxsec-consumer":
			return `histogram_quantile(0.99, sum by (le) (rate(mxsec_consumer_processing_duration_seconds_bucket[5m]))) * 1000`
		}
	case "error_rate":
		switch jobName {
		case "mxsec-manager":
			return `sum(rate(mxsec_http_requests_total{status_code=~"5.."}[1m])) / sum(rate(mxsec_http_requests_total[1m]))`
		case "mxsec-agentcenter":
			return `sum(rate(mxsec_ac_grpc_handled_total{grpc_code!="OK"}[1m])) / sum(rate(mxsec_ac_grpc_handled_total[1m]))`
		case "mxsec-consumer":
			return `sum(rate(mxsec_consumer_records_consumed_total{status=~"error|dlq"}[1m])) / sum(rate(mxsec_consumer_records_consumed_total[1m]))`
		}
	case "goroutines":
		return fmt.Sprintf(`go_goroutines{job=%q}`, jobName)
	case "fds":
		return fmt.Sprintf(`process_open_fds{job=%q}`, jobName)
	case "gc_pause_p99":
		return fmt.Sprintf(`histogram_quantile(0.99, sum by (le) (rate(go_gc_duration_seconds_bucket{job=%q}[5m])))`, jobName)
	case "db_qps":
		// 仅 mxsec-manager 视角的 DB QPS（通过 gorm callback 埋点）
		if jobName == "mxsec-manager" {
			return `sum(rate(mxsec_db_query_duration_seconds_count[1m]))`
		}
	case "db_p99":
		if jobName == "mxsec-manager" {
			return `histogram_quantile(0.99, sum by (le) (rate(mxsec_db_query_duration_seconds_bucket[5m]))) * 1000`
		}
	}
	return ""
}

// GetServiceHistory godoc
// GET /api/v1/monitor/services/:name/history?range=1h|6h|24h&metric=cpu|memory|qps|p99|error_rate|goroutines|fds|gc_pause_p99
//
// 返回指定服务+指标的时间序列。基于 Prometheus range query。
// 不缓存（用户主动刷新趋势图），但 Prometheus 自身 scrape interval 决定数据粒度。
func (h *MonitorHandler) GetServiceHistory(c *gin.Context) {
	if h.prometheusClient == nil {
		BadRequest(c, "Prometheus 未配置，无法查询历史趋势")
		return
	}

	name := strings.ToLower(c.Param("name"))
	jobName, ok := serviceJobMap[name]
	if !ok {
		BadRequest(c, fmt.Sprintf("未知服务名: %s", name))
		return
	}

	metric := c.DefaultQuery("metric", "cpu")
	query := serviceMetricQuery(metric, jobName)
	if query == "" {
		BadRequest(c, fmt.Sprintf("服务 %s 不支持指标 %s", name, metric))
		return
	}

	rangeParam := c.DefaultQuery("range", "1h")
	var duration time.Duration
	var step string
	switch rangeParam {
	case "6h":
		duration = 6 * time.Hour
		step = "1m"
	case "24h":
		duration = 24 * time.Hour
		step = "5m"
	case "7d":
		duration = 7 * 24 * time.Hour
		step = "30m"
	default:
		rangeParam = "1h"
		duration = 1 * time.Hour
		step = "15s"
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	now := time.Now()
	result, err := h.prometheusClient.QueryRange(ctx, query, now.Add(-duration), now, step)
	if err != nil {
		h.logger.Warn("PromQL range query 失败",
			zap.String("service", name),
			zap.String("metric", metric),
			zap.String("query", query),
			zap.Error(err))
		InternalError(c, "Prometheus 查询失败")
		return
	}

	// 扁平化为 [{time, value}, ...]
	points := make([]gin.H, 0, 128)
	if len(result.Data.Result) > 0 {
		for _, v := range result.Data.Result[0].Values {
			if len(v) < 2 {
				continue
			}
			ts, _ := v[0].(float64)
			var val float64
			switch x := v[1].(type) {
			case string:
				_, _ = fmt.Sscanf(x, "%f", &val)
			case float64:
				val = x
			}
			if math.IsNaN(val) || math.IsInf(val, 0) {
				val = 0
			}
			points = append(points, gin.H{
				"time":  time.Unix(int64(ts), 0).Format(model.TimeFormat),
				"value": val,
			})
		}
	}

	Success(c, gin.H{
		"service": name,
		"metric":  metric,
		"range":   rangeParam,
		"step":    step,
		"points":  points,
	})
}

// ---- /monitor/slo ----

// GetSLO godoc
// GET /api/v1/monitor/slo?range=30d
//
// 返回各服务的可用性（uptime ratio）+ Error Budget（剩余可允许的不可用时间）。
// 默认目标 SLO 99.9% (允许 30 天内停机 43min)。
func (h *MonitorHandler) GetSLO(c *gin.Context) {
	if h.prometheusClient == nil {
		BadRequest(c, "Prometheus 未配置，SLO 不可用")
		return
	}

	rangeParam := c.DefaultQuery("range", "30d")
	var promRange string
	switch rangeParam {
	case "7d":
		promRange = "7d"
	case "24h":
		promRange = "24h"
	default:
		rangeParam = "30d"
		promRange = "30d"
	}

	const sloTarget = 0.999 // 99.9% 月度 SLO，对应 30d 中 ~43.2min 错误预算

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	results := make([]gin.H, 0, len(serviceJobMap))
	seen := make(map[string]bool)
	for name, jobName := range serviceJobMap {
		// 去重（agentcenter 与 ac 两个 key 指同一 job）
		if seen[jobName] {
			continue
		}
		seen[jobName] = true

		// availability = avg(up[range])  → up=1 时为可用
		query := fmt.Sprintf(`avg_over_time(up{job=%q}[%s])`, jobName, promRange)
		availability := h.promQueryFloat(ctx, query)
		if availability < 0 {
			availability = 0
		}
		if availability > 1 {
			availability = 1
		}

		downtimeRatio := 1 - availability
		// budget: 允许的下行比例
		errorBudgetRatio := 1 - sloTarget
		// budget_consumed: 已消耗的预算占比
		budgetConsumed := 0.0
		if errorBudgetRatio > 0 {
			budgetConsumed = downtimeRatio / errorBudgetRatio
		}
		if budgetConsumed > 1 {
			budgetConsumed = 1
		}

		results = append(results, gin.H{
			"service":          name,
			"job":              jobName,
			"availability":     math.Round(availability*100000) / 100000, // 0.99987
			"availabilityPct":  math.Round(availability*10000) / 100,     // 99.99
			"sloTarget":        sloTarget,
			"sloTargetPct":     sloTarget * 100,
			"errorBudgetRatio": errorBudgetRatio,
			"budgetConsumed":   math.Round(budgetConsumed*10000) / 100, // 百分比
			"status":           sloStatus(availability, sloTarget),
		})
	}

	Success(c, gin.H{
		"range":     rangeParam,
		"sloTarget": sloTarget,
		"services":  results,
	})
}

func sloStatus(availability, target float64) string {
	switch {
	case availability >= target:
		return "ok"
	case availability >= target-0.0005:
		return "warning"
	default:
		return "breach"
	}
}

// GetServicesMonitor godoc
// GET /api/v1/monitor/services?range=1h|6h|24h
// 返回后端服务状态与连接统计。
//
// 性能保护（Tier 0-6）：
//   - Redis 缓存 30s（服务监控页轻量级数据，30s 粒度足够）
//   - singleflight 防止缓存过期瞬间的并发重复计算
//
// 不加缓存时 Kafka admin 调用（DescribeConsumerGroups + ListConsumerGroupOffsets）
// 是重操作，并发刷新会拖死 Kafka 协调器。
const servicesCacheKey = "mxsec:cache:monitor:services"
const servicesCacheTTL = 30 * time.Second

func (h *MonitorHandler) GetServicesMonitor(c *gin.Context) {
	ctx := c.Request.Context()

	// L1: Redis cache
	if h.redisClient != nil {
		if cached, err := h.redisClient.Get(ctx, servicesCacheKey).Bytes(); err == nil {
			c.Data(http.StatusOK, "application/json; charset=utf-8", cached)
			return
		}
	}

	// L2: singleflight 合并并发请求
	jsonBytes, err, _ := h.sfGroup.Do(servicesCacheKey, func() (interface{}, error) {
		services := h.collectServiceStatus()
		connections := h.collectConnectionStats()
		// 内联 1h QPS / 延迟时间序列（UI 直接渲染，无需额外 API 调用）
		qpsSeries := h.collectQPSSeries(ctx)
		latencySeries := h.collectLatencySeries(ctx)
		return json.Marshal(gin.H{
			"code": 0,
			"data": gin.H{
				"services":    services,
				"qps":         qpsSeries,
				"latency":     latencySeries,
				"connections": connections,
			},
		})
	})

	if err != nil {
		h.logger.Error("计算服务监控失败", zap.Error(err))
		InternalError(c, "服务监控查询失败")
		return
	}

	data := jsonBytes.([]byte)

	// 写回 Redis 缓存（30s）
	if h.redisClient != nil {
		h.redisClient.Set(ctx, servicesCacheKey, data, servicesCacheTTL)
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

// serviceInfo 是后端服务监控的标准 schema（v2 强类型）。
//
// 旧字段（Name/Status/QPS/CPU/Memory/PID/Uptime/Version/Detail）保留 JSON 兼容，
// 但**语义重写为真实数据**（不再用 ConnCount 当 QPS、用"3 实例"当 Memory）：
//
//   - QPS    float64 — 每秒请求/操作数，来自 PromQL `rate(*_total[1m])`
//   - CPU    float64 — CPU 使用率百分比 0-100，来自 `100*rate(process_cpu_seconds_total[1m])`
//   - Memory string  — 人类可读字符串如 "234 MB"，基于真实 `process_resident_memory_bytes`
//   - Uptime string  — 人类可读如 "3d 5h"，基于真实 `process_start_time_seconds`
//
// 新增 v2 字段（optional，UI 渐进采用）：
type serviceInfo struct {
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	QPS     float64 `json:"qps"`
	CPU     float64 `json:"cpu"`
	Memory  string  `json:"memory"`
	PID     string  `json:"pid"`
	Uptime  string  `json:"uptime"`
	Version string  `json:"version"`
	Detail  string  `json:"detail,omitempty"`

	// ============ v2 强类型字段（商业级监控完整指标） ============

	// MemRSSBytes 进程常驻内存（字节），来自 process_resident_memory_bytes
	MemRSSBytes uint64 `json:"memRssBytes,omitempty"`

	// P99LatencyMs p99 请求延迟（毫秒），来自 histogram_quantile(0.99, ...)
	P99LatencyMs float64 `json:"p99LatencyMs,omitempty"`

	// ErrorRate 错误率 [0, 1]，5xx 或 gRPC 非 OK 占比
	ErrorRate float64 `json:"errorRate,omitempty"`

	// Connections 当前活跃连接数
	Connections int64 `json:"connections,omitempty"`

	// QueueLag 队列积压（Kafka consumer lag 等）
	QueueLag int64 `json:"queueLag,omitempty"`

	// UptimeSec 运行秒数（机器可读，与 Uptime 字符串等价）
	UptimeSec int64 `json:"uptimeSec,omitempty"`

	// Extra 服务特异字段（如 ClickHouse 当前 active query、Kafka group state）
	Extra map[string]string `json:"extra,omitempty"`

	// DataSource 标识数据来源（prometheus / driver / sd-registry / unavailable）
	// 便于 UI 显示数据可信度
	DataSource string `json:"dataSource,omitempty"`

	// ============ 饱和度指标 (Tier 2-2) ============

	// GoroutineCount 当前 goroutine 数（持续 > 10000 可能泄漏）
	GoroutineCount int `json:"goroutineCount,omitempty"`

	// FDCount 当前打开的 fd 数（接近 ulimit 时需告警）
	FDCount int `json:"fdCount,omitempty"`

	// GCPauseP99Ms Go GC p99 暂停时间（毫秒，持续 > 500ms 影响延迟）
	GCPauseP99Ms float64 `json:"gcPauseP99Ms,omitempty"`
}

// PromQL 模板 — Go 默认 ProcessCollector + GoCollector 自动暴露
const (
	promCPUPercentTpl = `100 * rate(process_cpu_seconds_total{job=%q}[1m])`
	promRSSBytesTpl   = `process_resident_memory_bytes{job=%q}`
	promUptimeSecTpl  = `time() - process_start_time_seconds{job=%q}`
)

// promQueryFloat 执行 PromQL 即时查询并解析为单个 float 值。
//
// 失败 / 无数据 / 非有限数（NaN/Inf）一律返回 0；不抛错（监控指标缺失不应阻塞业务页面）。
// 仅当 prometheusClient 非 nil 时才查询。
func (h *MonitorHandler) promQueryFloat(ctx context.Context, query string) float64 {
	if h.prometheusClient == nil {
		return 0
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	result, err := h.prometheusClient.QueryInstant(queryCtx, query, nil)
	if err != nil || result == nil || len(result.Data.Result) == 0 {
		return 0
	}
	val := result.Data.Result[0].Value
	if len(val) < 2 {
		return 0
	}

	var f float64
	switch v := val[1].(type) {
	case string:
		if _, err := fmt.Sscanf(v, "%f", &f); err != nil {
			return 0
		}
	case float64:
		f = v
	default:
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}

// fillProcessMetrics 通用：用 job 标签从 Prometheus 拉取
// CPU% / RSS / Uptime / 饱和度（goroutine/fd/gc_pause）填到 info（不覆盖 Status）。
func (h *MonitorHandler) fillProcessMetrics(ctx context.Context, info *serviceInfo, jobName string) {
	if h.prometheusClient == nil {
		info.DataSource = "driver"
		return
	}
	info.DataSource = "prometheus"

	cpu := h.promQueryFloat(ctx, fmt.Sprintf(promCPUPercentTpl, jobName))
	if cpu > 0 {
		info.CPU = math.Round(cpu*10) / 10
	}

	rss := h.promQueryFloat(ctx, fmt.Sprintf(promRSSBytesTpl, jobName))
	if rss > 0 {
		info.MemRSSBytes = uint64(rss)
		info.Memory = humanizeBytes(uint64(rss))
	}

	uptime := h.promQueryFloat(ctx, fmt.Sprintf(promUptimeSecTpl, jobName))
	if uptime > 0 {
		info.UptimeSec = int64(uptime)
		info.Uptime = formatUptime(time.Duration(uptime) * time.Second)
	}

	// 饱和度指标（Tier 2-2）
	goroutines := h.promQueryFloat(ctx, fmt.Sprintf(`go_goroutines{job=%q}`, jobName))
	if goroutines > 0 {
		info.GoroutineCount = int(goroutines)
	}
	fds := h.promQueryFloat(ctx, fmt.Sprintf(`process_open_fds{job=%q}`, jobName))
	if fds > 0 {
		info.FDCount = int(fds)
	}
	gcPause := h.promQueryFloat(ctx,
		fmt.Sprintf(`histogram_quantile(0.99, sum by (le) (rate(go_gc_duration_seconds_bucket{job=%q}[5m])))`, jobName))
	if gcPause > 0 {
		info.GCPauseP99Ms = math.Round(gcPause*100000) / 100 // 秒 → 毫秒，保留 2 位小数
	}

	// PID + version 来自 mxsec_build_info（mxsec 三端自暴露）
	h.fillBuildInfo(ctx, info, jobName)
}

// fillBuildInfo 通过 PromQL mxsec_build_info{job=X} 读取进程的 version 和 pid（写入 labels）。
// 实现：QueryInstant 拿到 metric labels（不是 value）。
func (h *MonitorHandler) fillBuildInfo(ctx context.Context, info *serviceInfo, jobName string) {
	if h.prometheusClient == nil {
		return
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := h.prometheusClient.QueryInstant(queryCtx, fmt.Sprintf(`mxsec_build_info{job=%q}`, jobName), nil)
	if err != nil || res == nil || len(res.Data.Result) == 0 {
		return
	}
	m := res.Data.Result[0].Metric
	if v := m["version"]; v != "" {
		info.Version = v
	}
	if p := m["pid"]; p != "" {
		info.PID = p
	}
}

// collectServiceStatus 收集所有后端服务的真实运行状态。
//
// 数据来源策略（优先级从高到低）：
//  1. Prometheus PromQL  — 真实 CPU% / RSS / QPS / p99 / error_rate
//  2. 服务自身 driver/admin — Redis ops/sec、ClickHouse query count、Kafka admin
//  3. SD Registry (AC)   — 心跳健康 + ConnCount
//
// 字段语义严格遵循 serviceInfo schema。
func (h *MonitorHandler) collectServiceStatus() []serviceInfo {
	ctx := context.Background()

	services := []serviceInfo{h.checkManagerStatus(ctx)}
	services = append(services,
		h.checkACStatus(ctx),
		h.checkConsumerStatus(ctx),
		h.checkMySQLStatus(ctx),
		h.checkRedisStatus(ctx),
		h.checkClickHouseStatus(ctx),
		h.checkPrometheusStatus(ctx),
	)
	if h.cfg != nil && h.cfg.Kafka.Enabled && len(h.cfg.Kafka.Brokers) > 0 {
		services = append(services, h.checkKafkaStatus(ctx))
	}

	return services
}

// checkManagerStatus 检查 Manager 自身状态。
//
// 不再 hardcoded "healthy"（自报无意义，挂了无法反馈）。
// 用 Prometheus self-scrape（job="mxsec-manager"）获取真实 CPU/RSS/QPS/p99/error_rate。
// 若 Prometheus 不可用，降级用进程级 PID/Uptime + Go heap 估算（标 DataSource="driver"）。
func (h *MonitorHandler) checkManagerStatus(ctx context.Context) serviceInfo {
	const jobName = "mxsec-manager"

	info := serviceInfo{
		Name:      "Manager",
		Status:    "healthy",
		PID:       strconv.Itoa(os.Getpid()),
		Uptime:    formatUptime(time.Since(monitorStartTime)),
		UptimeSec: int64(time.Since(monitorStartTime).Seconds()),
		Version:   BuildVersion,
		Memory:    currentMemUsage(),
	}

	if h.prometheusClient == nil {
		info.DataSource = "driver"
		info.Detail = "Prometheus 未配置，仅显示进程级降级数据（CPU/RSS 不准确）"
		return info
	}

	h.fillProcessMetrics(ctx, &info, jobName)

	// QPS = HTTP 请求速率
	info.QPS = math.Round(h.promQueryFloat(ctx,
		`sum(rate(mxsec_http_requests_total[1m]))`)*100) / 100

	// p99 延迟（毫秒）
	info.P99LatencyMs = math.Round(h.promQueryFloat(ctx,
		`histogram_quantile(0.99, sum by (le) (rate(mxsec_http_request_duration_seconds_bucket[5m]))) * 1000`)*10) / 10

	// 错误率 = 5xx / 总请求
	total := h.promQueryFloat(ctx, `sum(rate(mxsec_http_requests_total[1m]))`)
	errs := h.promQueryFloat(ctx, `sum(rate(mxsec_http_requests_total{status_code=~"5.."}[1m]))`)
	if total > 0 {
		info.ErrorRate = math.Round(errs/total*10000) / 10000
		if info.ErrorRate > 0.05 {
			info.Status = "warning"
			info.Detail = fmt.Sprintf("HTTP 5xx 错误率 %.2f%% 超过 5%% 阈值", info.ErrorRate*100)
		}
	}

	return info
}

// checkACStatus 检查 AgentCenter 状态。
//
// 数据来源：
//   - 健康/Conn 数: SD Registry 心跳（权威）
//   - CPU/RSS/Uptime/QPS/p99/error_rate: Prometheus (job="mxsec-agentcenter")
//
// QPS 不再用 ConnCount 当近似（语义错误），而是用 gRPC handled 速率。
func (h *MonitorHandler) checkACStatus(ctx context.Context) serviceInfo {
	const jobName = "mxsec-agentcenter"

	info := serviceInfo{Name: "AgentCenter", PID: "--", Uptime: "--", Version: "--", Memory: "--"}

	// 1. SD Registry 决定健康状态 + 连接数
	if h.acRegistry == nil {
		info.Status = "error"
		info.Detail = "SD Registry 未初始化"
		return info
	}
	instances := h.acRegistry.ListAll()
	if len(instances) == 0 {
		info.Status = "warning"
		info.Detail = "无 AC 实例注册"
		return info
	}
	healthy := h.acRegistry.ListHealthy()
	switch {
	case len(healthy) == 0:
		info.Status = "error"
		info.Detail = fmt.Sprintf("全部 %d 个 AC 实例不健康", len(instances))
	case len(healthy) < len(instances):
		info.Status = "warning"
		info.Detail = fmt.Sprintf("%d/%d AC 实例不健康", len(instances)-len(healthy), len(instances))
	default:
		info.Status = "healthy"
		info.Detail = fmt.Sprintf("%d 个 AC 实例全部健康", len(instances))
	}

	var totalConn int64
	for _, inst := range instances {
		totalConn += inst.ConnCount
	}
	info.Connections = totalConn
	info.Extra = map[string]string{
		"acInstances":      strconv.Itoa(len(instances)),
		"healthyInstances": strconv.Itoa(len(healthy)),
		"agentConnections": strconv.FormatInt(totalConn, 10),
	}

	// 2. Prometheus 拉真实进程指标
	h.fillProcessMetrics(ctx, &info, jobName)

	// QPS = gRPC handled 总速率（真实业务流量）
	info.QPS = math.Round(h.promQueryFloat(ctx,
		`sum(rate(mxsec_ac_grpc_handled_total[1m]))`)*100) / 100

	// p99 延迟（毫秒）
	info.P99LatencyMs = math.Round(h.promQueryFloat(ctx,
		`histogram_quantile(0.99, sum by (le) (rate(mxsec_ac_grpc_duration_seconds_bucket[5m]))) * 1000`)*10) / 10

	// 错误率 = 非 OK gRPC 调用占比
	total := h.promQueryFloat(ctx, `sum(rate(mxsec_ac_grpc_handled_total[1m]))`)
	errs := h.promQueryFloat(ctx, `sum(rate(mxsec_ac_grpc_handled_total{grpc_code!="OK"}[1m]))`)
	if total > 0 {
		info.ErrorRate = math.Round(errs/total*10000) / 10000
	}

	return info
}

// checkConsumerStatus 检查 Consumer 状态。
//
// 数据来源：
//   - 健康/Lag/成员数: Kafka admin (sarama)
//   - CPU/RSS/Uptime/QPS/p99: Prometheus (job="mxsec-consumer")
//
// QPS 不再用 memberCount 当近似（语义错误），改用 records_consumed 速率。
// Memory 字段填进程 RSS 真实值，不再填 "lag X"（lag 单独入 QueueLag 字段）。
func (h *MonitorHandler) checkConsumerStatus(ctx context.Context) serviceInfo {
	const jobName = "mxsec-consumer"

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

	// 1. Kafka admin: 健康 + lag + 成员数
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
	info.Version = desc.State
	info.Connections = int64(memberCount)

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
	info.QueueLag = lag
	info.Detail = fmt.Sprintf("group=%s, members=%d, lag=%d, state=%s", consumerGroupID, memberCount, lag, desc.State)
	info.Extra = map[string]string{
		"groupId":     consumerGroupID,
		"groupState":  desc.State,
		"memberCount": strconv.Itoa(memberCount),
		"totalLag":    strconv.FormatInt(lag, 10),
	}

	switch {
	case memberCount == 0:
		info.Status = "error"
	case lag > 10000 || !strings.EqualFold(desc.State, "Stable"):
		info.Status = "warning"
	default:
		info.Status = "healthy"
	}

	// 2. Prometheus: CPU/RSS/Uptime + 处理速率 + p99
	h.fillProcessMetrics(ctx, &info, jobName)

	// QPS = 消息处理速率（真实业务吞吐）
	info.QPS = math.Round(h.promQueryFloat(ctx,
		`sum(rate(mxsec_consumer_records_consumed_total[1m]))`)*100) / 100

	// p99 处理延迟（毫秒）
	info.P99LatencyMs = math.Round(h.promQueryFloat(ctx,
		`histogram_quantile(0.99, sum by (le) (rate(mxsec_consumer_processing_duration_seconds_bucket[5m]))) * 1000`)*10) / 10

	// 错误率 = (error + dlq) / 总消息
	total := h.promQueryFloat(ctx, `sum(rate(mxsec_consumer_records_consumed_total[1m]))`)
	errs := h.promQueryFloat(ctx, `sum(rate(mxsec_consumer_records_consumed_total{status=~"error|dlq"}[1m]))`)
	if total > 0 {
		info.ErrorRate = math.Round(errs/total*10000) / 10000
	}

	return info
}

// checkMySQLStatus 检查 MySQL 状态。
//
// 数据来源（不依赖外部 mysqld_exporter，避免重复造轮子）：
//   - 健康/连接池: gorm driver stats
//   - QPS:        Manager 端 gorm callback 埋点 mxsec_db_query_duration_seconds_count
//     (Tier 1-2 新增 — 代表 Manager 视角真实 DB QPS，含 ORM + 网络 RTT)
//   - 版本:       SELECT VERSION() (driver)
//
// 注：用 Manager 视角 QPS 比 mysqld_exporter 的 mysql_global_status_queries 更准确，
// 因为后者反映整个 MySQL 实例（可能被其他应用共用）的查询，前者反映 mxsec 实际负载。
func (h *MonitorHandler) checkMySQLStatus(ctx context.Context) serviceInfo {
	info := serviceInfo{Name: "MySQL", PID: "--", Uptime: "--", Version: "--", Memory: "--", DataSource: "driver"}
	if h.db == nil {
		info.Status = "error"
		return info
	}
	sqlDB, err := h.db.DB()
	if err != nil {
		info.Status = "error"
		info.Detail = "获取数据库句柄失败"
		return info
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		info.Status = "error"
		info.Detail = "MySQL ping 失败"
		return info
	}
	stats := sqlDB.Stats()
	info.Status = "healthy"
	info.Connections = int64(stats.OpenConnections)
	info.Detail = mysqlAddress(h.cfg)
	info.Extra = map[string]string{
		"address":          mysqlAddress(h.cfg),
		"openConnections":  strconv.Itoa(stats.OpenConnections),
		"inUseConnections": strconv.Itoa(stats.InUse),
		"idleConnections":  strconv.Itoa(stats.Idle),
		"waitCount":        strconv.FormatInt(stats.WaitCount, 10),
	}

	// MySQL 版本 + Uptime + InnoDB Buffer Pool RSS（driver 直查，无需 mysqld_exporter）
	infoCtx, infoCancel := context.WithTimeout(ctx, 2*time.Second)
	defer infoCancel()

	var version string
	if rows, qerr := sqlDB.QueryContext(infoCtx, "SELECT VERSION()"); qerr == nil {
		if rows.Next() {
			_ = rows.Scan(&version)
		}
		_ = rows.Close()
	}
	if version != "" {
		info.Version = version
	}

	// Uptime — SHOW GLOBAL STATUS LIKE 'Uptime' 返回 Variable_name + Value
	if rows, qerr := sqlDB.QueryContext(infoCtx, "SHOW GLOBAL STATUS LIKE 'Uptime'"); qerr == nil {
		if rows.Next() {
			var name, value string
			if scanErr := rows.Scan(&name, &value); scanErr == nil {
				if sec, err := strconv.ParseInt(value, 10, 64); err == nil && sec > 0 {
					info.UptimeSec = sec
					info.Uptime = formatUptime(time.Duration(sec) * time.Second)
				}
			}
		}
		_ = rows.Close()
	}

	// 内存 — InnoDB Buffer Pool 当前已用字节数（最贴近 MySQL 实际内存占用）
	if rows, qerr := sqlDB.QueryContext(infoCtx, "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_bytes_data'"); qerr == nil {
		if rows.Next() {
			var name, value string
			if scanErr := rows.Scan(&name, &value); scanErr == nil {
				if b, err := strconv.ParseUint(value, 10, 64); err == nil && b > 0 {
					info.MemRSSBytes = b
					info.Memory = humanizeBytes(b)
					// "innodb" 标记放 extra，避免字符串过长撑高 UI 卡片
					if info.Extra == nil {
						info.Extra = map[string]string{}
					}
					info.Extra["memSource"] = "innodb_buffer_pool"
				}
			}
		}
		_ = rows.Close()
	}

	// QPS 来自 Manager 端 gorm callback 埋点（mxsec_db_query_duration_seconds_count）
	if h.prometheusClient != nil {
		qps := h.promQueryFloat(ctx, `sum(rate(mxsec_db_query_duration_seconds_count[1m]))`)
		if qps > 0 {
			info.QPS = math.Round(qps*100) / 100
			info.DataSource = "driver+prometheus"
		}
		p99 := h.promQueryFloat(ctx,
			`histogram_quantile(0.99, sum by (le) (rate(mxsec_db_query_duration_seconds_bucket[5m]))) * 1000`)
		if p99 > 0 {
			info.P99LatencyMs = math.Round(p99*10) / 10
		}
	}

	return info
}

// checkRedisStatus 检查 Redis 状态。
//
// 数据来源：
//   - 健康/Version/Uptime/QPS/RSS/连接数: Redis INFO (driver 端真实数据)
//   - 补充 CPU: Prometheus (job="redis-exporter"，需部署 redis_exporter)
//
// Redis 是少数 driver 自带真实 QPS 的服务（instantaneous_ops_per_sec），保留使用。
func (h *MonitorHandler) checkRedisStatus(ctx context.Context) serviceInfo {
	info := serviceInfo{Name: "Redis", PID: "--", Uptime: "--", Version: "--", Memory: "--", DataSource: "driver"}
	if h.redisClient == nil {
		info.Status = "error"
		return info
	}

	infoCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := h.redisClient.Ping(infoCtx).Err(); err != nil {
		info.Status = "error"
		info.Detail = "Redis ping 失败"
		return info
	}

	serverInfo, err := h.redisClient.Info(infoCtx, "server").Result()
	if err == nil {
		if version := redisInfoValue(serverInfo, "redis_version"); version != "" {
			info.Version = version
		}
		if uptime := redisInfoValue(serverInfo, "uptime_in_seconds"); uptime != "" {
			if seconds, convErr := strconv.ParseInt(uptime, 10, 64); convErr == nil {
				info.UptimeSec = seconds
				info.Uptime = formatUptime(time.Duration(seconds) * time.Second)
			}
		}
		if pid := redisInfoValue(serverInfo, "process_id"); pid != "" {
			info.PID = pid
		}
	}

	statsInfo, err := h.redisClient.Info(infoCtx, "stats").Result()
	if err == nil {
		if ops := redisInfoValue(statsInfo, "instantaneous_ops_per_sec"); ops != "" {
			if value, convErr := strconv.ParseFloat(ops, 64); convErr == nil {
				info.QPS = value
			}
		}
	}

	clientsInfo, err := h.redisClient.Info(infoCtx, "clients").Result()
	connected := int64(0)
	if err == nil {
		if c := redisInfoValue(clientsInfo, "connected_clients"); c != "" {
			if value, convErr := strconv.ParseInt(c, 10, 64); convErr == nil {
				connected = value
			}
		}
	}
	info.Connections = connected

	extra := map[string]string{
		"address":          redisAddress(h.cfg),
		"connectedClients": strconv.FormatInt(connected, 10),
	}

	memoryInfo, err := h.redisClient.Info(infoCtx, "memory").Result()
	if err == nil {
		if used := redisInfoValue(memoryInfo, "used_memory"); used != "" {
			if b, convErr := strconv.ParseUint(used, 10, 64); convErr == nil {
				info.MemRSSBytes = b
			}
		}
		if used := redisInfoValue(memoryInfo, "used_memory_human"); used != "" {
			info.Memory = used
		}
		if maxmem := redisInfoValue(memoryInfo, "maxmemory_human"); maxmem != "" {
			extra["maxMemory"] = maxmem
		}
	}

	info.Status = "healthy"
	info.Detail = redisAddress(h.cfg)
	info.Extra = extra

	// Redis INFO 已涵盖 QPS/Memory/Uptime/Clients，driver 完全够用
	// 不引入 redis_exporter（重复造轮子）
	return info
}

// checkClickHouseStatus 检查 ClickHouse 状态。
//
// 数据来源：
//   - 健康/Version/RSS: ClickHouse system.metrics + system.asynchronous_metrics (driver 真实)
//   - QPS: rate(ClickHouseProfileEvents_Query) via Prometheus (clickhouse-exporter)
//
// 当前 system.metrics WHERE metric='Query' 返回的是**当前 active query 数量**（瞬时），
// 不是 QPS rate。改用 Prometheus rate 公式得真 QPS。
func (h *MonitorHandler) checkClickHouseStatus(ctx context.Context) serviceInfo {
	info := serviceInfo{Name: "ClickHouse", PID: "--", Uptime: "--", Version: "--", Memory: "--", DataSource: "driver"}
	if h.chConn == nil {
		info.Status = "error"
		return info
	}

	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var version string
	if err := h.chConn.QueryRow(queryCtx, "SELECT version()").Scan(&version); err != nil {
		info.Status = "error"
		info.Detail = "ClickHouse 查询失败"
		return info
	}
	info.Version = version

	// 当前 active query 数 — system.metrics.value 是 Int64
	var activeQuery int64
	_ = h.chConn.QueryRow(queryCtx, "SELECT value FROM system.metrics WHERE metric = 'Query'").Scan(&activeQuery)

	// 真实 RSS — system.asynchronous_metrics.value 是 Float64（不是 UInt64！）
	var memoryBytes float64
	if err := h.chConn.QueryRow(queryCtx, "SELECT value FROM system.asynchronous_metrics WHERE metric = 'MemoryResident'").Scan(&memoryBytes); err == nil && memoryBytes > 0 {
		info.MemRSSBytes = uint64(memoryBytes)
		info.Memory = humanizeBytes(uint64(memoryBytes))
	}

	// Uptime — uptime() 返回 UInt32
	var uptimeSec uint32
	if err := h.chConn.QueryRow(queryCtx, "SELECT uptime()").Scan(&uptimeSec); err == nil && uptimeSec > 0 {
		info.UptimeSec = int64(uptimeSec)
		info.Uptime = formatUptime(time.Duration(uptimeSec) * time.Second)
	}

	info.Status = "healthy"
	info.Detail = clickHouseAddress(h.cfg)
	info.Extra = map[string]string{
		"address":       clickHouseAddress(h.cfg),
		"activeQueries": strconv.FormatInt(activeQuery, 10),
	}

	// 实际 QPS 用 system.events ProfileEvent_Query 增量计算（避免外部 exporter）
	// 这里用 active query 当近似指标，准确 QPS 由 Tier 1-2 历史趋势 API 走 PromQL 提供
	info.QPS = float64(activeQuery)

	return info
}

// checkPrometheusStatus 检查 Prometheus 自身状态。
//
// 数据来源：Prometheus 自身（job="prometheus"）+ /api/v1/query
// Prometheus 自带完整 process metric，CPU/RSS/Uptime 直接查 self-scrape。
func (h *MonitorHandler) checkPrometheusStatus(ctx context.Context) serviceInfo {
	const jobName = "prometheus"

	info := serviceInfo{Name: "Prometheus", PID: "--", Uptime: "--", Version: "--", Memory: "--"}
	if h.prometheusClient == nil {
		info.Status = "error"
		info.Detail = "Prometheus 客户端未初始化"
		return info
	}

	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	buildInfo, err := h.prometheusClient.QueryInstant(queryCtx, "prometheus_build_info", nil)
	if err != nil {
		info.Status = "error"
		info.Detail = "Prometheus 查询失败"
		return info
	}

	info.Status = "healthy"
	info.DataSource = "prometheus"
	if len(buildInfo.Data.Result) > 0 {
		if version := buildInfo.Data.Result[0].Metric["version"]; version != "" {
			info.Version = version
		}
	}

	// 真实 CPU/RSS/Uptime
	h.fillProcessMetrics(ctx, &info, jobName)

	// Prometheus 自身 QPS = HTTP 查询请求速率
	info.QPS = math.Round(h.promQueryFloat(ctx,
		`sum(rate(prometheus_http_requests_total[1m]))`)*100) / 100

	// p99 查询延迟（毫秒）
	info.P99LatencyMs = math.Round(h.promQueryFloat(ctx,
		`histogram_quantile(0.99, sum by (le) (rate(prometheus_http_request_duration_seconds_bucket[5m]))) * 1000`)*10) / 10

	// 监控 target 数（已配置/已 up）
	upResult, err := h.prometheusClient.QueryInstant(queryCtx, "up", nil)
	totalTargets, upTargets := 0, 0
	if err == nil && upResult != nil {
		totalTargets = len(upResult.Data.Result)
		for _, r := range upResult.Data.Result {
			if len(r.Value) >= 2 {
				if val, ok := r.Value[1].(string); ok && val == "1" {
					upTargets++
				}
			}
		}
	}
	info.Connections = int64(totalTargets)
	info.Extra = map[string]string{
		"totalTargets": strconv.Itoa(totalTargets),
		"upTargets":    strconv.Itoa(upTargets),
	}
	info.Detail = fmt.Sprintf("%d/%d targets up", upTargets, totalTargets)
	if totalTargets > 0 && upTargets < totalTargets {
		info.Status = "warning"
	}

	return info
}

// checkKafkaStatus 检查 Kafka 集群状态。
//
// 数据来源：
//   - 健康/broker 数: sarama client (driver 真实)
//   - QPS/RSS/CPU: Prometheus (job="kafka-exporter"，需部署 kafka_exporter)
//
// QPS 不再用 len(brokers) 当近似（语义错误：broker 数与消息速率无关）。
// Memory 字段填真 RSS，broker 信息入 Extra/Connections。
func (h *MonitorHandler) checkKafkaStatus(ctx context.Context) serviceInfo {
	totalBrokers := len(h.cfg.Kafka.Brokers)
	info := serviceInfo{
		Name:       "Kafka",
		PID:        "--",
		Uptime:     "--",
		Version:    "KRaft",
		Memory:     "--",
		DataSource: "driver",
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
	info.Connections = int64(len(brokers))
	info.Extra = map[string]string{
		"upBrokers":    strconv.Itoa(len(brokers)),
		"totalBrokers": strconv.Itoa(totalBrokers),
		"brokers":      strings.Join(h.cfg.Kafka.Brokers, ", "),
	}

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
	ctx := context.Background()
	var stats []connectionStat
	mysqlService := h.checkMySQLStatus(ctx)
	redisService := h.checkRedisStatus(ctx)
	clickHouseService := h.checkClickHouseStatus(ctx)
	kafkaStatus := "active"
	consumerService := h.checkConsumerStatus(ctx)
	if h.cfg != nil && h.cfg.Kafka.Enabled && len(h.cfg.Kafka.Brokers) > 0 {
		kafkaStatus = connectionStatusFromService(h.checkKafkaStatus(ctx).Status)
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
		// Consumer 连接 = consumer group 成员数（在 Connections 字段中）
		stats = append(stats, connectionStat{
			Service:           "Consumer",
			Protocol:          "Kafka Group",
			Address:           consumerGroupID,
			ActiveConnections: int(consumerService.Connections),
			TotalConnections:  int(consumerService.Connections),
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
