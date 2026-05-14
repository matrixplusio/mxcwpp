// Package biz 提供业务逻辑层
package biz

import (
	"context"
	"errors"
	"fmt"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
	"github.com/imkerbos/mxsec-platform/internal/server/prometheus"
)

var ErrPrometheusDatasourceNotConfigured = errors.New("找不到数据源，请配置 Prometheus 数据源")

// MetricsService 是监控数据查询服务
type MetricsService struct {
	db               *gorm.DB
	prometheusClient *prometheus.Client
	chConn           chdriver.Conn // 可为 nil，ClickHouse 未启用时降级
	logger           *zap.Logger
}

// NewMetricsService 创建监控数据查询服务
func NewMetricsService(db *gorm.DB, prometheusClient *prometheus.Client, chConn chdriver.Conn, logger *zap.Logger) *MetricsService {
	return &MetricsService{
		db:               db,
		prometheusClient: prometheusClient,
		chConn:           chConn,
		logger:           logger,
	}
}

// HostMetrics 是主机监控数据
type HostMetrics struct {
	HostID     string             `json:"host_id"`
	Latest     *LatestMetrics     `json:"latest,omitempty"`      // 最新监控数据
	TimeSeries *TimeSeriesMetrics `json:"time_series,omitempty"` // 时间序列数据
	Source     string             `json:"source"`                // 数据源：prometheus
}

// LatestMetrics 是最新监控数据
type LatestMetrics struct {
	CPUUsage        *float64   `json:"cpu_usage,omitempty"`
	MemUsage        *float64   `json:"mem_usage,omitempty"`
	DiskUsage       *float64   `json:"disk_usage,omitempty"`
	NetBytesSent    *uint64    `json:"net_bytes_sent,omitempty"`
	NetBytesRecv    *uint64    `json:"net_bytes_recv,omitempty"`
	DiskReadBytes   *uint64    `json:"disk_read_bytes,omitempty"`
	DiskWriteBytes  *uint64    `json:"disk_write_bytes,omitempty"`
	AgentCPUUsage   *float64   `json:"agent_cpu_usage,omitempty"`
	AgentMemRSS     *uint64    `json:"agent_mem_rss,omitempty"`
	AgentMemPercent *float64   `json:"agent_mem_percent,omitempty"`
	CollectedAt     *time.Time `json:"collected_at,omitempty"`
}

// TimeSeriesMetrics 是时间序列监控数据
type TimeSeriesMetrics struct {
	CPUUsage  []TimeSeriesPoint `json:"cpu_usage,omitempty"`
	MemUsage  []TimeSeriesPoint `json:"mem_usage,omitempty"`
	DiskUsage []TimeSeriesPoint `json:"disk_usage,omitempty"`
	NetIn     []TimeSeriesPoint `json:"net_in,omitempty"`
	NetOut    []TimeSeriesPoint `json:"net_out,omitempty"`
	DiskRead  []TimeSeriesPoint `json:"disk_read,omitempty"`
	DiskWrite []TimeSeriesPoint `json:"disk_write,omitempty"`
	AgentCPU  []TimeSeriesPoint `json:"agent_cpu,omitempty"`
	AgentMem  []TimeSeriesPoint `json:"agent_mem,omitempty"`
}

// TimeSeriesPoint 是时间序列数据点
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// GetHostMetrics 获取主机监控数据
func (s *MetricsService) GetHostMetrics(ctx context.Context, hostID string, startTime, endTime *time.Time) (*HostMetrics, error) {
	if s.prometheusClient == nil {
		return nil, ErrPrometheusDatasourceNotConfigured
	}

	return s.getHostMetricsFromPrometheus(ctx, hostID, startTime, endTime)
}

// resolveTimeRange 返回有效的时间范围（nil 时默认最近 1 小时）
func resolveTimeRange(startTime, endTime *time.Time) (time.Time, time.Time) {
	now := time.Now()
	if startTime == nil || endTime == nil {
		return now.Add(-1 * time.Hour), now
	}
	return *startTime, *endTime
}

// getHostMetricsFromClickHouse 从 ClickHouse 查询单主机时序数据
// range < 24h：查原始 host_metrics 表（分钟级精度）
// range >= 24h：查物化视图 host_metrics_hourly（小时级，性能更好）
func (s *MetricsService) getHostMetricsFromClickHouse(ctx context.Context, hostID string, start, end time.Time) (*HostMetrics, error) {
	duration := end.Sub(start)
	if duration >= 24*time.Hour {
		return s.getHostMetricsFromMaterializedView(ctx, hostID, start, end)
	}

	var bucketFn string
	switch {
	case duration <= 2*time.Hour:
		bucketFn = "toStartOfFiveMinutes"
	default:
		bucketFn = "toStartOfFifteenMinutes"
	}

	rows, err := s.chConn.Query(ctx, fmt.Sprintf(`
		SELECT
			%s(timestamp)                   AS bucket,
			round(avg(cpu_usage),1)         AS cpu,
			round(avg(mem_usage),1)         AS mem,
			round(avg(disk_usage),1)        AS disk,
			toUInt64(sum(net_in))           AS net_in,
			toUInt64(sum(net_out))          AS net_out,
			toUInt64(sum(disk_read_bytes))  AS disk_read,
			toUInt64(sum(disk_write_bytes)) AS disk_write
		FROM host_metrics
		WHERE host_id = ? AND timestamp >= ? AND timestamp <= ?
		GROUP BY bucket
		ORDER BY bucket ASC
	`, bucketFn), hostID, start, end)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse 查询主机时序指标失败: %w", err)
	}
	defer rows.Close()

	return s.scanHostMetricRows(rows, hostID, "clickhouse")
}

// getHostMetricsFromMaterializedView 查物化视图 host_metrics_hourly（用于 >= 24h 范围）
func (s *MetricsService) getHostMetricsFromMaterializedView(ctx context.Context, hostID string, start, end time.Time) (*HostMetrics, error) {
	rows, err := s.chConn.Query(ctx, `
		SELECT
			hour                              AS bucket,
			round(avgMerge(cpu_avg),1)        AS cpu,
			round(avgMerge(mem_avg),1)        AS mem,
			round(avgMerge(disk_avg),1)       AS disk,
			toUInt64(sumMerge(net_in_total))  AS net_in,
			toUInt64(sumMerge(net_out_total)) AS net_out,
			toUInt64(sumMerge(disk_read_total))  AS disk_read,
			toUInt64(sumMerge(disk_write_total)) AS disk_write
		FROM host_metrics_hourly
		WHERE host_id = ? AND hour >= ? AND hour <= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, hostID, start, end)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse 查询物化视图指标失败: %w", err)
	}
	defer rows.Close()

	return s.scanHostMetricRows(rows, hostID, "clickhouse_mv")
}

// scanHostMetricRows 扫描指标查询结果行，复用于原始表和物化视图查询
func (s *MetricsService) scanHostMetricRows(rows chdriver.Rows, hostID, source string) (*HostMetrics, error) {
	metrics := &HostMetrics{HostID: hostID, Source: source}
	ts := &TimeSeriesMetrics{}
	var lastCPU, lastMem, lastDisk float64

	for rows.Next() {
		var bucket time.Time
		var cpu, mem, disk float64
		var netIn, netOut, diskRead, diskWrite uint64
		if err := rows.Scan(&bucket, &cpu, &mem, &disk, &netIn, &netOut, &diskRead, &diskWrite); err != nil {
			continue
		}
		ts.CPUUsage = append(ts.CPUUsage, TimeSeriesPoint{Timestamp: bucket, Value: cpu})
		ts.MemUsage = append(ts.MemUsage, TimeSeriesPoint{Timestamp: bucket, Value: mem})
		ts.DiskUsage = append(ts.DiskUsage, TimeSeriesPoint{Timestamp: bucket, Value: disk})
		lastCPU, lastMem, lastDisk = cpu, mem, disk
	}
	if rows.Err() != nil {
		s.logger.Warn("ClickHouse 游标读取错误", zap.Error(rows.Err()))
	}

	if len(ts.CPUUsage) > 0 {
		now := time.Now()
		metrics.Latest = &LatestMetrics{
			CPUUsage:    &lastCPU,
			MemUsage:    &lastMem,
			DiskUsage:   &lastDisk,
			CollectedAt: &now,
		}
		metrics.TimeSeries = ts
	}
	return metrics, nil
}

// getHostMetricsFromMySQL 从 MySQL 获取主机监控数据
func (s *MetricsService) getHostMetricsFromMySQL(ctx context.Context, hostID string, startTime, endTime *time.Time) (*HostMetrics, error) {
	metrics := &HostMetrics{
		HostID: hostID,
		Source: "mysql",
	}

	// 查询最新监控数据
	var latestMetric model.HostMetric
	if err := s.db.Where("host_id = ?", hostID).
		Order("collected_at DESC").
		Limit(1).
		First(&latestMetric).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("查询最新监控数据失败: %w", err)
		}
		// 没有数据，返回空结果
		return metrics, nil
	}

	collectedAtTime := time.Time(latestMetric.CollectedAt)
	metrics.Latest = &LatestMetrics{
		CPUUsage:     latestMetric.CPUUsage,
		MemUsage:     latestMetric.MemUsage,
		DiskUsage:    latestMetric.DiskUsage,
		NetBytesSent: latestMetric.NetBytesSent,
		NetBytesRecv: latestMetric.NetBytesRecv,
		CollectedAt:  &collectedAtTime,
	}

	// 如果指定了时间范围，查询时间序列数据
	if startTime != nil && endTime != nil {
		timeSeries, err := s.getTimeSeriesFromMySQL(ctx, hostID, *startTime, *endTime)
		if err != nil {
			s.logger.Warn("查询时间序列数据失败", zap.Error(err))
		} else {
			metrics.TimeSeries = timeSeries
		}
	}

	return metrics, nil
}

// getHostMetricsFromPrometheus 从 Prometheus 获取主机监控数据
func (s *MetricsService) getHostMetricsFromPrometheus(ctx context.Context, hostID string, startTime, endTime *time.Time) (*HostMetrics, error) {
	metrics := &HostMetrics{
		HostID: hostID,
		Source: "prometheus",
	}

	labels := map[string]string{
		"host_id": hostID,
	}

	// 查询最新监控数据（即时查询）
	latest, err := s.getLatestMetricsFromPrometheus(ctx, labels)
	if err != nil {
		return nil, fmt.Errorf("查询 Prometheus 最新监控数据失败: %w", err)
	}
	if latest != nil {
		metrics.Latest = latest
	}

	// 如果指定了时间范围，查询时间序列数据
	if startTime != nil && endTime != nil {
		timeSeries, err := s.getTimeSeriesFromPrometheus(ctx, labels, *startTime, *endTime)
		if err != nil {
			return nil, fmt.Errorf("查询 Prometheus 时间序列数据失败: %w", err)
		}
		if timeSeries != nil && timeSeries.hasData() {
			metrics.TimeSeries = timeSeries
		}
	}

	return metrics, nil
}

// getLatestMetricsFromPrometheus 从 Prometheus 获取最新监控数据
func (s *MetricsService) getLatestMetricsFromPrometheus(ctx context.Context, labels map[string]string) (*LatestMetrics, error) {
	latest := &LatestMetrics{}
	var firstErr error

	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_cpu_usage", labels); err == nil && v != nil {
		latest.CPUUsage = v
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_mem_usage", labels); err == nil && v != nil {
		latest.MemUsage = v
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_disk_usage", labels); err == nil && v != nil {
		latest.DiskUsage = v
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_net_in", labels); err == nil && v != nil {
		u := uint64(*v)
		latest.NetBytesRecv = &u
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_net_out", labels); err == nil && v != nil {
		u := uint64(*v)
		latest.NetBytesSent = &u
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_disk_read_bytes", labels); err == nil && v != nil {
		u := uint64(*v)
		latest.DiskReadBytes = &u
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_host_disk_write_bytes", labels); err == nil && v != nil {
		u := uint64(*v)
		latest.DiskWriteBytes = &u
	} else if err != nil && firstErr == nil {
		firstErr = err
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_agent_cpu_usage", labels); err == nil && v != nil {
		latest.AgentCPUUsage = v
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_agent_mem_rss", labels); err == nil && v != nil {
		u := uint64(*v)
		latest.AgentMemRSS = &u
	}
	if v, err := s.prometheusClient.GetMetricValue(ctx, "mxsec_agent_mem_percent", labels); err == nil && v != nil {
		latest.AgentMemPercent = v
	}

	if !latest.hasData() {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, nil
	}

	now := time.Now()
	latest.CollectedAt = &now

	return latest, nil
}

// getTimeSeriesFromPrometheus 从 Prometheus 获取时间序列数据
func (s *MetricsService) getTimeSeriesFromPrometheus(ctx context.Context, labels map[string]string, start, end time.Time) (*TimeSeriesMetrics, error) {
	timeSeries := &TimeSeriesMetrics{}
	var firstErr error

	// 计算步长（根据时间范围自动调整）
	duration := end.Sub(start)
	var step string
	if duration <= 1*time.Hour {
		step = "1m" // 1 分钟
	} else if duration <= 24*time.Hour {
		step = "5m" // 5 分钟
	} else if duration <= 7*24*time.Hour {
		step = "15m" // 15 分钟
	} else {
		step = "1h" // 1 小时
	}

	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_cpu_usage", labels, start, end, step); err == nil {
		timeSeries.CPUUsage = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_mem_usage", labels, start, end, step); err == nil {
		timeSeries.MemUsage = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_disk_usage", labels, start, end, step); err == nil {
		timeSeries.DiskUsage = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_net_in", labels, start, end, step); err == nil {
		timeSeries.NetIn = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_net_out", labels, start, end, step); err == nil {
		timeSeries.NetOut = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_disk_read_bytes", labels, start, end, step); err == nil {
		timeSeries.DiskRead = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_host_disk_write_bytes", labels, start, end, step); err == nil {
		timeSeries.DiskWrite = convertToTimeSeriesPoints(pts)
	} else if firstErr == nil {
		firstErr = err
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_agent_cpu_usage", labels, start, end, step); err == nil {
		timeSeries.AgentCPU = convertToTimeSeriesPoints(pts)
	}
	if pts, err := s.prometheusClient.GetMetricRange(ctx, "mxsec_agent_mem_rss", labels, start, end, step); err == nil {
		timeSeries.AgentMem = convertToTimeSeriesPoints(pts)
	}

	if !timeSeries.hasData() && firstErr != nil {
		return nil, firstErr
	}

	return timeSeries, nil
}

// getTimeSeriesFromMySQL 从 MySQL 获取时间序列数据
func (s *MetricsService) getTimeSeriesFromMySQL(_ context.Context, hostID string, start, end time.Time) (*TimeSeriesMetrics, error) {
	timeSeries := &TimeSeriesMetrics{}

	// 查询 CPU 使用率时间序列
	var cpuMetrics []model.HostMetric
	if err := s.db.Where("host_id = ? AND collected_at >= ? AND collected_at <= ?", hostID, start, end).
		Select("collected_at, cpu_usage").
		Order("collected_at ASC").
		Find(&cpuMetrics).Error; err == nil {
		timeSeries.CPUUsage = make([]TimeSeriesPoint, 0, len(cpuMetrics))
		for _, m := range cpuMetrics {
			if m.CPUUsage != nil {
				timeSeries.CPUUsage = append(timeSeries.CPUUsage, TimeSeriesPoint{
					Timestamp: time.Time(m.CollectedAt),
					Value:     *m.CPUUsage,
				})
			}
		}
	}

	// 查询内存使用率时间序列
	var memMetrics []model.HostMetric
	if err := s.db.Where("host_id = ? AND collected_at >= ? AND collected_at <= ?", hostID, start, end).
		Select("collected_at, mem_usage").
		Order("collected_at ASC").
		Find(&memMetrics).Error; err == nil {
		timeSeries.MemUsage = make([]TimeSeriesPoint, 0, len(memMetrics))
		for _, m := range memMetrics {
			if m.MemUsage != nil {
				timeSeries.MemUsage = append(timeSeries.MemUsage, TimeSeriesPoint{
					Timestamp: time.Time(m.CollectedAt),
					Value:     *m.MemUsage,
				})
			}
		}
	}

	// 查询磁盘使用率时间序列
	var diskMetrics []model.HostMetric
	if err := s.db.Where("host_id = ? AND collected_at >= ? AND collected_at <= ?", hostID, start, end).
		Select("collected_at, disk_usage").
		Order("collected_at ASC").
		Find(&diskMetrics).Error; err == nil {
		timeSeries.DiskUsage = make([]TimeSeriesPoint, 0, len(diskMetrics))
		for _, m := range diskMetrics {
			if m.DiskUsage != nil {
				timeSeries.DiskUsage = append(timeSeries.DiskUsage, TimeSeriesPoint{
					Timestamp: time.Time(m.CollectedAt),
					Value:     *m.DiskUsage,
				})
			}
		}
	}

	return timeSeries, nil
}

// convertToTimeSeriesPoints 转换 Prometheus 时间序列点为内部格式
func convertToTimeSeriesPoints(points []prometheus.TimeSeriesPoint) []TimeSeriesPoint {
	result := make([]TimeSeriesPoint, 0, len(points))
	for _, p := range points {
		result = append(result, TimeSeriesPoint{
			Timestamp: p.Timestamp,
			Value:     p.Value,
		})
	}
	return result
}

func (m *LatestMetrics) hasData() bool {
	if m == nil {
		return false
	}

	return m.CPUUsage != nil ||
		m.MemUsage != nil ||
		m.DiskUsage != nil ||
		m.NetBytesSent != nil ||
		m.NetBytesRecv != nil ||
		m.DiskReadBytes != nil ||
		m.DiskWriteBytes != nil ||
		m.AgentCPUUsage != nil ||
		m.AgentMemRSS != nil ||
		m.AgentMemPercent != nil
}

func (m *TimeSeriesMetrics) hasData() bool {
	if m == nil {
		return false
	}

	return len(m.CPUUsage) > 0 ||
		len(m.MemUsage) > 0 ||
		len(m.DiskUsage) > 0 ||
		len(m.NetIn) > 0 ||
		len(m.NetOut) > 0 ||
		len(m.DiskRead) > 0 ||
		len(m.DiskWrite) > 0 ||
		len(m.AgentCPU) > 0 ||
		len(m.AgentMem) > 0
}
