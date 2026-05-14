// Package metrics 提供 Prometheus 指标导出
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	// 指标注册表
	registry *prometheus.Registry
	once     sync.Once

	// Agent 连接指标
	agentConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mxsec_agent_connections_total",
			Help: "当前连接的 Agent 数量",
		},
		[]string{"status"}, // online, offline
	)

	// 心跳指标
	heartbeatTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mxsec_heartbeat_total",
			Help: "心跳总数",
		},
		[]string{"host_id"},
	)

	// 基线检查结果指标
	baselineResultsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mxsec_baseline_results_total",
			Help: "基线检查结果总数",
		},
		[]string{"host_id", "status", "severity"}, // status: pass, fail, error, na
	)

	// 基线得分指标
	baselineScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mxsec_baseline_score",
			Help: "主机基线得分（0-100）",
		},
		[]string{"host_id"},
	)

	// 任务指标
	tasksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mxsec_tasks_total",
			Help: "扫描任务总数",
		},
		[]string{"status"}, // pending, running, completed, failed
	)

	// 任务执行时间
	taskDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mxsec_task_duration_seconds",
			Help:    "任务执行时间（秒）",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 512s
		},
		[]string{"task_id", "status"},
	)

	// HTTP 请求指标
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mxsec_http_requests_total",
			Help: "HTTP 请求总数",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	// HTTP 请求延迟
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mxsec_http_request_duration_seconds",
			Help:    "HTTP 请求延迟（秒）",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint"},
	)

	// 数据库查询指标
	dbQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mxsec_db_query_duration_seconds",
			Help:    "数据库查询延迟（秒）",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"operation", "table"},
	)
)

// Init 初始化 Prometheus 指标
func Init(logger *zap.Logger) *prometheus.Registry {
	once.Do(func() {
		registry = prometheus.NewRegistry()

		// 注册默认指标（Go 运行时指标）
		registry.MustRegister(prometheus.NewGoCollector())
		registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

		// 注册自定义指标
		registry.MustRegister(
			agentConnections,
			heartbeatTotal,
			baselineResultsTotal,
			baselineScore,
			tasksTotal,
			taskDuration,
			httpRequestsTotal,
			httpRequestDuration,
			dbQueryDuration,
		)

		if logger != nil {
			logger.Info("Prometheus 指标已初始化")
		}
	})

	return registry
}

// GetRegistry 获取指标注册表
func GetRegistry() *prometheus.Registry {
	return registry
}

// Handler 返回 Prometheus metrics HTTP handler
func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// RecordAgentConnection 记录 Agent 连接
func RecordAgentConnection(status string, count float64) {
	agentConnections.WithLabelValues(status).Set(count)
}

// RecordHeartbeat 记录心跳
func RecordHeartbeat(hostID string) {
	heartbeatTotal.WithLabelValues(hostID).Inc()
}

// RecordBaselineResult 记录基线检查结果
func RecordBaselineResult(hostID, status, severity string) {
	baselineResultsTotal.WithLabelValues(hostID, status, severity).Inc()
}

// RecordBaselineScore 记录基线得分
func RecordBaselineScore(hostID string, score float64) {
	baselineScore.WithLabelValues(hostID).Set(score)
}

// RecordTask 记录任务
func RecordTask(status string) {
	tasksTotal.WithLabelValues(status).Inc()
}

// RecordTaskDuration 记录任务执行时间
func RecordTaskDuration(taskID, status string, duration float64) {
	taskDuration.WithLabelValues(taskID, status).Observe(duration)
}

// RecordHTTPRequest 记录 HTTP 请求
func RecordHTTPRequest(method, endpoint, statusCode string) {
	httpRequestsTotal.WithLabelValues(method, endpoint, statusCode).Inc()
}

// RecordHTTPRequestDuration 记录 HTTP 请求延迟
func RecordHTTPRequestDuration(method, endpoint string, duration float64) {
	httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration)
}

// RecordDBQueryDuration 记录数据库查询延迟
func RecordDBQueryDuration(operation, table string, duration float64) {
	dbQueryDuration.WithLabelValues(operation, table).Observe(duration)
}
