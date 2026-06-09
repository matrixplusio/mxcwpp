// Package metrics 实现 Agent /metrics Prometheus 暴露 (P2-5)。
//
// ref/02-Agent M2-P2-3: Agent /metrics 端点暴露 CPU/RSS/心跳/任务指标。
//
// 默认端口 9100, 与 node_exporter 平行 (mxsec 用 9101 避撞):
//
//	HTTP server :9101/metrics
//
// 指标分类:
//   - mxsec_agent_* 健康 (build_info / start_time / uptime)
//   - mxsec_agent_heartbeat_* (lastsuccess / count / duration)
//   - mxsec_agent_task_* (received / completed / failed / inflight)
//   - mxsec_agent_event_* (collected / sent / dropped)
//   - mxsec_agent_plugin_* (alive / restart_count)
//   - mxsec_agent_self_* (RSS / CPU / fd 数)
package metrics

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	defaultListenAddr = ":9101" // 不撞 node_exporter 9100
	namespace         = "mxsec"
	subsystemAgent    = "agent"
)

// Metrics Agent 全指标集合 (单例).
type Metrics struct {
	// 健康
	BuildInfo *prometheus.GaugeVec
	StartTime prometheus.Gauge
	Uptime    prometheus.GaugeFunc

	// 心跳
	HeartbeatTotal       *prometheus.CounterVec
	HeartbeatDuration    *prometheus.HistogramVec
	HeartbeatLastSuccess prometheus.Gauge

	// 任务
	TaskReceived  *prometheus.CounterVec
	TaskCompleted *prometheus.CounterVec
	TaskFailed    *prometheus.CounterVec
	TaskInflight  *prometheus.GaugeVec

	// 事件
	EventCollected *prometheus.CounterVec
	EventSent      *prometheus.CounterVec
	EventDropped   *prometheus.CounterVec

	// 插件
	PluginAlive        *prometheus.GaugeVec
	PluginRestartTotal *prometheus.CounterVec

	// 自身资源
	SelfRSS        prometheus.GaugeFunc
	SelfFDs        prometheus.GaugeFunc
	SelfGoroutines prometheus.GaugeFunc

	logger    *zap.Logger
	startedAt int64 // unix nano
}

var globalMetrics atomic.Pointer[Metrics]

// Init 创建并注册全局 Metrics, 必须在 main() 早期调用一次。
func Init(buildVersion, buildTime string, logger *zap.Logger) *Metrics {
	if logger == nil {
		logger = zap.NewNop()
	}
	m := &Metrics{
		logger:    logger,
		startedAt: time.Now().UnixNano(),
	}

	m.BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "build_info", Help: "Agent build info (always 1)",
	}, []string{"version", "build_time", "go_version", "host"})

	m.StartTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "start_time_seconds", Help: "Agent start time as unix epoch",
	})

	m.Uptime = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "uptime_seconds", Help: "Agent uptime in seconds",
	}, func() float64 {
		return float64(time.Now().UnixNano()-m.startedAt) / 1e9
	})

	m.HeartbeatTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "heartbeat_total", Help: "Agent heartbeat attempts by result",
	}, []string{"result"}) // success / failed

	m.HeartbeatDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "heartbeat_duration_seconds", Help: "Agent heartbeat RTT",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"result"})

	m.HeartbeatLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "heartbeat_last_success_seconds", Help: "Unix epoch of last successful heartbeat",
	})

	m.TaskReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "task_received_total", Help: "Tasks received by data_type",
	}, []string{"data_type"})

	m.TaskCompleted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "task_completed_total", Help: "Tasks completed",
	}, []string{"data_type"})

	m.TaskFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "task_failed_total", Help: "Tasks failed",
	}, []string{"data_type", "reason"})

	m.TaskInflight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "task_inflight", Help: "Currently running tasks",
	}, []string{"data_type"})

	m.EventCollected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "event_collected_total", Help: "Events collected by source",
	}, []string{"source"}) // ebpf / fanotify / procfs / netlink

	m.EventSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "event_sent_total", Help: "Events sent to AC",
	}, []string{"data_type"})

	m.EventDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "event_dropped_total", Help: "Events dropped (backpressure/WAL full)",
	}, []string{"reason"}) // wal_full / sock_busy / queue_full

	m.PluginAlive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "plugin_alive", Help: "Plugin process alive (1/0)",
	}, []string{"plugin"})

	m.PluginRestartTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "plugin_restart_total", Help: "Plugin restart attempts",
	}, []string{"plugin", "result"})

	m.SelfRSS = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "self_rss_bytes", Help: "Agent resident set size",
	}, func() float64 { return float64(readRSS()) })

	m.SelfFDs = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "self_open_fds", Help: "Agent open file descriptor count",
	}, func() float64 { return float64(readFDCount()) })

	m.SelfGoroutines = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystemAgent,
		Name: "self_goroutines", Help: "Active Go goroutines",
	}, func() float64 { return float64(runtime.NumGoroutine()) })

	prometheus.MustRegister(
		m.BuildInfo, m.StartTime, m.Uptime,
		m.HeartbeatTotal, m.HeartbeatDuration, m.HeartbeatLastSuccess,
		m.TaskReceived, m.TaskCompleted, m.TaskFailed, m.TaskInflight,
		m.EventCollected, m.EventSent, m.EventDropped,
		m.PluginAlive, m.PluginRestartTotal,
		m.SelfRSS, m.SelfFDs, m.SelfGoroutines,
	)

	hostname, _ := os.Hostname()
	m.BuildInfo.WithLabelValues(buildVersion, buildTime, runtime.Version(), hostname).Set(1)
	m.StartTime.Set(float64(time.Now().Unix()))

	globalMetrics.Store(m)
	logger.Info("Agent metrics initialized",
		zap.String("version", buildVersion),
		zap.String("hostname", hostname))
	return m
}

// Get 全局单例 (启动后任意位置调用).
func Get() *Metrics { return globalMetrics.Load() }

// Serve 启动 HTTP /metrics 端点。失败仅 warn, 不阻塞 Agent。
func (m *Metrics) Serve(ctx context.Context, listenAddr string) {
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	m.logger.Info("Agent metrics server listening", zap.String("addr", listenAddr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		m.logger.Warn("Agent metrics server error", zap.Error(err))
	}
}

// 便捷封装 (业务代码直接 metrics.IncHeartbeat 等).

// IncHeartbeat 记录心跳尝试.
func IncHeartbeat(success bool, durationSec float64) {
	m := Get()
	if m == nil {
		return
	}
	result := "failed"
	if success {
		result = "success"
	}
	m.HeartbeatTotal.WithLabelValues(result).Inc()
	m.HeartbeatDuration.WithLabelValues(result).Observe(durationSec)
	if success {
		m.HeartbeatLastSuccess.Set(float64(time.Now().Unix()))
	}
}

// IncEventSent 事件发送计数.
func IncEventSent(dataType string) {
	m := Get()
	if m != nil {
		m.EventSent.WithLabelValues(dataType).Inc()
	}
}

// IncEventDropped 事件丢弃计数.
func IncEventDropped(reason string) {
	m := Get()
	if m != nil {
		m.EventDropped.WithLabelValues(reason).Inc()
	}
}

// IncTaskCompleted 任务完成计数.
func IncTaskCompleted(dataType string) {
	m := Get()
	if m != nil {
		m.TaskCompleted.WithLabelValues(dataType).Inc()
	}
}

// IncTaskFailed 任务失败计数.
func IncTaskFailed(dataType, reason string) {
	m := Get()
	if m != nil {
		m.TaskFailed.WithLabelValues(dataType, reason).Inc()
	}
}
