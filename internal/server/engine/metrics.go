package engine

// Pipeline metrics instrumentation (P2-23).
//
// 暴露 Prometheus 指标用于:
//   - 单 stage 处理延迟
//   - stage 命中告警数
//   - 入站 message 总数
//   - 单条 message 流水线总延迟 (生产 SLO p99 < 10ms)
//
// 配合 Grafana dashboard mxcwpp-engine.json 监控.

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// 全局 instrument 单例.
var (
	once sync.Once
	mtx  *PipelineMetrics
)

// PipelineMetrics 全部 engine 指标.
type PipelineMetrics struct {
	MessageReceived  prometheus.Counter
	MessageProcessed prometheus.Counter
	MessageFailed    *prometheus.CounterVec   // 标签 reason
	PipelineDuration *prometheus.HistogramVec // 标签 outcome
	StageDuration    *prometheus.HistogramVec // 标签 stage_name
	StageAlerts      *prometheus.CounterVec   // 标签 stage_name, severity
	AlertsProduced   *prometheus.CounterVec   // 标签 rule_id, severity
	StageErrors      *prometheus.CounterVec   // 标签 stage_name
	BackpressureDrop prometheus.Counter
}

// Metrics 单例 (lazy 注册).
func Metrics() *PipelineMetrics {
	once.Do(func() {
		mtx = &PipelineMetrics{
			MessageReceived: prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "message_received_total",
				Help: "Total messages received from Kafka",
			}),
			MessageProcessed: prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "message_processed_total",
				Help: "Total messages fully processed",
			}),
			MessageFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "message_failed_total",
				Help: "Messages failed processing by reason",
			}, []string{"reason"}),
			PipelineDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name:    "pipeline_duration_seconds",
				Help:    "End-to-end pipeline processing duration",
				Buckets: []float64{.001, .002, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
			}, []string{"outcome"}), // success / failed
			StageDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name:    "stage_duration_seconds",
				Help:    "Per-stage processing duration",
				Buckets: []float64{.0001, .0005, .001, .002, .005, .01, .025, .05, .1, .25},
			}, []string{"stage_name"}),
			StageAlerts: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "stage_alerts_total",
				Help: "Alerts produced per stage",
			}, []string{"stage_name", "severity"}),
			AlertsProduced: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "alerts_total",
				Help: "Alerts produced grouped by rule_id and severity",
			}, []string{"rule_id", "severity"}),
			StageErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "stage_errors_total",
				Help: "Errors per stage",
			}, []string{"stage_name"}),
			BackpressureDrop: prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: "mxcwpp", Subsystem: "engine",
				Name: "backpressure_drop_total",
				Help: "Messages dropped due to backpressure (producer queue full)",
			}),
		}
		prometheus.MustRegister(
			mtx.MessageReceived, mtx.MessageProcessed, mtx.MessageFailed,
			mtx.PipelineDuration, mtx.StageDuration, mtx.StageAlerts,
			mtx.AlertsProduced, mtx.StageErrors, mtx.BackpressureDrop,
		)
	})
	return mtx
}

// ObservePipeline 单次 pipeline 处理记录.
func ObservePipeline(start time.Time, outcome string) {
	Metrics().PipelineDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
	if outcome == "success" {
		Metrics().MessageProcessed.Inc()
	}
}

// ObserveStage 单 stage 处理记录.
func ObserveStage(stageName string, start time.Time) {
	Metrics().StageDuration.WithLabelValues(stageName).Observe(time.Since(start).Seconds())
}

// RecordStageError stage 内部 error.
func RecordStageError(stageName string) {
	Metrics().StageErrors.WithLabelValues(stageName).Inc()
}

// RecordAlert 产 alert 时调用.
func RecordAlert(stageName, ruleID, severity string) {
	Metrics().StageAlerts.WithLabelValues(stageName, severity).Inc()
	Metrics().AlertsProduced.WithLabelValues(ruleID, severity).Inc()
}

// IncMessageReceived 入站 message 计数.
func IncMessageReceived() {
	Metrics().MessageReceived.Inc()
}

// IncMessageFailed message 处理失败计数.
func IncMessageFailed(reason string) {
	Metrics().MessageFailed.WithLabelValues(reason).Inc()
}

// IncBackpressureDrop 背压丢弃计数.
func IncBackpressureDrop() {
	Metrics().BackpressureDrop.Inc()
}
