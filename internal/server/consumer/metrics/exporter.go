// Package metrics 提供 Consumer 进程的 Prometheus 指标暴露。
//
// Consumer 是后台 Kafka 消费者，原本无对外 HTTP 端口。
// 为接入 Prometheus 拉取模式，本包：
//  1. 定义 Consumer 业务指标（消息处理速率、处理延迟、错误数、Kafka lag）
//  2. 暴露独立 /metrics HTTP server（默认 :9100），供 Prometheus 抓取
package metrics

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	// Consumer 进程 build 元信息（value=1，labels 含 version/pid/commit）
	// monitor.go 用 PromQL `mxcwpp_build_info{job="mxcwpp-consumer"}` 拉取 version + pid
	BuildInfoGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_build_info",
		Help: "Consumer 进程 build 元信息（value=1，labels 含 version/pid/commit）",
	}, []string{"version", "pid", "commit"})

	// 消息处理总数（按 topic + status 分桶，用于 rate + error_rate）
	RecordsConsumedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_records_consumed_total",
		Help: "Total number of Kafka messages consumed by the consumer, labeled by topic and result status.",
	}, []string{"topic", "data_type", "status"}) // status: success / error / dlq

	// 处理延迟（histogram，用于 p99）
	ProcessingDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mxcwpp_consumer_processing_duration_seconds",
		Help:    "Histogram of Consumer message processing latency in seconds, labeled by topic.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"topic"})

	// Kafka 消费 lag（gauge，定期由 lag-collector 协程刷新；亦可被外部 kafka-exporter 替代）
	ConsumerLag = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_lag",
		Help: "Current Kafka consumer lag (messages behind newest offset), labeled by topic and partition.",
	}, []string{"topic", "partition"})

	// 当前消费组成员数
	ConsumerGroupMembers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_group_members",
		Help: "Current number of members in the consumer group.",
	})
)

// RecordProcessing 在 handleMessage 完成后调用，统一记录三项指标。
//
// topic    Kafka 主题
// dataType MQMessage.DataType（用 string 形式以控制 label 基数；少量已知值）
// status   "success" | "error" | "dlq"
// elapsed  处理耗时
func RecordProcessing(topic, dataType, status string, elapsed time.Duration) {
	RecordsConsumedTotal.WithLabelValues(topic, dataType, status).Inc()
	ProcessingDurationSeconds.WithLabelValues(topic).Observe(elapsed.Seconds())
}

// SetConsumerLag 由 lag-collector（router.go 内的定时器）调用，刷新 Kafka 消费 lag gauge。
func SetConsumerLag(topic, partition string, lag int64) {
	ConsumerLag.WithLabelValues(topic, partition).Set(float64(lag))
}

// SetBuildInfo 设置 Consumer build 元信息（main 启动时调一次）
func SetBuildInfo(version, commit string) {
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "unknown"
	}
	BuildInfoGauge.WithLabelValues(version, strconv.Itoa(os.Getpid()), commit).Set(1)
}

// SetGroupMembers 由 router 定时刷新当前消费组成员数。
func SetGroupMembers(n int) {
	ConsumerGroupMembers.Set(float64(n))
}

// registry 是 Consumer 进程独立的 Prometheus 注册表。
//
// 不复用 server/metrics 的全局 registry，避免与 Manager 进程指标命名冲突
// （Manager 与 Consumer 是独立二进制，但开发期可能在同一镜像内运行）。
var registry = prometheus.NewRegistry()

func init() {
	// 注册 Go runtime + 进程级 collector（process_cpu_seconds_total / process_resident_memory_bytes 等）
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	// 注册业务 metric（含 build info，让 monitor.go 通过 PromQL 拉 version+pid）
	registry.MustRegister(
		BuildInfoGauge,
		RecordsConsumedTotal,
		ProcessingDurationSeconds,
		ConsumerLag,
		ConsumerGroupMembers,
	)
}

// StartHTTPServer 启动独立的 /metrics HTTP server。
//
// 阻塞直到 ctx 结束；返回错误时 caller 决定是否重启。
func StartHTTPServer(ctx context.Context, addr string, logger *zap.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("Consumer metrics HTTP server 启动", zap.String("addr", addr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
