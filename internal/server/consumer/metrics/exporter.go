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
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"

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

	// ClickHouse 写入失败次数（MySQL 已落但 CH 写失败 → 双写漂移风险，原被 `_=` 静默吞掉）。
	CHWriteErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_ch_write_errors_total",
		Help: "Number of ClickHouse write failures in the consumer, labeled by operation.",
	}, []string{"op"})

	// 消费到未路由的未知 DataType 次数（已转 DLQ，原仅 Debug 丢弃 = 静默数据黑洞）。
	UnknownDataTypeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_unknown_data_type_total",
		Help: "Number of messages with an unrouted/unknown DataType consumed (sent to DLQ).",
	}, []string{"data_type"})

	// DLQ 写入失败次数。这是数据保全的最后一米：消息处理失败 → 转 DLQ 保底 → 连 DLQ 也没写进去，
	// 此时消息真的没了。异步 producer 在 burst 下会丢（prod 曾一次丢 24709 条），原先只有一条
	// 日志，无法计量也无法告警。任何非零值都意味着已发生不可恢复的数据丢失。
	DLQWriteFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_dlq_write_failures_total",
		Help: "Number of messages lost because writing them to the dead letter queue failed.",
	}, []string{"dlq_topic"})
)

// --- ML 异常检测器（IForest + correlation）安全状态指标 ---
//
// 全部低基数（无 host_id label），仅注册到 Consumer 独立 registry（见 init）。
// 模式采用 one-hot GaugeVec（固定 4 个 label 值 off/shadow/context/alert），
// 生效模式同理，避免 info-style 变化 label 值累积 stale series。由 SetAnomalyStatus 刷新。
var (
	// 配置模式 one-hot：匹配的 mode=1，其余=0。
	AnomalyModeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_detector_mode",
		Help: "Configured ML anomaly detector safety mode (one-hot: 1 for the active mode, 0 otherwise).",
	}, []string{"mode"})

	// 生效模式 one-hot（fail-closed 后可能异于配置模式，如 context/alert 未就绪降 shadow）。
	AnomalyEffectiveModeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_detector_effective_mode",
		Help: "Effective ML anomaly detector mode after fail-closed gating (one-hot: 1 for the active mode).",
	}, []string{"mode"})

	// anomaly_alerts schema（hit_count/last_seen_at + 去重唯一索引）是否就绪（1/0）。
	AnomalySchemaReady = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_schema_ready",
		Help: "Whether anomaly_alerts schema gate passed (1) or not (0); 0 => detector fail-closed to shadow.",
	})

	// DNS domain/rcode 字段是否可信（M0 恒 0）。
	AnomalyDNSFieldReady = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_dns_field_ready",
		Help: "Whether DNS domain/rcode fields are trusted (1) or not (0); M0 is always 0.",
	})

	// IForest 是否已训练（1/0）。
	AnomalyIForestTrained = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_iforest_trained",
		Help: "Whether the isolation forest has been trained (1) or not (0).",
	})

	// 训练样本缓冲区大小。
	AnomalySampleCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_sample_count",
		Help: "Number of samples in the isolation forest training buffer.",
	})

	// 已跟踪主机数（warmup 覆盖面）。
	AnomalyHostCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_host_count",
		Help: "Number of unique hosts tracked by the anomaly detector.",
	})
)

// anomalyModes 是 one-hot GaugeVec 的固定 label 值集合（限定基数，且每次刷新清零非命中项）。
var anomalyModes = []string{"off", "shadow", "context", "alert"}

// SetAnomalyStatus 刷新 ML 异常检测器状态指标（由 main 启动时初始化并周期调用）。
// 入参用原始类型而非 anomaly.Status 结构体，避免 metrics 包反向依赖 engine/anomaly。
func SetAnomalyStatus(configMode, effectiveMode string, schemaReady, dnsFieldReady, trained bool, sampleCount, hostCount int) {
	for _, m := range anomalyModes {
		AnomalyModeGauge.WithLabelValues(m).Set(b2f(m == configMode))
		AnomalyEffectiveModeGauge.WithLabelValues(m).Set(b2f(m == effectiveMode))
	}
	AnomalySchemaReady.Set(b2f(schemaReady))
	AnomalyDNSFieldReady.Set(b2f(dnsFieldReady))
	AnomalyIForestTrained.Set(b2f(trained))
	AnomalySampleCount.Set(float64(sampleCount))
	AnomalyHostCount.Set(float64(hostCount))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// RecordCHWriteError 记录一次 ClickHouse 写失败（op 为固定小集合，如 host_metrics/fim_event/ebpf_event）。
func RecordCHWriteError(op string) {
	CHWriteErrorsTotal.WithLabelValues(op).Inc()
}

// RecordUnknownDataType 记录一次未知 DataType（已转 DLQ）。
// RecordDLQWriteFailure 记录一次 DLQ 写入失败——即一条消息的最终丢失。
func RecordDLQWriteFailure(dlqTopic string) {
	DLQWriteFailuresTotal.WithLabelValues(dlqTopic).Inc()
}

func RecordUnknownDataType(dataType string) {
	UnknownDataTypeTotal.WithLabelValues(dataType).Inc()
}

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

// --- 就绪检查（/readyz）---
//
// 后台组件（如 ML 异常检测器的 schema gate）通过 RegisterReadiness 注册一个就绪回调，
// /readyz 聚合所有回调：全部就绪返回 200，否则返回 503 并列出未就绪项。
// 与 /healthz（进程存活）区分：schema 未就绪时进程仍存活（fail-closed 只观测不落库），但 /readyz 报未就绪。
var (
	readinessMu     sync.RWMutex
	readinessChecks = map[string]func() bool{}
)

// RegisterReadiness 注册/覆盖一个命名就绪检查。name 稳定唯一（如 "anomaly_schema"）。
func RegisterReadiness(name string, check func() bool) {
	readinessMu.Lock()
	defer readinessMu.Unlock()
	readinessChecks[name] = check
}

// readinessSnapshot 返回各就绪检查结果与整体是否全部就绪（按 name 排序，输出稳定）。
//
// 锁内只复制 name + check 函数引用，解锁后再逐个调用回调 —— 绝不持锁执行回调：
// 回调可能慢/阻塞/panic，持锁执行会连带卡住 RegisterReadiness 与其他 /readyz 请求。
func readinessSnapshot() (results []string, ready bool) {
	readinessMu.RLock()
	names := make([]string, 0, len(readinessChecks))
	checks := make(map[string]func() bool, len(readinessChecks))
	for n, fn := range readinessChecks {
		names = append(names, n)
		checks[n] = fn
	}
	readinessMu.RUnlock()

	sort.Strings(names)
	ready = true
	for _, n := range names {
		ok := runReadinessCheck(checks[n])
		if !ok {
			ready = false
		}
		state := "ready"
		if !ok {
			state = "not_ready"
		}
		results = append(results, n+"="+state)
	}
	return results, ready
}

// runReadinessCheck 安全执行单个就绪回调：panic 时恢复并判 not_ready。
// 某组件回调 panic 不应拖垮 /readyz 整个端点或进程（进程存活优先，未就绪由编排器观测）。
func runReadinessCheck(fn func() bool) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	return fn()
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

	// ML 异常检测器安全状态指标（低基数，仅本独立 registry；不走 promauto 默认 registry）。
	registry.MustRegister(
		AnomalyModeGauge,
		AnomalyEffectiveModeGauge,
		AnomalySchemaReady,
		AnomalyDNSFieldReady,
		AnomalyIForestTrained,
		AnomalySampleCount,
		AnomalyHostCount,
	)

	// 模型健康指标（漂移/投毒防护、版本、训练集、排序通路）定义在 anomaly 包内，
	// 因为它们是事件驱动的计数器，无法用"周期性把状态拷过来"的方式表达。
	// 必须显式注册到本 registry：anomaly 包若用 promauto，指标会落到默认 registry，
	// /metrics 永远抓不到，而告警规则的存在会让人以为已被监控覆盖。
	registry.MustRegister(anomaly.Collectors()...)
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
	// /readyz：聚合各组件就绪检查（如 anomaly schema gate）。未就绪→503，供编排器/运维观测。
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		results, ready := readinessSnapshot()
		if ready {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		body := "ready"
		if !ready {
			body = "not_ready"
		}
		for _, r := range results {
			body += "\n" + r
		}
		_, _ = w.Write([]byte(body))
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
