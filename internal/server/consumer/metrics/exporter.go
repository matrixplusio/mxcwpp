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

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/signals"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"
	"github.com/matrixplusio/mxcwpp/internal/server/remediation"

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

	// ClickHouse 拒收的行数：该行取值与表结构不符（如枚举里没有的值），已从批次剔除、不会重试。
	// 原先一行出错会让整批作废，且只在日志里留一条，同批的 FIM 证据会一起丢失且不易察觉。
	CHRowsRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_ch_rows_rejected_total",
		Help: "Number of rows rejected by ClickHouse because a value does not fit the table schema, labeled by table.",
	}, []string{"table"})

	// 写失败、留在内存里等待重试的行数。大于 0 期间 offset 不推进；持续不降说明 ClickHouse
	// 一直写不进去，数据在 consumer 内存与 Kafka 里积压。
	CHRetryRows = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_ch_retry_rows",
		Help: "Rows that failed to write to ClickHouse and are kept in memory for retry, labeled by table.",
	}, []string{"table"})

	// 转存到 Kafka 的行数：写不进 ClickHouse（持续不可用或取值不合表结构），需用回放工具补写。
	// 非零即表示 ClickHouse 里缺了这些行，控制台与大屏看不到。
	CHSpilledRowsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_ch_spilled_rows_total",
		Help: "Rows that could not be written to ClickHouse and were spilled to Kafka for replay, labeled by table and reason.",
	}, []string{"table", "reason"})

	// 隔离丢弃的行数：写不进 ClickHouse、也无法转存（序列化失败或单行过大）。真正丢了的数据，
	// 日志「这一行无法转存」里有 host_id；单行过大多半是主机上报异常，值得查那台主机。
	CHRowsDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_ch_rows_dropped_total",
		Help: "Rows dropped because they could neither be written to ClickHouse nor spilled, labeled by table.",
	}, []string{"table"})

	// 转存失败次数：ClickHouse 与转存都写不进去，这些行只剩在 consumer 内存里。
	CHSpillFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_ch_spill_failures_total",
		Help: "Number of failed attempts to spill rows to Kafka, labeled by table.",
	}, []string{"table"})

	// 转存主题里回放工具还没处理的记录数。转存发生后一直不为 0，直到回放完；
	// 「数据转存过」会随时间从告警窗口里消失，「还没回放」不会。为 -1 表示没算出来。
	CHSpillPendingRecords = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_consumer_ch_spill_pending_records",
		Help: "Records in the ClickHouse spill topic not yet replayed; -1 when it cannot be computed.",
	})

	// 写入方因缓冲超限等待超时的次数。说明 ClickHouse 长时间写不进去、内存缓冲已满。
	CHBackpressureTimeoutsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_ch_backpressure_timeouts_total",
		Help: "Number of times a writer waited for buffer room and timed out because ClickHouse writes kept failing.",
	})

	// 消费到未路由的未知 DataType 次数（已转 DLQ，原仅 Debug 丢弃 = 静默数据黑洞）。
	UnknownDataTypeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_consumer_unknown_data_type_total",
		Help: "Number of messages with an unrouted/unknown DataType consumed (sent to DLQ).",
	}, []string{"data_type"})

	// DLQ 写入失败次数。这是数据保全的最后一米：消息处理失败 → 转 DLQ 保底 → 连 DLQ 也没写进去，
	// 此时消息真的没了。异步 producer 在突发流量下可能成批丢消息，原先只有一条
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

// RecordCHRowRejected 记录一行被 ClickHouse 拒收（table 为固定小集合）。
func RecordCHRowRejected(table string) {
	CHRowsRejectedTotal.WithLabelValues(table).Inc()
}

// SetCHRetryRows 设置某张表等待重试的行数。
func SetCHRetryRows(table string, n int) {
	CHRetryRows.WithLabelValues(table).Set(float64(n))
}

// RecordCHSpilled 记录转存的行数。
func RecordCHSpilled(table, reason string, rows int) {
	CHSpilledRowsTotal.WithLabelValues(table, reason).Add(float64(rows))
}

// SetCHSpillPending 设置待回放的转存记录数。
func SetCHSpillPending(n int64) {
	CHSpillPendingRecords.Set(float64(n))
}

// RecordCHRowDropped 记录一行被隔离丢弃。
func RecordCHRowDropped(table string) {
	CHRowsDroppedTotal.WithLabelValues(table).Inc()
}

// RecordCHSpillFailure 记录一次转存失败。
func RecordCHSpillFailure(table string) {
	CHSpillFailuresTotal.WithLabelValues(table).Inc()
}

// RecordCHBackpressureTimeout 记录一次写入方等待缓冲空间超时。
func RecordCHBackpressureTimeout() {
	CHBackpressureTimeoutsTotal.Inc()
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

// DeleteConsumerLag 分区被重平衡迁走时删掉它的积压序列。
func DeleteConsumerLag(topic, partition string) {
	ConsumerLag.DeleteLabelValues(topic, partition)
}

// SetConsumerLag 由提交屏障调用：最新位置 − 已提交位置。
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
		// 下面四个曾漏登记：/metrics 上没有，引用它们的 critical 告警从来不可能触发。
		CHWriteErrorsTotal,
		CHRowsRejectedTotal,
		UnknownDataTypeTotal,
		DLQWriteFailuresTotal,
		CHRetryRows,
		CHBackpressureTimeoutsTotal,
		CHSpilledRowsTotal,
		CHSpillFailuresTotal,
		CHRowsDroppedTotal,
		CHSpillPendingRecords,
	)
	// 计数器的标签序列在第一次 Inc 时才出现，第一次抓到的就是非零值，increase() 看不到这次增长。
	// 拒收可能只在短时间内集中出现，预置为 0 才不会漏掉进程重启后的第一次。
	for _, t := range []string{"host_metrics", "fim_events", "ebpf_events", "auth_events"} {
		CHWriteErrorsTotal.WithLabelValues(t)
		CHRowsRejectedTotal.WithLabelValues(t)
		CHRetryRows.WithLabelValues(t)
		CHSpillFailuresTotal.WithLabelValues(t)
		CHRowsDroppedTotal.WithLabelValues(t)
		for _, r := range []string{"clickhouse_unavailable", "rejected"} {
			CHSpilledRowsTotal.WithLabelValues(t, r)
		}
	}

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

	// 同理：死信生产者的丢弃/队列指标、前置检查失效结果计数都定义在别的包里。
	registry.MustRegister(kafka.Collectors()...)
	registry.MustRegister(remediation.Collectors()...)
	registry.MustRegister(signals.Collectors()...)
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
