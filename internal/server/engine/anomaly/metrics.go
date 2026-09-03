package anomaly

import "github.com/prometheus/client_golang/prometheus"

// Collectors 返回本包定义的全部 Prometheus 指标，供宿主进程注册。
//
// 为什么必须显式返回而不是用 promauto 自动注册：consumer 进程用的是**独立 registry**
// （见 consumer/metrics/exporter.go），promauto 注册到的默认 registry 根本不会被
// /metrics 暴露。指标定义了、代码在打点、告警规则也写了，但 Prometheus 永远抓不到——
// 这比没有埋点更糟：告警规则的存在会让人以为这块已经被监控覆盖了。
//
// 新增指标时必须同时加进这个列表，否则它不会出现在 /metrics 上。
func Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		anomalyDriftScore,
		anomalyRetrainRejected,
		anomalyModelAge,
		anomalyReferenceLoaded,
		anomalyScoreFlushFailed,
		anomalyModelVersion,
		trainingSampleHosts,
	}
}
