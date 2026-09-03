package advisory

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// 漏洞库新鲜度指标。
//
// 漏洞库停更是典型的静默失效：同步任务挂了或上游拒绝服务后，界面上漏洞列表照常
// 显示，只是内容永远停在最后一次成功的时刻。运维看不出区别，直到某个已公开数周的
// CVE 在事后复盘里出现——那时才发现平台早就不知道它了。
//
// 因此计量的不是"跑了多少次"，而是"距上次成功多久"：前者在任务反复失败时同样在增长，
// 后者才能回答"我现在看到的漏洞数据可信到什么时候"。
var (
	// lastSuccessTimestamp 上次成功同步的 Unix 秒。按源打标签，
	// 单个上游长期失败不会被其它源的成功掩盖。
	lastSuccessTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_vulnsync_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful advisory sync, by source",
	}, []string{"source"})

	// syncOutcome 按结果计数，区分成功与失败原因。
	syncOutcome = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_vulnsync_outcome_total",
		Help: "Advisory sync attempts by source and outcome",
	}, []string{"source", "outcome"})

	// advisoriesFetched 单次同步取到的 advisory 条数。
	// 持续为 0 而 outcome=success，说明上游"成功但没数据"——同样是停更，只是更隐蔽。
	advisoriesFetched = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_vulnsync_advisories_fetched_total",
		Help: "Advisories fetched from upstream, by source",
	}, []string{"source"})
)

// RecordSyncSuccess 记录一次成功同步。
func RecordSyncSuccess(source string, fetched int) {
	lastSuccessTimestamp.WithLabelValues(source).Set(float64(time.Now().Unix()))
	syncOutcome.WithLabelValues(source, "success").Inc()
	if fetched > 0 {
		advisoriesFetched.WithLabelValues(source).Add(float64(fetched))
	}
}

// RecordSyncFailure 记录一次失败同步。不更新新鲜度时间戳——
// 失败不能让"上次成功"看起来更近，否则告警永远不会触发。
func RecordSyncFailure(source string) {
	syncOutcome.WithLabelValues(source, "failure").Inc()
}
