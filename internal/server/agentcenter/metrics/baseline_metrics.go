package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// 基线任务结局指标（任务层）。
//
// 结果摄取/主机完成的可观测由 consumer 侧已有的 RecordProcessing 覆盖
// （per topic+datatype+status，topic=mxcwpp.agent.baseline，datatype=8000/8001）：
// kafka 启用时 8000/8001 走 consumer 落库，AC 内联路径不触发，故此处不再重复埋点。
// 任务结局发生在 AC 的超时调度器（与管道无关），仍在此暴露。
var (
	// outcome: completed / partial / failed / retried
	baselineTaskOutcome = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_baseline_task_outcome_total",
		Help: "Baseline scan task lifecycle outcomes on timeout handling",
	}, []string{"outcome"})
)

// 任务结局取值
const (
	BaselineOutcomeCompleted = "completed"
	BaselineOutcomePartial   = "partial"
	BaselineOutcomeFailed    = "failed"
	BaselineOutcomeRetried   = "retried"
)

// IncBaselineTaskOutcome 记录一次任务结局（completed/partial/failed/retried）。
func IncBaselineTaskOutcome(outcome string) {
	baselineTaskOutcome.WithLabelValues(outcome).Inc()
}
