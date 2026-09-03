package alertbus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// publishTotal 按去向计量每一次发布。
//
// outcome 是这个指标的全部价值：只统计"发了多少条"无法回答运维真正要问的问题——
// 没送出去是因为类别还没灰度开、等级不够、被抑制、没有匹配的接收方，还是发送失败？
// 这几种情况的处置完全不同，收敛成一个成功率会让它们无法区分。
var publishTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "mxcwpp_alert_publish_total",
	Help: "Alert publications by producing source, notification category and outcome",
}, []string{"source", "category", "outcome"})

// IncPublish 记录一次发布去向。
func IncPublish(source, category, outcome string) {
	publishTotal.WithLabelValues(source, category, outcome).Inc()
}
