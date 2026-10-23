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

// deliveryTotal 分发器对每个渠道的每一次决定。与 notification_deliveries 一一对应，
// 用来在监控上直接看出「类别没开」「没有接收方」「发送失败」各占多少。
var deliveryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "mxcwpp_notify_delivery_total",
	Help: "Notification dispatcher decisions by category and outcome",
}, []string{"category", "outcome"})

// pendingEvents 待处理的通知事件数；持续增长说明分发器停了或发送一直失败。
var pendingEvents = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "mxcwpp_notify_outbox_pending",
	Help: "Alert notify events waiting to be dispatched",
})

// IncDelivery 记录一次投递决定。
func IncDelivery(category, outcome string) {
	deliveryTotal.WithLabelValues(category, outcome).Inc()
}
