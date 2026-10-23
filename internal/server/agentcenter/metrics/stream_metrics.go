package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// streamIdleClosedTotal 统计因长时间收不到任何消息而被主动断开的 Agent 流。
//
// 连接还在、Agent 却不再发送时，主机会被判离线但流永远不断，只能等 MaxConnectionAge 才自愈。
// 非零值说明有 Agent 发送侧停摆，持续增长时应排查 Agent 与服务端的写入延迟。
var streamIdleClosedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "mxcwpp_ac_stream_idle_closed_total",
	Help: "Agent streams closed by the server after receiving nothing for the idle timeout",
})

// IncStreamIdleClosed 记录一次空闲超时断流。
func IncStreamIdleClosed() {
	streamIdleClosedTotal.Inc()
}

// identityConflictTotal 统计同一 AgentID 出现在不同机器上的次数（克隆镜像、证书被拷走）。
var identityConflictTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "mxcwpp_ac_identity_conflict_total",
	Help: "Connections whose AgentID is already bound to a different machine",
}, []string{"action"})

// IncIdentityConflict 记录一次身份冲突，action 为 alert 或 reject。
func IncIdentityConflict(action string) {
	identityConflictTotal.WithLabelValues(action).Inc()
}
