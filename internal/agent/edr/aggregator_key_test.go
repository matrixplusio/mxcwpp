//go:build linux

package edr

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

func netEvent(evtType event.EventType, remoteAddr, remotePort, localPort, direction string) *event.Event {
	e := &event.Event{
		DataType:  event.DataTypeNetwork,
		EventType: evtType,
		Fields:    map[string]string{},
	}
	e.SetField("remote_addr", remoteAddr)
	e.SetField("remote_port", remotePort)
	e.SetField("local_port", localPort)
	if direction != "" {
		e.SetField("direction", direction)
	}
	return e
}

// TestAggKey_InboundCollapsesByLocalPort 入站必须按本机端口聚合。
//
// 回归点：原实现无论方向都用对端端口做键。入站时那是客户端的临时源端口，
// 每条连接都不同，聚合键因此永不重复——聚合器对入站完全失效。
// 半小时数十万条 tcp_accept，按对端端口去重后仍有十几万组、
// 按本机端口去重 2,299 组；单台 nginx 的 141,592 条入站只来自 43 个源 IP、
// 全部打在 80 端口，却一条都没被合并。
func TestAggKey_InboundCollapsesByLocalPort(t *testing.T) {
	// 同一客户端连同一个业务端口两次，源端口不同（真实情况必然如此）
	first := netEvent(event.TCPAccept, "10.0.0.32", "51234", "80", "inbound")
	second := netEvent(event.TCPAccept, "10.0.0.32", "51987", "80", "inbound")

	if aggKey(first) != aggKey(second) {
		t.Errorf("入站同源同本机端口必须聚合到同一键，得到 %q vs %q", aggKey(first), aggKey(second))
	}

	// 连到不同本机端口必须分开——端口扫描检测靠的正是"同源命中多个本机端口"
	other := netEvent(event.TCPAccept, "10.0.0.32", "51234", "22", "inbound")
	if aggKey(first) == aggKey(other) {
		t.Error("入站不同本机端口必须是不同键，否则端口扫描检测失去判据")
	}
}

// TestAggKey_OutboundKeepsRemotePort 出站仍按对端端口聚合。
//
// 出站的对端端口是目的端口，本就该聚合；本机端口才是临时源端口。
// 同期 tcp_connect 按对端端口去重后收敛到数千组（聚合正常工作），
// 若改用本机端口会炸到 119,593 组，等于把出站的聚合也毁掉。
func TestAggKey_OutboundKeepsRemotePort(t *testing.T) {
	first := netEvent(event.TCPConnect, "203.0.113.10", "443", "40001", "outbound")
	second := netEvent(event.TCPConnect, "203.0.113.10", "443", "40002", "outbound")

	if aggKey(first) != aggKey(second) {
		t.Errorf("出站同目的地址端口必须聚合到同一键，得到 %q vs %q", aggKey(first), aggKey(second))
	}

	other := netEvent(event.TCPConnect, "203.0.113.10", "8443", "40001", "outbound")
	if aggKey(first) == aggKey(other) {
		t.Error("出站不同目的端口必须是不同键")
	}
}

// TestAggKey_InboundWithoutDirectionField 旧内核 procfs 降级路径没有 direction 字段，
// 必须以 event_type 兜底，判据与 stage_scan.go 保持一致。
func TestAggKey_InboundWithoutDirectionField(t *testing.T) {
	a := netEvent(event.TCPAccept, "10.0.0.9", "33445", "8080", "")
	b := netEvent(event.TCPAccept, "10.0.0.9", "33999", "8080", "")

	if aggKey(a) != aggKey(b) {
		t.Errorf("缺 direction 字段时应按 event_type 判定为入站，得到 %q vs %q", aggKey(a), aggKey(b))
	}
}

// TestAggregator_InboundBurstEmitsOnceThenCounts 端到端确认：
// 首条放行供检测消费，其余只累加计数不再转发。
func TestAggregator_InboundBurstEmitsOnceThenCounts(t *testing.T) {
	agg := newEventAggregator(nil)

	forwarded := 0
	for i := range 500 {
		// 同源同本机端口，源端口每条不同
		evt := netEvent(event.TCPAccept, "10.0.0.32", string(rune('0'+i%10))+"1234", "80", "inbound")
		if !agg.TryAggregate(evt) {
			forwarded++
		}
	}

	if forwarded != 1 {
		t.Errorf("500 条同键入站事件应只放行首条，实际放行 %d 条", forwarded)
	}
}
