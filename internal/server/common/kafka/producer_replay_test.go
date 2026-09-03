package kafka

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestReplayLoop_RetryCountIncrementsAndDrops 回归 2b：
// 旧实现 replayLoop 调 p.Send，Input 满时以 retryCount=0 回落降级队列，fallbackMaxRetries
// 永不触发 → 消息在队列里无限循环（直到 TTL）。修复后 replay 直投 Input 并保留/递增
// retryCount，超上限即丢弃。
//
// 本测试把 Input 占满，让 trySendInput 始终失败，验证单条消息在若干重放周期后因重试超限被丢弃
// （retryCount 确实递增），而非无限回队。
func TestReplayLoop_RetryCountIncrementsAndDrops(t *testing.T) {
	old := replayBackoff
	replayBackoff = time.Millisecond

	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)
	// 占满自有缓冲，迫使 trySendInput 始终走 default（失败）。
	stallProducer(p)

	// 单条消息，retryCount=0；Input 满时每个重放周期应 +1，达 fallbackMaxRetries 后丢弃。
	p.fallback <- &pendingMsg{topic: "t", msg: &MQMessage{}, retryCount: 0, enqueuedAt: time.Now()}
	atomic.AddInt64(&p.fallbackLen, 1)

	done := make(chan struct{})
	go func() { p.replayLoop(); close(done) }()

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt64(&p.dropped) < 1 {
		select {
		case <-deadline:
			t.Fatal("消息未在预期时间内因重试超限被丢弃：retryCount 可能未递增（死循环 bug 回归）")
		case <-time.After(2 * time.Millisecond):
		}
	}
	close(p.closed)
	<-done // 等 replayLoop 完全退出后再恢复 replayBackoff，避免与其读取竞态
	replayBackoff = old

	// 丢弃后降级队列应为空（消息被丢弃而非无限回队）。
	if got := atomic.LoadInt64(&p.fallbackLen); got != 0 {
		t.Errorf("fallbackLen = %d, 期望 0（消息已丢弃）", got)
	}
}

// TestReplayLoop_SuccessDeliversToInput 验证 Kafka 恢复（Input 有空位）时，
// 降级队列消息被成功重放投递到 Input，且透传原始分区 key。
func TestReplayLoop_SuccessDeliversToInput(t *testing.T) {
	fake := newFakeAsyncProducer()  // Input 空，trySendInput 应成功
	p := newTestAsyncProducer(fake) // 端到端用例：保留 feeder，验证消息真的抵达 sarama

	p.fallback <- &pendingMsg{topic: "prodmxcwpp.agent.ebpf", key: "agent-1", msg: &MQMessage{DataType: 3002}, retryCount: 2, enqueuedAt: time.Now()}
	atomic.AddInt64(&p.fallbackLen, 1)

	done := make(chan struct{})
	go func() { p.replayLoop(); close(done) }()

	select {
	case pm := <-fake.input:
		if pm.Topic != "prodmxcwpp.agent.ebpf" {
			t.Errorf("重放 topic = %q", pm.Topic)
		}
		if k, _ := pm.Key.Encode(); string(k) != "agent-1" {
			t.Errorf("重放丢失分区 key: %q", string(k))
		}
	case <-time.After(time.Second):
		t.Fatal("重放未投递到 Input")
	}
	close(p.closed)
	<-done
}
