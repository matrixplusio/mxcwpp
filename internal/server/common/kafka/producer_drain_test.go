package kafka

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

// TestDrainFallback_BatchesWhileInputHasRoom 排空必须成批。
//
// 回归点：旧实现每轮只重放一条，失败即退避 100ms。生产上因此出现积压与空闲并存的死局——
// 降级队列满着 5 万条、Kafka 侧全空闲，队列排空速度约 10 条/秒，而消息 300 秒就到 TTL，
// 于是队列里的东西在被重试之前先死掉，队列恒定钉在容量上限、丢弃恒定 141 条/秒，
// 重启也只是重新灌满。一条一条喂还有第二个后果：sarama 攒不出批次，
// 吞吐被钉死在"批大小 ÷ 往返延迟"，而不是链路能力。
func TestDrainFallback_BatchesWhileInputHasRoom(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)

	// 队列里放 10 条，Input 容量 16（够放下）
	const queued = 10
	for range queued {
		p.fallback <- &pendingMsg{topic: "t", msg: &MQMessage{}, enqueuedAt: time.Now()}
		atomic.AddInt64(&p.fallbackLen, 1)
	}

	drained, inputFull := p.drainFallback(replayBatch)
	if inputFull {
		t.Fatal("Input 尚有空间时不应报告已满")
	}
	if drained != queued {
		t.Errorf("单轮应排空 %d 条，实际 %d 条", queued, drained)
	}
	if got := atomic.LoadInt64(&p.fallbackLen); got != 0 {
		t.Errorf("排空后队列长度应为 0，实际 %d", got)
	}
	if len(p.pending) != queued {
		t.Errorf("应有 %d 条进入缓冲，实际 %d 条", queued, len(p.pending))
	}
}

// TestDrainFallback_StopsWhenInputFull Input 满时必须立刻停手并把消息回队，
// 交由调用方退避——继续空转会烧 CPU，丢弃则是数据损失。
func TestDrainFallback_StopsWhenInputFull(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)
	stallProducer(p)

	p.fallback <- &pendingMsg{topic: "t", msg: &MQMessage{}, enqueuedAt: time.Now()}
	atomic.AddInt64(&p.fallbackLen, 1)

	drained, inputFull := p.drainFallback(replayBatch)
	if !inputFull {
		t.Error("Input 已满时应报告，否则调用方不会退避")
	}
	if drained != 0 {
		t.Errorf("一条都推不进去时排空数应为 0，实际 %d", drained)
	}
	// 消息必须回到队列，不能凭空消失
	if got := atomic.LoadInt64(&p.fallbackLen); got != 1 {
		t.Errorf("失败的消息应回队，队列长度期望 1，实际 %d", got)
	}
}

// TestDrainFallback_ExpiredDoesNotBlockDrain 过期消息应被丢弃并继续排空，
// 不能因为队头是陈货就停下——那正是队列排不空的成因之一。
func TestDrainFallback_ExpiredDoesNotBlockDrain(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)

	stale := time.Now().Add(-2 * fallbackMsgTTL)
	p.fallback <- &pendingMsg{topic: "t", msg: &MQMessage{}, enqueuedAt: stale}
	p.fallback <- &pendingMsg{topic: "t", msg: &MQMessage{}, enqueuedAt: time.Now()}
	atomic.AddInt64(&p.fallbackLen, 2)

	drained, inputFull := p.drainFallback(replayBatch)
	if inputFull {
		t.Fatal("Input 有空间时不应报告已满")
	}
	if drained != 1 {
		t.Errorf("过期 1 条 + 有效 1 条，成功重放应为 1，实际 %d", drained)
	}
	if atomic.LoadInt64(&p.dropped) != 1 {
		t.Errorf("过期消息应计入丢弃，实际 dropped=%d", atomic.LoadInt64(&p.dropped))
	}
	if len(p.pending) != 1 {
		t.Errorf("只有未过期的那条应进缓冲，实际 %d 条", len(p.pending))
	}
}

// TestEnqueueFallback_EvictsOldestWhenFull 队列满时淘汰最旧的，而不是拒收最新的。
//
// 拒收新消息会让队列变成一潭死水：里面全是接近 TTL 的陈货，占满容量空转，
// 新到达的数据一条都进不来。队头离过期最近、被成功重放的机会最小，淘汰它代价最低。
func TestEnqueueFallback_EvictsOldestWhenFull(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)

	// 灌满降级队列
	capacity := cap(p.fallback)
	for i := range capacity {
		p.fallback <- &pendingMsg{topic: "old", key: string(rune('a' + i%26)), msg: &MQMessage{}, enqueuedAt: time.Now()}
	}
	atomic.StoreInt64(&p.fallbackLen, int64(capacity))

	if err := p.enqueueToFallbackWithRetry("new", "k", &MQMessage{}, 0); err != nil {
		t.Fatalf("队列满时应淘汰最旧的给新消息让位，却返回错误: %v", err)
	}

	// 队列仍满（淘汰一条、进来一条），且新消息确实在队列里
	if got := atomic.LoadInt64(&p.fallbackLen); got != int64(capacity) {
		t.Errorf("淘汰一条又入队一条后长度应不变(%d)，实际 %d", capacity, got)
	}

	var foundNew bool
	for range capacity {
		select {
		case pm := <-p.fallback:
			if pm.topic == "new" {
				foundNew = true
			}
		default:
		}
	}
	if !foundNew {
		t.Error("新消息应已入队，实际未找到——说明仍在拒收新数据")
	}
}

// TestSend_DoesNotDependOnUnbufferedInputRace 投递不得直接对 sarama 的 Input 做非阻塞发送。
//
// 根因回归：sarama 的 Input() 是**无缓冲**通道（async_producer.go:139，ChannelBufferSize
// 只作用于其内部 partition/broker 通道）。对无缓冲通道做 select+default，只有恰好有接收者
// parked 在那一瞬间才成功，否则立刻落空——与下游是否有能力完全无关。
// 表现为：broker 全空闲、消费零延迟、链路吞吐充裕，而发送侧速率低两个数量级，
// 其余全进降级队列直到过期，且不重启不恢复。
//
// 用例刻意在**没有接收者**时发送：旧实现此时必然落空并回落降级队列，
// 经自有缓冲则应全部成功，待接收者出现后如数抵达。
func TestSend_DoesNotDependOnUnbufferedInputRace(t *testing.T) {
	fake := &fakeAsyncProducer{
		input:     make(chan *sarama.ProducerMessage), // 无缓冲，与真实 sarama 一致
		successes: make(chan *sarama.ProducerMessage, 1),
		errors:    make(chan *sarama.ProducerError, 1),
	}
	p := newTestAsyncProducer(fake)

	// 此刻没有任何接收者 parked 在 Input 上
	const n = 8
	for range n {
		if err := p.Send("prodmxcwpp.agent.ebpf", "agent-1", &MQMessage{DataType: 3002}); err != nil {
			t.Fatalf("无接收者时 Send 不应失败（说明又在直接非阻塞投 Input）: %v", err)
		}
	}
	if d := atomic.LoadInt64(&p.dropped); d != 0 {
		t.Fatalf("消息不该被丢弃，实际 dropped=%d", d)
	}

	// 接收者出现后，消息应如数抵达
	got := 0
	deadline := time.After(3 * time.Second)
	for got < n {
		select {
		case <-fake.input:
			got++
		case <-deadline:
			t.Fatalf("只抵达 %d/%d 条", got, n)
		}
	}
	close(p.closed)
}
