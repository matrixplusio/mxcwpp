package kafka

import (
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// fakeAsyncProducer 是 sarama.AsyncProducer 的最小实现，
// 仅捕获 Input chan 收到的 ProducerMessage 供测试断言。
type fakeAsyncProducer struct {
	input     chan *sarama.ProducerMessage
	successes chan *sarama.ProducerMessage
	errors    chan *sarama.ProducerError
}

func newFakeAsyncProducer() *fakeAsyncProducer {
	return &fakeAsyncProducer{
		input:     make(chan *sarama.ProducerMessage, 16),
		successes: make(chan *sarama.ProducerMessage, 16),
		errors:    make(chan *sarama.ProducerError, 16),
	}
}

func (f *fakeAsyncProducer) AsyncClose()                               { close(f.input); close(f.successes); close(f.errors) }
func (f *fakeAsyncProducer) Close() error                              { return nil }
func (f *fakeAsyncProducer) Input() chan<- *sarama.ProducerMessage     { return f.input }
func (f *fakeAsyncProducer) Successes() <-chan *sarama.ProducerMessage { return f.successes }
func (f *fakeAsyncProducer) Errors() <-chan *sarama.ProducerError      { return f.errors }
func (f *fakeAsyncProducer) IsTransactional() bool                     { return false }
func (f *fakeAsyncProducer) TxnStatus() sarama.ProducerTxnStatusFlag   { return 0 }
func (f *fakeAsyncProducer) BeginTxn() error                           { return nil }
func (f *fakeAsyncProducer) CommitTxn() error                          { return nil }
func (f *fakeAsyncProducer) AbortTxn() error                           { return nil }
func (f *fakeAsyncProducer) AddOffsetsToTxn(map[string][]*sarama.PartitionOffsetMetadata, string) error {
	return nil
}
func (f *fakeAsyncProducer) AddMessageToTxn(*sarama.ConsumerMessage, string, *string) error {
	return nil
}

func newTestAsyncProducer(fake sarama.AsyncProducer) *AsyncProducer {
	p := &AsyncProducer{
		producer: fake,
		logger:   zap.NewNop(),
		fallback: make(chan *pendingMsg, 16),
		pending:  make(chan *sarama.ProducerMessage, 16),
		closed:   make(chan struct{}),
		msgPool: sync.Pool{
			New: func() any { return &sarama.ProducerMessage{} },
		},
	}
	// 与生产一致：投递经由 feeder 阻塞写入 sarama Input。
	// 真实 sarama 的 Input 是无缓冲通道，没有 feeder 时非阻塞发送几乎必然落空。
	go p.feedLoop()
	return p
}

// newTestAsyncProducerNoFeeder 用于直接检查自有缓冲的用例：不启动 feeder，
// 消息投进 pending 后就停在那里，断言不受异步搬运的时序影响。
func newTestAsyncProducerNoFeeder(fake sarama.AsyncProducer) *AsyncProducer {
	return &AsyncProducer{
		producer: fake,
		logger:   zap.NewNop(),
		fallback: make(chan *pendingMsg, 16),
		pending:  make(chan *sarama.ProducerMessage, 16),
		closed:   make(chan struct{}),
		msgPool: sync.Pool{
			New: func() any { return &sarama.ProducerMessage{} },
		},
	}
}

// stallProducer 让下游彻底堵死，构造"投递不进去"的场景。
//
// 必须两步：先占满 fake 的 Input 让 feeder 阻塞，再占满自有缓冲。
// 只占其一都不成立——feeder 会把缓冲排空，而只堵 Input 时缓冲仍有空间。
// 生产上的等价场景是 Kafka 侧长时间不可写。
// stallProducer 占满自有缓冲，构造"投递不进去"的场景（配合无 feeder 的构造使用）。
// 生产上的等价场景是 sarama 侧长时间不可写、pending 因此堆满。
func stallProducer(p *AsyncProducer) {
	for {
		select {
		case p.pending <- &sarama.ProducerMessage{}:
		default:
			return
		}
	}
}

// TestSend_NoDoubleTopicPrefix 回归测试: producer.Send 不应再次拼接 TopicPrefix。
//
// 历史 bug: 调用方 (RouteDataType / DLQTopic) 已传入完整 topic
// "prodmxcwpp.agent.ebpf"，旧版 Send 内部又拼一次 cfg.TopicPrefix，
// 导致实际发送 topic 变成 "prodprodmxcwpp.agent.ebpf"，broker 不存在，
// sarama circuit breaker 永久 open，所有 EDR/FIM 消息被丢弃。
func TestSend_NoDoubleTopicPrefix(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducer(fake)

	wantTopic := "prodmxcwpp.agent.ebpf"
	if err := p.Send(wantTopic, "agent-1", &MQMessage{DataType: 3002, AgentID: "agent-1"}); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	select {
	case pm := <-fake.input:
		if pm.Topic != wantTopic {
			t.Fatalf("topic = %q, want %q (double prefix bug regression)", pm.Topic, wantTopic)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for producer.Input")
	}
}

// TestSend_PreservesAlreadyPrefixedTopic 验证多种已带 prefix 的 topic 透传不变。
func TestSend_PreservesAlreadyPrefixedTopic(t *testing.T) {
	cases := []string{
		"prodmxcwpp.agent.ebpf",
		"prodmxcwpp.agent.events",
		"prodmxcwpp.agent.ebpf.dlq",
		"devmxcwpp.agent.baseline",
		"mxcwpp.agent.heartbeat", // empty prefix case
	}
	for _, topic := range cases {
		t.Run(topic, func(t *testing.T) {
			fake := newFakeAsyncProducer()
			p := newTestAsyncProducer(fake)
			if err := p.Send(topic, "k", &MQMessage{}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			pm := <-fake.input
			if pm.Topic != topic {
				t.Fatalf("topic mutated: got %q want %q", pm.Topic, topic)
			}
		})
	}
}

// TestSend_FallbackPreservesTopic Input 满时入降级队列，保留原 topic 不变。
func TestSend_FallbackPreservesTopic(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)
	// 占满自有缓冲，迫使 Send 走 default → enqueueToFallback
	stallProducer(p)

	wantTopic := "prodmxcwpp.agent.ebpf"
	if err := p.Send(wantTopic, "k", &MQMessage{DataType: 3002}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case pm := <-p.fallback:
		if pm.topic != wantTopic {
			t.Fatalf("fallback topic = %q, want %q", pm.topic, wantTopic)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback queue empty")
	}
}

// TestSendReliable_DeliversToInput 验证 SendReliable 正常情况下投递到 Kafka Input。
func TestSendReliable_DeliversToInput(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducer(fake)

	if err := p.SendReliable("mxcwpp.agent.baseline", "agent-1", &MQMessage{DataType: 8001}); err != nil {
		t.Fatalf("SendReliable err: %v", err)
	}
	select {
	case pm := <-fake.input:
		if pm.Topic != "mxcwpp.agent.baseline" {
			t.Errorf("topic = %q, want mxcwpp.agent.baseline", pm.Topic)
		}
	case <-time.After(time.Second):
		t.Fatal("message not delivered to Input")
	}
}

// TestSendReliable_FallbackWhenInputFull 验证核心可靠性保证：
// Input 满时 SendReliable 不丢弃，超时后退降级队列重试。
func TestSendReliable_FallbackWhenInputFull(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)

	// 填满自有缓冲
	stallProducer(p)

	old := producerReliableSendTimeout
	producerReliableSendTimeout = 30 * time.Millisecond
	defer func() { producerReliableSendTimeout = old }()

	if err := p.SendReliable("mxcwpp.agent.baseline", "agent-1", &MQMessage{DataType: 8001}); err != nil {
		t.Fatalf("SendReliable 应退降级队列而非报错: %v", err)
	}
	// 消息必须进降级队列，不得被丢弃
	if got := p.FallbackQueueLen(); got != 1 {
		t.Fatalf("fallback len = %d, want 1（消息不得被丢弃）", got)
	}
}
