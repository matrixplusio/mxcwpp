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
	return &AsyncProducer{
		producer: fake,
		logger:   zap.NewNop(),
		fallback: make(chan *pendingMsg, 16),
		closed:   make(chan struct{}),
		msgPool: sync.Pool{
			New: func() any { return &sarama.ProducerMessage{} },
		},
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
	// 把 input 占满，迫使 Send 走 default → enqueueToFallback
	for i := 0; i < cap(fake.input); i++ {
		fake.input <- &sarama.ProducerMessage{}
	}
	p := newTestAsyncProducer(fake)

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
