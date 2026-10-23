package kafka

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

func errMsg(t *testing.T, retry any) *sarama.ProducerMessage {
	t.Helper()
	body, _ := json.Marshal(&MQMessage{DataType: 5050})
	return &sarama.ProducerMessage{Topic: "prodmxcwpp.agent.asset", Key: sarama.StringEncoder("agent-1"),
		Value: sarama.ByteEncoder(body), Metadata: retry}
}

// runErrorLoop 把错误逐条喂给 errorLoop，等它处理完后退出。
func runErrorLoop(t *testing.T, p *AsyncProducer, fake *fakeAsyncProducer, errs ...*sarama.ProducerError) {
	t.Helper()
	done := make(chan struct{})
	go func() { p.errorLoop(); close(done) }()
	for _, e := range errs {
		fake.errors <- e
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(fake.errors) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	close(p.closed)
	<-done
}

// TestErrorLoop_PermanentErrorDropped 消息过大重发也不会成功：直接丢弃，不进降级队列。
// 回归：超过大小上限的消息曾在「失败 → 入队 → 重放 → 再失败」里无限循环。
func TestErrorLoop_PermanentErrorDropped(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)
	tooLarge := sarama.ConfigurationError("Attempt to produce message larger than configured Producer.MaxMessageBytes: 1049545 > 1048576")
	runErrorLoop(t, p, fake,
		&sarama.ProducerError{Msg: errMsg(t, 0), Err: tooLarge},
		&sarama.ProducerError{Msg: errMsg(t, 0), Err: sarama.ErrMessageSizeTooLarge},
	)
	if n := atomic.LoadInt64(&p.fallbackLen); n != 0 {
		t.Fatalf("永久性错误不应进降级队列，fallbackLen=%d", n)
	}
	if n := atomic.LoadInt64(&p.dropped); n != 2 {
		t.Fatalf("应丢弃 2 条，实际 %d", n)
	}
}

// TestErrorLoop_RetryCountCarried 可重试的错误带着原重试次数回队，上限才能生效；
// 已到上限的直接丢弃。
func TestErrorLoop_RetryCountCarried(t *testing.T) {
	fake := newFakeAsyncProducer()
	p := newTestAsyncProducerNoFeeder(fake)
	runErrorLoop(t, p, fake, &sarama.ProducerError{Msg: errMsg(t, 2), Err: errors.New("broker not available")})
	if len(p.fallback) != 1 {
		t.Fatalf("可重试错误应回降级队列，实际队列长度 %d", len(p.fallback))
	}
	if pm := <-p.fallback; pm.retryCount != 3 {
		t.Fatalf("重试次数应从 2 递增到 3，实际 %d", pm.retryCount)
	}

	fake2 := newFakeAsyncProducer()
	p2 := newTestAsyncProducerNoFeeder(fake2)
	runErrorLoop(t, p2, fake2, &sarama.ProducerError{Msg: errMsg(t, fallbackMaxRetries-1), Err: errors.New("broker not available")})
	if len(p2.fallback) != 0 || atomic.LoadInt64(&p2.dropped) != 1 {
		t.Fatalf("到达上限应丢弃：队列 %d，丢弃 %d", len(p2.fallback), atomic.LoadInt64(&p2.dropped))
	}
}
