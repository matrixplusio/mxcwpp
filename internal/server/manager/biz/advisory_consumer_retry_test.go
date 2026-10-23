package biz

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

type fakeSession struct {
	sarama.ConsumerGroupSession
	ctx    context.Context
	mu     sync.Mutex
	marked []int64
}

func (s *fakeSession) Context() context.Context { return s.ctx }
func (s *fakeSession) MarkMessage(m *sarama.ConsumerMessage, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.marked = append(s.marked, m.Offset)
}
func (s *fakeSession) markedOffsets() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.marked...)
}

type fakeClaim struct {
	sarama.ConsumerGroupClaim
	ch chan *sarama.ConsumerMessage
}

func (c *fakeClaim) Messages() <-chan *sarama.ConsumerMessage { return c.ch }

func advisoryMsg(t *testing.T, offset int64) *sarama.ConsumerMessage {
	t.Helper()
	b, err := advisory.AdvisoryMessage{Source: "rhsa",
		Advisory: &advisory.Advisory{AdvisoryID: "A", CVEIDs: []string{"CVE-2026-0001"}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &sarama.ConsumerMessage{Offset: offset, Value: b}
}

func fastAdvisoryRetry(t *testing.T) {
	old := advisoryRetryBase
	advisoryRetryBase = time.Millisecond
	t.Cleanup(func() { advisoryRetryBase = old })
}

// flush 失败时不提交 offset，退避后用同一批重做，成功后才提交。
// 此前 flush 不返回成败、无条件提交，写入失败的整批通告就此丢失。
func TestAdvisoryFlushFailureRetriesBeforeCommit(t *testing.T) {
	fastAdvisoryRetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{ctx: ctx}
	claim := &fakeClaim{ch: make(chan *sarama.ConsumerMessage, 1)}

	var mu sync.Mutex
	calls, sizes := 0, []int{}
	h := &advisoryGroupHandler{c: &AdvisoryConsumer{logger: zap.NewNop()}, flushFn: func(msgs []advisory.AdvisoryMessage, _ bool) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		sizes = append(sizes, len(msgs))
		if calls < 3 {
			if got := sess.markedOffsets(); len(got) != 0 {
				t.Errorf("flush 成功之前不应提交 offset，实际已提交 %v", got)
			}
			return errors.New("lock wait timeout")
		}
		cancel() // 成功后结束会话
		return nil
	}}
	claim.ch <- advisoryMsg(t, 41)
	close(claim.ch) // claim 关闭触发 flush

	done := make(chan struct{})
	go func() { _ = h.ConsumeClaim(sess, claim); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ConsumeClaim 未结束")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 {
		t.Errorf("应重做到第 3 次成功，实际 flush %d 次", calls)
	}
	for _, n := range sizes {
		if n != 1 {
			t.Errorf("每次重做都应是同一批（1 条），实际 %v", sizes)
			break
		}
	}
	if got := sess.markedOffsets(); len(got) != 1 || got[0] != 41 {
		t.Errorf("成功后应提交 offset 41，实际 %v", got)
	}
}

// 一直失败时会话结束：不提交，交给 Kafka 重新投递。
func TestAdvisoryFlushFailureNoCommitOnSessionEnd(t *testing.T) {
	fastAdvisoryRetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	sess := &fakeSession{ctx: ctx}
	claim := &fakeClaim{ch: make(chan *sarama.ConsumerMessage, 1)}
	n := 0
	h := &advisoryGroupHandler{c: &AdvisoryConsumer{logger: zap.NewNop()}, flushFn: func([]advisory.AdvisoryMessage, bool) error {
		n++
		if n == 2 {
			cancel()
		}
		return errors.New("deadlock")
	}}
	claim.ch <- advisoryMsg(t, 7)
	close(claim.ch)
	done := make(chan struct{})
	go func() { _ = h.ConsumeClaim(sess, claim); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("会话结束后 ConsumeClaim 应返回")
	}
	if got := sess.markedOffsets(); len(got) != 0 {
		t.Errorf("一直失败不应提交 offset，实际 %v", got)
	}
}

// 缓冲里有没写成功的消息时，坏消息不能单独提交：提交它会越过前面的消息，那些消息就丢了。
func TestMalformedMessageDoesNotCommitPastUnflushed(t *testing.T) {
	fastAdvisoryRetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	sess := &fakeSession{ctx: ctx}
	claim := &fakeClaim{ch: make(chan *sarama.ConsumerMessage, 2)}
	h := &advisoryGroupHandler{c: &AdvisoryConsumer{logger: zap.NewNop()}, flushFn: func([]advisory.AdvisoryMessage, bool) error {
		cancel() // 第一次 flush 就失败并结束会话
		return errors.New("db down")
	}}
	claim.ch <- advisoryMsg(t, 10)
	claim.ch <- &sarama.ConsumerMessage{Offset: 11, Value: []byte("not json")}
	close(claim.ch)
	done := make(chan struct{})
	go func() { _ = h.ConsumeClaim(sess, claim); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ConsumeClaim 未结束")
	}
	if got := sess.markedOffsets(); len(got) != 0 {
		t.Errorf("offset 10 未写成功，不应提交任何位置，实际 %v", got)
	}
}
