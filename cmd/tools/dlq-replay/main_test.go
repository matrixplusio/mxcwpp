package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/IBM/sarama"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
)

// fakeSession 记录哪些消息被推进了位点。
type fakeSession struct {
	sarama.ConsumerGroupSession
	marked   int
	commits  int
	markedAt []int64
}

func (f *fakeSession) MarkMessage(msg *sarama.ConsumerMessage, _ string) {
	f.marked++
	f.markedAt = append(f.markedAt, msg.Offset)
}
func (f *fakeSession) Commit() { f.commits++ }

// fakeClaim 提供一批预置消息后关闭 channel。
type fakeClaim struct {
	sarama.ConsumerGroupClaim
	ch chan *sarama.ConsumerMessage
}

func (f *fakeClaim) Messages() <-chan *sarama.ConsumerMessage { return f.ch }

func newClaim(msgs ...*sarama.ConsumerMessage) *fakeClaim {
	ch := make(chan *sarama.ConsumerMessage, len(msgs))
	for _, m := range msgs {
		ch <- m
	}
	close(ch)
	return &fakeClaim{ch: ch}
}

func dlqMsg(t *testing.T, offset int64, agentID string, retry int, errMsg string) *sarama.ConsumerMessage {
	t.Helper()
	body, err := json.Marshal(kafka.DLQMessage{
		Original:    &kafka.MQMessage{DataType: 6001, AgentID: agentID},
		Error:       errMsg,
		SourceTopic: "mxcwpp.agent.events",
		RetryCount:  retry,
		FailedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &sarama.ConsumerMessage{Offset: offset, Value: body}
}

func newHandler(apply bool, maxRetry, max int) *replayHandler {
	h := &replayHandler{
		opt:         options{apply: apply, maxRetry: maxRetry, max: max},
		sourceTopic: "mxcwpp.agent.events",
	}
	h.lastMsg.Store(time.Now())
	return h
}

// TestReplay_DryRunDoesNotAdvanceOffset 预演不得推进位点，否则"看一眼"就把
// 待重放的消息跳过去了，真正执行时反而捞不到。
func TestReplay_DryRunDoesNotAdvanceOffset(t *testing.T) {
	h := newHandler(false, 3, 100)
	sess := &fakeSession{}
	claim := newClaim(
		dlqMsg(t, 1, "host-a", 0, "mysql timeout"),
		dlqMsg(t, 2, "host-b", 0, "mysql timeout"),
	)
	if err := h.ConsumeClaim(sess, claim); err != nil {
		t.Fatalf("ConsumeClaim: %v", err)
	}
	if sess.marked != 0 || sess.commits != 0 {
		t.Errorf("预演不应推进位点，实际 marked=%d commits=%d", sess.marked, sess.commits)
	}
	if h.replayed != 2 {
		t.Errorf("预演应统计出 2 条待重放，实际 %d", h.replayed)
	}
}

// TestReplay_SkipsPoisonMessages 重试次数达上限的消息不再重放。
// 这类消息重放多少次都会再失败，继续放只会在队列间循环并淹没正常流量。
func TestReplay_SkipsPoisonMessages(t *testing.T) {
	h := newHandler(true, 3, 100)
	sess := &fakeSession{}
	claim := newClaim(
		dlqMsg(t, 1, "host-a", 3, "invalid field"), // 已达上限
		dlqMsg(t, 2, "host-b", 5, "invalid field"), // 超出上限
	)
	if err := h.ConsumeClaim(sess, claim); err != nil {
		t.Fatalf("ConsumeClaim: %v", err)
	}
	if h.poison != 2 {
		t.Errorf("应识别 2 条毒消息，实际 %d", h.poison)
	}
	if h.replayed != 0 {
		t.Errorf("毒消息不应被重放，实际重放 %d 条", h.replayed)
	}
	if sess.marked != 2 {
		t.Errorf("毒消息应推进位点以免卡住，实际 marked=%d", sess.marked)
	}
}

// TestReplay_UndecodableAdvancesButIsReported 解析不了的记录必须推进位点，
// 否则工具会卡在同一条上反复读取；但要计入报告，不能当作正常处理掉。
func TestReplay_UndecodableAdvancesButIsReported(t *testing.T) {
	h := newHandler(true, 3, 100)
	sess := &fakeSession{}
	claim := newClaim(
		&sarama.ConsumerMessage{Offset: 1, Value: []byte("not json")},
		&sarama.ConsumerMessage{Offset: 2, Value: []byte(`{"error":"x"}`)}, // 无 original
	)
	if err := h.ConsumeClaim(sess, claim); err != nil {
		t.Fatalf("ConsumeClaim: %v", err)
	}
	if h.undecodabl != 2 {
		t.Errorf("应计入 2 条无法解析，实际 %d", h.undecodabl)
	}
	if sess.marked != 2 {
		t.Errorf("无法解析的记录应推进位点避免卡死，实际 marked=%d", sess.marked)
	}
}

// TestReplay_RespectsMaxCap 达到上限即停，避免一次把整个 DLQ 灌回正常链路。
func TestReplay_RespectsMaxCap(t *testing.T) {
	h := newHandler(false, 3, 2)
	sess := &fakeSession{}
	claim := newClaim(
		dlqMsg(t, 1, "a", 0, "e"),
		dlqMsg(t, 2, "b", 0, "e"),
		dlqMsg(t, 3, "c", 0, "e"),
		dlqMsg(t, 4, "d", 0, "e"),
	)
	if err := h.ConsumeClaim(sess, claim); err != nil {
		t.Fatalf("ConsumeClaim: %v", err)
	}
	if h.replayed != 2 {
		t.Errorf("上限 2 条，实际处理 %d 条", h.replayed)
	}
}

// TestTruncate 错误信息用于报告聚合，须防止超长内容刷屏。
func TestTruncate(t *testing.T) {
	if got := truncate("   "); got != "(无错误信息)" {
		t.Errorf("空错误应有占位文案，实际 %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := truncate(long); len(got) > 130 {
		t.Errorf("超长错误未截断，长度 %d", len(got))
	}
}
