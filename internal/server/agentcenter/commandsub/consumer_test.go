package commandsub

import (
	"sync"
	"testing"
)

type fakePusher struct {
	mu        sync.Mutex
	pushes    []string
	batchHits int
}

func (f *fakePusher) PushToAgent(agentID string, _ []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushes = append(f.pushes, agentID)
	return true, nil
}

func (f *fakePusher) PushToAgents(agentIDs []string, _ []byte) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batchHits++
	f.pushes = append(f.pushes, agentIDs...)
	return len(agentIDs), 0, nil
}

func TestNewConsumer_RejectsNilPusher(t *testing.T) {
	t.Parallel()
	_, err := NewConsumer([]string{"x:9092"}, "ac-1", nil, nil)
	if err == nil {
		t.Fatal("expected error for nil pusher")
	}
}

func TestNewConsumer_RejectsEmptyBrokers(t *testing.T) {
	t.Parallel()
	_, err := NewConsumer(nil, "ac-1", &fakePusher{}, nil)
	if err == nil {
		t.Fatal("expected error for nil brokers")
	}
}

func TestConsumerGroupID_Constant(t *testing.T) {
	t.Parallel()
	if ConsumerGroupID != "mxcwpp-ac-command" {
		t.Fatalf("ConsumerGroupID must be 'mxcwpp-ac-command', got %q", ConsumerGroupID)
	}
}

func TestCommandMessage_DecodingFields(t *testing.T) {
	t.Parallel()
	c := CommandMessage{
		TenantID:    "t-bank-a",
		AgentIDs:    []string{"a1", "a2"},
		CommandType: "rule_sync",
		IssuedAt:    1234567890,
		TraceID:     "abc",
		IdempotKey:  "k1",
	}
	if c.TenantID != "t-bank-a" || len(c.AgentIDs) != 2 {
		t.Fatalf("CommandMessage fields incorrect")
	}
}

// TestGroupIDFor_PerInstance 多台 AC 必须各自一组：共用一组时每条命令只分给其中一台，
// 目标 Agent 连在另一台上就静默丢失。
func TestGroupIDFor_PerInstance(t *testing.T) {
	if GroupIDFor("ac-a") == GroupIDFor("ac-b") {
		t.Fatal("不同实例必须使用不同的消费组")
	}
	if GroupIDFor("") != ConsumerGroupID {
		t.Fatalf("未配置实例 ID 时退回原组名，实际 %q", GroupIDFor(""))
	}
}
