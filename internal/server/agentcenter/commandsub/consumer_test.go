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
	_, err := NewConsumer([]string{"x:9092"}, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil pusher")
	}
}

func TestNewConsumer_RejectsEmptyBrokers(t *testing.T) {
	t.Parallel()
	_, err := NewConsumer(nil, &fakePusher{}, nil)
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
