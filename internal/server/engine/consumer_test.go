package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/IBM/sarama"
)

func TestNewKafkaConsumer_RejectsEmptyBrokers(t *testing.T) {
	t.Parallel()
	_, err := NewKafkaConsumer(nil, "", nil, nil)
	if err == nil {
		t.Fatalf("expected error for nil brokers")
	}
	_, err = NewKafkaConsumer([]string{}, "", nil, nil)
	if err == nil {
		t.Fatalf("expected error for empty brokers")
	}
}

// TestBuildSubscribedTopics_AppliesPrefix 回归: agent.* 必须带 topic_prefix
// (与 AgentCenter 生产端一致), 否则 Engine 收不到任何事件; vuln.advisory 由
// VulnSync 裸名生产, 保持不带前缀。
func TestBuildSubscribedTopics_AppliesPrefix(t *testing.T) {
	t.Parallel()
	got := buildSubscribedTopics("prod")
	want := map[string]bool{
		"prodmxcwpp.agent.ebpf":     true,
		"prodmxcwpp.agent.events":   true,
		"prodmxcwpp.agent.scanner":  true,
		"prodmxcwpp.agent.baseline": true,
		"mxcwpp.vuln.advisory":      true, // advisory 裸名, 不带前缀
	}
	if len(got) != len(want) {
		t.Fatalf("topic count = %d, want %d: %v", len(got), len(want), got)
	}
	for _, topic := range got {
		if !want[topic] {
			t.Errorf("unexpected topic: %s", topic)
		}
	}
}

// TestBuildSubscribedTopics_EmptyPrefix 空前缀时 agent.* 退化为裸名。
func TestBuildSubscribedTopics_EmptyPrefix(t *testing.T) {
	t.Parallel()
	got := buildSubscribedTopics("")
	if !slices.Contains(got, "mxcwpp.agent.ebpf") {
		t.Errorf("empty prefix should yield bare mxcwpp.agent.ebpf, got %v", got)
	}
}

func TestConsumerGroupID_Constant(t *testing.T) {
	t.Parallel()
	if ConsumerGroupID != "mxcwpp-engine" {
		t.Fatalf("ConsumerGroupID must be 'mxcwpp-engine', got %q", ConsumerGroupID)
	}
}

func TestNoopHandler_ReturnsNil(t *testing.T) {
	t.Parallel()
	err := noopHandler(context.Background(), &sarama.ConsumerMessage{})
	if err != nil {
		t.Fatalf("noop handler should never error, got %v", err)
	}
}

func TestGroupHandler_SetupCleanup(t *testing.T) {
	t.Parallel()
	h := &groupHandler{handler: noopHandler, logger: nil}
	// Setup/Cleanup 是 sarama interface 要求,但我们不做任何事
	if err := h.Setup(nil); err != nil {
		t.Errorf("Setup: %v", err)
	}
	if err := h.Cleanup(nil); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
}
