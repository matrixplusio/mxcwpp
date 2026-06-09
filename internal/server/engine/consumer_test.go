package engine

import (
	"context"
	"testing"

	"github.com/IBM/sarama"
)

func TestNewKafkaConsumer_RejectsEmptyBrokers(t *testing.T) {
	t.Parallel()
	_, err := NewKafkaConsumer(nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error for nil brokers")
	}
	_, err = NewKafkaConsumer([]string{}, nil, nil)
	if err == nil {
		t.Fatalf("expected error for empty brokers")
	}
}

func TestSubscribedTopics_IsNonEmpty(t *testing.T) {
	t.Parallel()
	if len(SubscribedTopics) == 0 {
		t.Fatalf("SubscribedTopics must not be empty")
	}
	want := map[string]bool{
		"mxsec.agent.ebpf":     true,
		"mxsec.agent.events":   true,
		"mxsec.agent.scanner":  true,
		"mxsec.agent.baseline": true,
		"mxsec.vuln.advisory":  true,
	}
	for _, topic := range SubscribedTopics {
		if !want[topic] {
			t.Errorf("unexpected topic in SubscribedTopics: %s", topic)
		}
	}
}

func TestConsumerGroupID_Constant(t *testing.T) {
	t.Parallel()
	if ConsumerGroupID != "mxsec-engine" {
		t.Fatalf("ConsumerGroupID must be 'mxsec-engine', got %q", ConsumerGroupID)
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
