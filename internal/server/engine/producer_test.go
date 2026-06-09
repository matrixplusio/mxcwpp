package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/IBM/sarama/mocks"
)

func TestAlertProducer_Publish_WithMock(t *testing.T) {
	t.Parallel()
	mp := mocks.NewAsyncProducer(t, nil)
	defer mp.Close()

	mp.ExpectInputAndSucceed()

	p := &AlertProducer{
		producer: mp,
		topic:    "mxsec.engine.alert",
		logger:   nil,
		stopCh:   make(chan struct{}),
	}

	env := AlertEnvelope{
		AlertID:    "alrt-1",
		TenantID:   "t-bank-a",
		HostID:     "h-1",
		RuleID:     "BRUTE_FORCE_SSH",
		Severity:   "high",
		DetectedAt: time.Now(),
	}
	if err := p.Publish(context.Background(), env); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func TestAlertProducer_DefaultMode(t *testing.T) {
	t.Parallel()
	mp := mocks.NewAsyncProducer(t, nil)
	defer mp.Close()
	mp.ExpectInputAndSucceed()

	p := &AlertProducer{producer: mp, topic: "x", stopCh: make(chan struct{})}
	env := AlertEnvelope{AlertID: "a", TenantID: "t", RuleID: "r"}
	if err := p.Publish(context.Background(), env); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func TestAlertEnvelope_MarshalRoundtrip(t *testing.T) {
	t.Parallel()
	env := AlertEnvelope{
		AlertID:  "a-1",
		TenantID: "t",
		RuleID:   "r",
		Mode:     "observe",
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out AlertEnvelope
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.AlertID != env.AlertID {
		t.Errorf("alert_id roundtrip failed")
	}
}
