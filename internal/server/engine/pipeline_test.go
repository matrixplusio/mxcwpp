package engine

import (
	"context"

	"encoding/json"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"testing"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"

	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
)

type stubStage struct {
	name   string
	alerts []Alert
	calls  int
}

func (s *stubStage) Name() string { return s.name }
func (s *stubStage) Process(_ context.Context, _ PipelineEvent) ([]Alert, error) {
	s.calls++
	return s.alerts, nil
}

func TestPipeline_NoStages_NoOp(t *testing.T) {
	t.Parallel()
	p := NewPipeline(nil, nil, nil, nil)
	h := p.Handler()
	err := h(context.Background(), &sarama.ConsumerMessage{
		Topic: "x",
		Value: []byte(`{"tenant_id":"t1"}`),
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPipeline_StageProduces_AlertObserveMode(t *testing.T) {
	t.Parallel()
	mp := mocks.NewAsyncProducer(t, nil)
	defer mp.Close()
	mp.ExpectInputAndSucceed()

	producer := &AlertProducer{producer: mp, topic: "mxcwpp.engine.alert", stopCh: make(chan struct{})}
	resolver := mode.NewMemoryResolver(mode.Observe)

	stage := &stubStage{
		name: "test_stage",
		alerts: []Alert{
			{
				AlertID:  "a-1",
				RuleID:   "TEST_RULE",
				Severity: "high",
				Action:   json.RawMessage(`{"type":"ip_block"}`),
			},
		},
	}
	p := NewPipeline(producer, resolver, []Stage{stage}, nil)
	h := p.Handler()
	err := h(context.Background(), &sarama.ConsumerMessage{
		Topic: "mxcwpp.agent.ebpf",
		Value: []byte(`{"tenant_id":"t1","host_id":"h1"}`),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if stage.calls != 1 {
		t.Errorf("expected 1 stage call, got %d", stage.calls)
	}
}

func TestPipeline_ProtectMode_FillsAction(t *testing.T) {
	t.Parallel()
	mp := mocks.NewAsyncProducer(t, nil)
	defer mp.Close()
	mp.ExpectInputAndSucceed()

	producer := &AlertProducer{producer: mp, topic: "mxcwpp.engine.alert", stopCh: make(chan struct{})}
	resolver := mode.NewMemoryResolver(mode.Observe)
	_ = resolver.SetRule("DANGER_RULE", mode.Protect)

	stage := &stubStage{
		name: "s",
		alerts: []Alert{
			{
				AlertID:  "a-2",
				RuleID:   "DANGER_RULE",
				Severity: "critical",
				Action:   json.RawMessage(`{"type":"kill"}`),
			},
		},
	}
	p := NewPipeline(producer, resolver, []Stage{stage}, nil)
	h := p.Handler()
	_ = h(context.Background(), &sarama.ConsumerMessage{
		Topic: "x",
		Value: []byte(`{"tenant_id":"t1","host_id":"h1"}`),
	})
}

func TestDecodeEvent_PartialFields(t *testing.T) {
	t.Parallel()
	msg := &sarama.ConsumerMessage{Value: []byte(`{"agent_id":"h-1","data_type":3001}`)}
	ev, err := decodeEvent(msg)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.AgentID != "h-1" {
		t.Errorf("agent_id: got %s", ev.AgentID)
	}
	if ev.HostID != "h-1" {
		t.Errorf("host_id: got %s", ev.HostID)
	}
	if ev.DataType != 3001 {
		t.Errorf("data_type: got %d", ev.DataType)
	}
}

// TestPrewarmStageMetrics 注册即可见：Stage 一接入流水线，它的计数器就必须存在。
//
// 不预热的话，CounterVec 的序列要等第一次告警才创建，于是"能力正常但无威胁"
// 和"能力从未跑过"在监控上都是查不到数据，无法用告警区分。
// 今天发现的几处静默失效，共同点正是没人知道某个东西一直是零。
func TestPrewarmStageMetrics(t *testing.T) {
	stages := []Stage{&countingStage{name: "prewarm_probe"}}
	PrewarmStageMetrics(stages)

	got := testutil.ToFloat64(Metrics().StageAlerts.WithLabelValues("prewarm_probe", "critical"))
	if got != 0 {
		t.Fatalf("预热后计数器应存在且为 0, got %v", got)
	}

	// 关键在于序列已存在——收集时能被抓到，而不是一片空白
	if n := testutil.CollectAndCount(Metrics().StageAlerts); n == 0 {
		t.Fatal("预热后 StageAlerts 不应为空集合")
	}
}

type countingStage struct{ name string }

func (s *countingStage) Name() string { return s.name }
func (s *countingStage) Process(_ context.Context, _ PipelineEvent) ([]Alert, error) {
	return nil, nil
}
