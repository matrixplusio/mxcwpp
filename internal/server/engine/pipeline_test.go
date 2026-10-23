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
// 已发现的几处静默失效，共同点正是没人知道某个东西一直是零。
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

// selfPersistStub 模拟自行落库的阶段：每次命中都返回一条用于外发。
type selfPersistStub struct{ stubStage }

func (s *selfPersistStub) PersistsOwnAlerts() bool { return true }

// 阶段告警数只统计告警，不统计命中：
// 由流水线落库的阶段在这里计一次；自行落库的阶段每次命中都会返回一条，那是命中次数，
// 它们的告警数由落库处在新开告警时上报，流水线不能再计——否则计数会按命中次数暴涨。
func TestPipelineCountsAlertsOnlyForStagesItPersists(t *testing.T) {
	alert := []Alert{{AlertID: "a-1", RuleID: "R", Severity: "high"}}
	plain := &stubStage{name: "count_plain", alerts: alert}
	self := &selfPersistStub{stubStage{name: "count_self", alerts: alert}}

	p := NewPipeline(nil, nil, []Stage{plain, self}, nil)
	h := p.Handler()
	for i := 0; i < 3; i++ {
		_ = h(context.Background(), &sarama.ConsumerMessage{Topic: "mxcwpp.agent.ebpf", Value: []byte(`{"tenant_id":"t1","host_id":"h1"}`)})
	}

	if got := testutil.ToFloat64(Metrics().StageAlerts.WithLabelValues("count_plain", "high")); got != 3 {
		t.Errorf("由流水线落库的阶段应计 3，得 %v", got)
	}
	if got := testutil.ToFloat64(Metrics().StageAlerts.WithLabelValues("count_self", "high")); got != 0 {
		t.Errorf("自行落库的阶段不应由流水线计数，得 %v", got)
	}
}

// 补全在自排除和各阶段之前执行，各阶段看到的是补全后的字段。
//
// agent 自己的文件与网络事件不带 exe，此前自排除对它们不生效——
// 排除逻辑只看 exe，而 exe 是空的。
func TestPipelineEnrichesBeforeSelfExclusionAndStages(t *testing.T) {
	var seen []string
	probe := &fieldProbeStage{onFields: func(f map[string]string) { seen = append(seen, f["exe"]) }}
	p := NewPipeline(nil, nil, []Stage{probe}, nil)
	p.SetEnricher(func(_ PipelineEvent, fields map[string]string) {
		switch fields["pid"] {
		case "1":
			fields["exe"] = "/usr/sbin/nginx"
		case "2":
			fields["exe"] = agentSelfDir + "plugins/collector/collector"
		}
	})
	h := p.Handler()
	for _, pid := range []string{"1", "2", "3"} {
		_ = h(context.Background(), &sarama.ConsumerMessage{Topic: "mxcwpp.agent.ebpf",
			Value: []byte(`{"agent_id":"a1","data_type":3002,"event_type":"tcp_connect","uid":"0","pid":"` + pid + `"}`)})
	}
	if len(seen) != 2 || seen[0] != "/usr/sbin/nginx" || seen[1] != "" {
		t.Fatalf("各阶段看到的 exe = %q，期望 [nginx, 空]：补全后的 agent 自身事件应被排除", seen)
	}
}

type fieldProbeStage struct{ onFields func(map[string]string) }

func (s *fieldProbeStage) Name() string { return "field_probe" }
func (s *fieldProbeStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if f, err := ev.Fields(); err == nil {
		s.onFields(f)
	}
	return nil, nil
}

// 自排除只认规范化的绝对路径与 root 身份：eBPF 的 exe 是 execve 的原样参数，
// 普通用户执行 /var/lib/mxcwpp-agent/../../../tmp/x 就能把自己的 exec 整条藏掉。
func TestIsAgentSelfEventRejectsSpoofedPaths(t *testing.T) {
	cases := []struct {
		exe, uid, inContainer string
		want                  bool
	}{
		{"/usr/bin/mxcwpp-agent", "0", "", true},
		{"/usr/bin/mxcwpp-agent (deleted)", "0", "", true},
		{"/var/lib/mxcwpp-agent/plugins/collector/collector", "0", "", true},
		{"/var/lib/mxcwpp-agent/plugins/x (deleted)", "0", "", false},         // 插件目录不放宽 (deleted)
		{"/var/lib/mxcwpp-agent/plugins/scanner/bin/clamscan", "", "", false}, // 无 uid：确认不了身份
		{"/var/lib/mxcwpp-agent/plugins/x", "0", "true", false},               // 容器 root 自建的同名路径
		{"/var/lib/mxcwpp-agent/../../../tmp/payload", "1000", "", false},
		{"/var/lib/mxcwpp-agent/../../../bin/bash", "0", "", false},
		{"/var/lib/mxcwpp-agent//plugins/x", "0", "", false},
		{"/var/lib/mxcwpp-agent/plugins/collector/collector", "1000", "", false},
		{"/usr/bin/mxcwpp-agentcenter", "0", "", false},
		{"/usr/bin/mxcwpp-agent-evil", "0", "", false},
		{"var/lib/mxcwpp-agent/plugins/x", "0", "", false},
		{"", "0", "", false},
	}
	for _, c := range cases {
		f := map[string]string{"agent_id": "a1", "event_type": "process_exec", "exe": c.exe}
		if c.uid != "" {
			f["uid"] = c.uid
		}
		if c.inContainer != "" {
			f["in_container"] = c.inContainer
		}
		raw, _ := json.Marshal(f)
		ev := PipelineEvent{DataType: 3000, Payload: raw}
		if got := isAgentSelfEvent(ev); got != c.want {
			t.Errorf("exe=%q uid=%q in_container=%q: got %v, want %v", c.exe, c.uid, c.inContainer, got, c.want)
		}
	}

	// /proc 补采的进程事件与内存威胁事件不带容器标记，分不清容器 root 自建的同名路径，不排除。
	for _, src := range []string{"proc_snapshot", "reconciliation"} {
		raw, _ := json.Marshal(map[string]string{"exe": "/var/lib/mxcwpp-agent/x", "uid": "0", "source": src})
		if isAgentSelfEvent(PipelineEvent{DataType: 3000, Payload: raw}) {
			t.Errorf("source=%s 不该被当成自身", src)
		}
	}
	raw, _ := json.Marshal(map[string]string{"exe": "/var/lib/mxcwpp-agent/x", "uid": "0"})
	if isAgentSelfEvent(PipelineEvent{DataType: 3004, Payload: raw}) {
		t.Error("内存威胁事件不该被当成自身")
	}
}
