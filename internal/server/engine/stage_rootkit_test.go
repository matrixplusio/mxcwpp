package engine

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

// Stage 必须把执行体透传给 detector。
//
// detector 靠 exe 排除包管理器写 systemd 单元这类常规行为。Stage 不传的话，
// 排除逻辑在真实链路里完全不生效——detector 的单测会过，线上照样每次装包报警。
// 这正是「只测 detector 不测 Stage」会漏掉的那一层。
func TestRootkitStage_PassesExeToDetector(t *testing.T) {
	st := NewRootkitStage(nil, zap.NewNop())

	mk := func(fields map[string]string) PipelineEvent {
		b, _ := json.Marshal(fields)
		return PipelineEvent{HostID: "h1", DataType: 3001, Payload: b}
	}

	// 包管理器写 systemd 单元：常规行为，不该告警
	alerts, err := st.Process(context.Background(), mk(map[string]string{
		"file_path": "/etc/systemd/system/node-exporter.service",
		"exe":       "/usr/bin/dpkg",
	}))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("包管理器装包不该报持久化后门，实际产生 %d 条告警——"+
			"说明 exe 没有透传到 detector", len(alerts))
	}

	// 同一路径但执行体是 shell：应当告警
	alerts, err = st.Process(context.Background(), mk(map[string]string{
		"file_path": "/etc/systemd/system/evil.service",
		"exe":       "/bin/bash",
	}))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("shell 投放 systemd 单元应当告警，实际未命中")
	}
}

// 无关事件不产生告警，也不报错。
func TestRootkitStage_IgnoresUnrelatedEvents(t *testing.T) {
	st := NewRootkitStage(nil, zap.NewNop())
	b, _ := json.Marshal(map[string]string{"exe": "/usr/bin/ls", "cmdline": "ls -la"})
	alerts, err := st.Process(context.Background(),
		PipelineEvent{HostID: "h1", DataType: 3000, Payload: b})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("普通命令不该告警，实际 %d 条", len(alerts))
	}
}
