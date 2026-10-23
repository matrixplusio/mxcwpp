package celengine

import (
	"testing"

	"go.uber.org/zap"
)

func lexec(t *ProcessTree, pid, ppid, exe string) {
	t.HandleExec("h1", map[string]string{"pid": pid, "ppid": ppid, "exe": exe, "cmdline": exe})
}

// 登录会话、服务、定时任务各自是一段独立活动的起点。
func TestLineageRoot(t *testing.T) {
	tr := NewProcessTree(zap.NewNop())
	lexec(tr, "1", "0", "/usr/lib/systemd/systemd")
	lexec(tr, "500", "1", "/usr/sbin/sshd")
	lexec(tr, "600", "500", "/usr/sbin/sshd-session")
	lexec(tr, "700", "600", "/bin/bash") // 登录 shell
	lexec(tr, "710", "700", "/usr/bin/sudo")
	lexec(tr, "720", "710", "/usr/bin/id") // 会话里的命令
	lexec(tr, "800", "1", "/usr/sbin/crond")
	lexec(tr, "810", "800", "/bin/sh") // 定时任务
	lexec(tr, "820", "810", "/usr/bin/curl")
	lexec(tr, "900", "1", "/opt/app/server") // 服务
	lexec(tr, "910", "900", "/bin/sh")

	cases := map[string]string{"720": "700", "710": "700", "820": "810", "910": "900", "900": "900"}
	for pid, want := range cases {
		r, ok := tr.LineageRoot("h1", pid)
		if !ok || r.PID != want {
			t.Errorf("进程 %s 的血缘根应为 %s，得 %+v", pid, want, r)
		}
	}
	if _, ok := tr.LineageRoot("h1", "999"); ok {
		t.Error("不在树里的进程应返回 false，由调用方退到主机级")
	}
	// 父链断了（祖先没有执行事件）就取已知的最上层。
	lexec(tr, "1100", "1050", "/bin/bash")
	lexec(tr, "1110", "1100", "/usr/bin/whoami")
	if r, _ := tr.LineageRoot("h1", "1110"); r.PID != "1100" {
		t.Errorf("父链断开时应取已知最上层，得 %+v", r)
	}
	// 伪装成边界程序名、但不在系统目录下的程序不是边界：用 /tmp/cron 派生的命令仍归到上层。
	lexec(tr, "1200", "700", "/tmp/cron")
	lexec(tr, "1210", "1200", "/usr/bin/curl")
	if r, _ := tr.LineageRoot("h1", "1210"); r.PID != "700" {
		t.Errorf("/tmp/cron 不应算作边界，血缘根应仍是登录 shell，得 %+v", r)
	}
	// 进程号复用时键不同：同一个进程号先后是两个进程，不能合并成一个实体。
	a, _ := tr.LineageRoot("h1", "700")
	lexec(tr, "700", "600", "/bin/bash")
	b, _ := tr.LineageRoot("h1", "700")
	if a.Key == b.Key {
		t.Error("进程号复用后血缘键应不同")
	}
}
