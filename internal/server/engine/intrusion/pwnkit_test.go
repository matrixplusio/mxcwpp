package intrusion

import (
	"context"
	"testing"
)

// PwnKit 检测只认作为程序被执行的 pkexec，不认命令行里出现的 polkit 字样。
func TestPwnKitPatternMatchesOnlyPkexecInvocation(t *testing.T) {
	d := NewPrivEscalationDetector()
	scan := func(cmd string) bool {
		_, hit := d.Scan(context.Background(), ProcessEvent{HostID: "h1", Cmdline: cmd})
		return hit
	}
	for _, cmd := range []string{"pkexec", "pkexec /bin/sh", "/usr/bin/pkexec --user root id", "sudo pkexec bash"} {
		if !scan(cmd) {
			t.Errorf("应判为 PwnKit 提权: %q", cmd)
		}
	}
	for _, cmd := range []string{"crontab -l -u polkitd", "systemctl status polkit", "/usr/lib/polkit-1/polkitd --no-debug"} {
		if scan(cmd) {
			t.Errorf("不应判为提权: %q", cmd)
		}
	}
}
