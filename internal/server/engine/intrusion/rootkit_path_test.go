package intrusion

import (
	"context"
	"testing"
)

// 路径类持久化判据只认真实目录：重建 initramfs 的临时目录里也有 etc/systemd/system 与 etc/cron.d，
// 那里的文件不会被系统加载，不是持久化。
func TestRootkitPathIndicatorsAreAnchored(t *testing.T) {
	d := NewRootkitDetector()
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/systemd/system/backdoor.service", true},
		{"/etc/systemd/system/multi-user.target.wants/evil.service", true},
		{"/etc/cron.d/evil", true},
		{"/var/spool/cron/root", true},
		{"/tmp/dracut.7oscvq/initramfs/etc/systemd/system/rescue.target.wants/systemd-vconsole-setup.service", false},
		{"/initramfs/squash/root/etc/systemd/system/initrd.target.wants/kdump-capture.service", false},
		{"/var/tmp/dracut.abc/initramfs/etc/cron.d/0hourly", false},
		{"/data/backup/var/spool/cron/root", false},
	}
	for _, c := range cases {
		_, got := d.Scan(context.Background(), IndicatorEvent{HostID: "h1", Source: SourceFile, Content: c.path, ExePath: "/usr/bin/cp"})
		if got != c.want {
			t.Errorf("%s: 命中=%v，期望 %v", c.path, got, c.want)
		}
	}
}
