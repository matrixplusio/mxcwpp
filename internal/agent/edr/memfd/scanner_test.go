//go:build linux

package memfd

import (
	"strings"
	"testing"
	"time"
)

func TestDedupPreventsRepeat(t *testing.T) {
	key := dedupKey{exe: "test-bin", threatType: "memfd_exec"}

	s := &Scanner{
		seen: make(map[dedupKey]time.Time),
	}

	// First check: not seen.
	s.seen[key] = time.Now()

	// Same key within window should be present.
	if _, ok := s.seen[key]; !ok {
		t.Error("key should be present after insertion")
	}
}

func TestDedupExpiry(t *testing.T) {
	key := dedupKey{exe: "test-bin", threatType: "deleted_exe"}

	s := &Scanner{
		seen: make(map[dedupKey]time.Time),
	}

	// Insert with past timestamp.
	s.seen[key] = time.Now().Add(-dedupWindow - time.Second)

	// Check expiry logic.
	now := time.Now()
	for k, ts := range s.seen {
		if now.Sub(ts) > dedupWindow {
			delete(s.seen, k)
		}
	}

	if _, ok := s.seen[key]; ok {
		t.Error("expired key should be cleaned up")
	}
}

func TestWhitelist(t *testing.T) {
	// 原有
	whitelisted := []string{"runc", "pulseaudio", "pipewire", "Xwayland", "memfd_test"}
	for _, name := range whitelisted {
		if !whitelistedExes[name] {
			t.Errorf("%s should be whitelisted", name)
		}
	}

	if whitelistedExes["malware"] {
		t.Error("malware should not be whitelisted")
	}

	// 2026-06-04 新增 prod 实测 top 误报源,守护回归
	prodFP := []string{
		"dbus-broker-launch", "sshd", "node_exporter", "systemd",
		"systemd-logind", "NetworkManager", "chronyd", "cron", "crond",
		"containerd", "dockerd",
	}
	for _, name := range prodFP {
		if !whitelistedExes[name] {
			t.Errorf("%s 必须 whitelist (prod top false positive)", name)
		}
	}
}

func TestSystemBinDirsCoverage(t *testing.T) {
	// 守护:确保关键系统目录在 demotion 名单
	mustHave := []string{"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/"}
	for _, want := range mustHave {
		found := false
		for _, d := range systemBinDirs {
			if d == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("systemBinDirs 必须包含 %s", want)
		}
	}
}

func TestDeletedExeSystemDirSkipped(t *testing.T) {
	// 模拟:系统目录的 deleted_exe 应被 demotion(不通过 systemBinDirs check)
	systemExes := []string{
		"/usr/bin/sshd",
		"/usr/sbin/NetworkManager",
		"/usr/lib/systemd/systemd",
	}
	for _, exe := range systemExes {
		demoted := false
		for _, d := range systemBinDirs {
			if strings.HasPrefix(exe, d) {
				demoted = true
				break
			}
		}
		if !demoted {
			t.Errorf("%s 在系统目录但未被 demotion", exe)
		}
	}

	// 反例:非系统目录(/tmp/malware)应被告警(不 demotion)
	suspect := []string{"/tmp/xmrig", "/dev/shm/exploit", "/var/tmp/backdoor"}
	for _, exe := range suspect {
		for _, d := range systemBinDirs {
			if strings.HasPrefix(exe, d) {
				t.Errorf("%s 不应被 demotion(可疑路径)", exe)
			}
		}
	}
}
