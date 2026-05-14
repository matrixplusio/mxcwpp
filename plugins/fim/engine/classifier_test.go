package engine

import "testing"

func TestClassifyBinaryPaths(t *testing.T) {
	tests := []struct {
		path       string
		wantSev    string
		wantCat    string
		changeType string
	}{
		{"/bin/ls", "critical", "binary", "changed"},
		{"/sbin/iptables", "critical", "binary", "changed"},
		{"/usr/bin/curl", "critical", "binary", "changed"},
		{"/usr/sbin/sshd", "critical", "binary", "changed"},
	}
	for _, tt := range tests {
		ev := &FIMEvent{FilePath: tt.path, ChangeType: tt.changeType}
		Classify(ev)
		if ev.Severity != tt.wantSev {
			t.Errorf("Classify(%s): severity = %s, want %s", tt.path, ev.Severity, tt.wantSev)
		}
		if ev.Category != tt.wantCat {
			t.Errorf("Classify(%s): category = %s, want %s", tt.path, ev.Category, tt.wantCat)
		}
	}
}

func TestClassifyAuthPaths(t *testing.T) {
	tests := []struct {
		path    string
		wantCat string
	}{
		{"/etc/passwd", "auth"},
		{"/etc/shadow", "auth"},
		{"/etc/sudoers", "auth"},
		{"/etc/pam.d/common-auth", "auth"},
	}
	for _, tt := range tests {
		ev := &FIMEvent{FilePath: tt.path, ChangeType: "changed"}
		Classify(ev)
		if ev.Category != tt.wantCat {
			t.Errorf("Classify(%s): category = %s, want %s", tt.path, ev.Category, tt.wantCat)
		}
		if ev.Severity != "high" {
			t.Errorf("Classify(%s): severity = %s, want high", tt.path, ev.Severity)
		}
	}
}

func TestClassifySSHPaths(t *testing.T) {
	ev := &FIMEvent{FilePath: "/etc/ssh/sshd_config", ChangeType: "changed"}
	Classify(ev)
	if ev.Severity != "high" || ev.Category != "ssh" {
		t.Errorf("got severity=%s category=%s, want high/ssh", ev.Severity, ev.Category)
	}
}

func TestClassifyConfigPaths(t *testing.T) {
	tests := []struct {
		path    string
		wantSev string
	}{
		{"/etc/crontab", "high"},
		{"/etc/cron.d/daily", "high"},
		{"/etc/systemd/system/my.service", "high"},
		{"/etc/init.d/nginx", "high"},
		{"/etc/hostname", "medium"}, // 通用 /etc/ → medium
		{"/etc/resolv.conf", "medium"},
	}
	for _, tt := range tests {
		ev := &FIMEvent{FilePath: tt.path, ChangeType: "changed"}
		Classify(ev)
		if ev.Severity != tt.wantSev {
			t.Errorf("Classify(%s): severity = %s, want %s", tt.path, ev.Severity, tt.wantSev)
		}
	}
}

func TestClassifyOtherPaths(t *testing.T) {
	ev := &FIMEvent{FilePath: "/opt/app/data.json", ChangeType: "changed"}
	Classify(ev)
	if ev.Severity != "low" || ev.Category != "other" {
		t.Errorf("got severity=%s category=%s, want low/other", ev.Severity, ev.Category)
	}
}

func TestClassifyAddedPromotesSeverity(t *testing.T) {
	tests := []struct {
		path       string
		changeType string
		wantSev    string
	}{
		// changed → base severity; added/removed → promoted
		{"/opt/app/file.txt", "changed", "low"},
		{"/opt/app/file.txt", "added", "medium"},
		{"/opt/app/file.txt", "removed", "medium"},
		{"/etc/hostname", "changed", "medium"},
		{"/etc/hostname", "added", "high"},
		{"/etc/ssh/authorized_keys", "changed", "high"},
		{"/etc/ssh/authorized_keys", "added", "critical"},
		{"/bin/sh", "changed", "critical"},
		{"/bin/sh", "added", "critical"}, // critical stays critical
	}
	for _, tt := range tests {
		ev := &FIMEvent{FilePath: tt.path, ChangeType: tt.changeType}
		Classify(ev)
		if ev.Severity != tt.wantSev {
			t.Errorf("Classify(%s, %s): severity = %s, want %s", tt.path, tt.changeType, ev.Severity, tt.wantSev)
		}
	}
}

func TestPromoteSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"low", "medium"},
		{"medium", "high"},
		{"high", "critical"},
		{"critical", "critical"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := promoteSeverity(tt.input)
		if got != tt.want {
			t.Errorf("promoteSeverity(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}
