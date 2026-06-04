package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StatusReport 运行状态报告
type StatusReport struct {
	Version         string `json:"version"`
	BuildTime       string `json:"build_time"`
	ServerHost      string `json:"server_host"`
	AgentID         string `json:"agent_id"`
	SystemdActive   bool   `json:"systemd_active"`
	SystemdState    string `json:"systemd_state"`
	MainPID         int    `json:"main_pid"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	ServerReachable bool   `json:"server_reachable"`
	ServerError     string `json:"server_error,omitempty"`
	PluginCount     int    `json:"plugin_count"`
	LogFile         string `json:"log_file"`
	WorkDir         string `json:"work_dir"`
}

// RunStatus 执行 --status 子命令
func RunStatus(opts CommonOptions, out io.Writer) error {
	r := collectStatus(opts)
	if opts.JSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	_, err := io.WriteString(out, formatStatusText(r))
	return err
}

// collectStatus 收集状态（不依赖 io.Writer，便于测试）
func collectStatus(opts CommonOptions) *StatusReport {
	r := &StatusReport{
		Version:    versionString(opts.BuildVersion),
		BuildTime:  opts.BuildTime,
		ServerHost: opts.ServerHost,
		AgentID:    readFileTrim(DefaultIDFile),
		LogFile:    DefaultLogFile,
		WorkDir:    DefaultWorkDir,
	}

	r.SystemdActive, r.SystemdState, r.MainPID, r.UptimeSeconds = readSystemdState(SystemdUnit)
	r.ServerReachable, r.ServerError = probeTCP(opts.ServerHost, 3*time.Second)
	r.PluginCount = countPlugins(filepath.Join(DefaultWorkDir, "plugin"))

	return r
}

// readSystemdState 调 `systemctl show <unit>` 解析关键属性
//
// 返回：active、SubState 文本（如 running/dead）、MainPID、Uptime（秒，未启动时 0）
func readSystemdState(unit string) (bool, string, int, int64) {
	out, err := execCommand("systemctl",
		"show", unit,
		"--property=ActiveState",
		"--property=SubState",
		"--property=MainPID",
		"--property=ActiveEnterTimestamp",
	)
	if err != nil {
		return false, "unknown", 0, 0
	}
	props := parseSystemdShow(string(out))
	active := props["ActiveState"] == "active"
	sub := props["SubState"]
	if sub == "" {
		sub = "unknown"
	}
	pid, _ := strconv.Atoi(props["MainPID"])
	var uptime int64
	if ts := props["ActiveEnterTimestamp"]; ts != "" {
		// systemd 默认格式 "Day YYYY-MM-DD HH:MM:SS TZ"
		if t, err := parseSystemdTimestamp(ts); err == nil && !t.IsZero() {
			uptime = max(int64(time.Since(t).Seconds()), 0)
		}
	}
	if pid == 0 {
		uptime = 0
	}
	return active, sub, pid, uptime
}

// parseSystemdShow 把 "Key=Value\n" 行解析为 map
func parseSystemdShow(out string) map[string]string {
	m := make(map[string]string)
	for line := range strings.SplitSeq(out, "\n") {
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		m[line[:idx]] = strings.TrimSpace(line[idx+1:])
	}
	return m
}

// parseSystemdTimestamp 解析 systemd ActiveEnterTimestamp 格式
//
// 形如 "Mon 2026-06-03 12:34:56 CST"。空值或 "n/a" 返回零值。
func parseSystemdTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "n/a" {
		return time.Time{}, nil
	}
	// 去掉星期前缀
	if i := strings.IndexByte(s, ' '); i > 0 && i <= 4 {
		s = s[i+1:]
	}
	// 尝试常见布局
	layouts := []string{
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp: %q", s)
}

// probeTCP 探测 host:port 连通性
//
// host 已含端口时直接使用；为空返回 false 不可达。
func probeTCP(addr string, timeout time.Duration) (bool, string) {
	if addr == "" {
		return false, "server host not embedded"
	}
	d := net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, ""
}

// countPlugins 统计 plugin 目录下的子目录数量（粗略指标）
func countPlugins(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n
}

// formatStatusText 把 StatusReport 渲染为人类可读文本
func formatStatusText(r *StatusReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "mxsec-agent status\n")
	fmt.Fprintf(&b, "  Version:        %s\n", r.Version)
	if r.BuildTime != "" {
		fmt.Fprintf(&b, "  Build time:     %s\n", r.BuildTime)
	}
	fmt.Fprintf(&b, "  Server:         %s\n", emptyDash(r.ServerHost))
	fmt.Fprintf(&b, "  Agent ID:       %s\n", emptyDash(r.AgentID))
	fmt.Fprintf(&b, "  Work dir:       %s\n", r.WorkDir)
	fmt.Fprintf(&b, "  Log file:       %s\n", r.LogFile)
	fmt.Fprintf(&b, "  Plugins:        %d\n", r.PluginCount)
	fmt.Fprintf(&b, "\nSystemd\n")
	fmt.Fprintf(&b, "  Active:         %s (%s)\n", boolYesNo(r.SystemdActive), r.SystemdState)
	if r.MainPID > 0 {
		fmt.Fprintf(&b, "  PID:            %d\n", r.MainPID)
	}
	if r.UptimeSeconds > 0 {
		fmt.Fprintf(&b, "  Uptime:         %s\n", formatDuration(r.UptimeSeconds))
	}
	fmt.Fprintf(&b, "\nServer reachability\n")
	if r.ServerReachable {
		fmt.Fprintf(&b, "  TCP:            OK\n")
	} else {
		fmt.Fprintf(&b, "  TCP:            FAIL (%s)\n", emptyDash(r.ServerError))
	}
	return b.String()
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// formatDuration 友好显示秒数（天/时/分/秒）
func formatDuration(sec int64) string {
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	var parts []string
	if d > 0 {
		parts = append(parts, fmt.Sprintf("%dd", d))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	if s > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", s))
	}
	return strings.Join(parts, "")
}

// execCommand 默认执行外部命令，测试时可替换
var execCommand = func(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}
