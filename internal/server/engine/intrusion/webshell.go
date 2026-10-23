package intrusion

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
)

// WebshellDetector 用启发式特征 + YARA 规则检测 Web 后门。
//
// 启发式检测 (本 PR 实现):
//   - eval/assert/exec/passthru/shell_exec 与 base64_decode 组合 (PHP)
//   - <%@ Runtime.exec / ProcessBuilder (JSP)
//   - cmd /c / powershell 与 Response.Write (ASPX)
//
// 真正的 YARA 引擎集成由 Agent 端 av-scanner 插件负责;
// Engine 这一层做"文件落地事件 + 启发式快速过滤"。
type WebshellDetector struct {
	patterns []*shellPattern
}

type shellPattern struct {
	Name     string
	Severity string
	Lang     string
	Regex    *regexp.Regexp
	Hint     string
}

// NewWebshellDetector 构造内置启发式规则集。
func NewWebshellDetector() *WebshellDetector {
	return &WebshellDetector{
		patterns: []*shellPattern{
			{
				Name:     "PHP_EVAL_BASE64",
				Severity: "critical",
				Lang:     "php",
				Regex:    regexp.MustCompile(`(?i)(eval|assert)\s*\(\s*base64_decode\s*\(`),
				Hint:     "PHP eval/assert + base64_decode 链式调用是经典 webshell 模式",
			},
			{
				Name:     "PHP_SHELL_EXEC",
				Severity: "critical",
				Lang:     "php",
				Regex:    regexp.MustCompile(`(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`),
				Hint:     "PHP shell_exec/system 直接执行 $_GET/POST 参数",
			},
			{
				Name:     "JSP_RUNTIME_EXEC",
				Severity: "critical",
				Lang:     "jsp",
				Regex:    regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\s*\(`),
				Hint:     "JSP Runtime.exec 命令执行",
			},
			{
				Name:     "ASPX_RESPONSE_WRITE_CMD",
				Severity: "critical",
				Lang:     "aspx",
				Regex:    regexp.MustCompile(`(?i)Response\.Write\s*\(\s*(Process|cmd\.exe|powershell)`),
				Hint:     "ASPX 直接 Response.Write 命令输出",
			},
			{
				Name:     "JSP_PROCESS_BUILDER",
				Severity: "high",
				Lang:     "jsp",
				Regex:    regexp.MustCompile(`(?i)new\s+ProcessBuilder\s*\(`),
				Hint:     "JSP ProcessBuilder 命令构造",
			},
			{
				Name:     "GENERIC_REVERSE_SHELL",
				Severity: "high",
				Lang:     "any",
				Regex:    regexp.MustCompile(`(?i)bash\s+-i\s+>&\s+/dev/tcp/`),
				Hint:     "通用反弹 shell 模式 (bash -i)",
			},
		},
	}
}

// FileSampleEvent 是单次文件落地或修改事件的 Webshell 检测载荷。
type FileSampleEvent struct {
	HostID   string
	FilePath string
	Content  string // 完整或前 4KB 内容
	Action   string // create / modify / move
}

// Scan 检测文件内容,返回命中的所有规则的 Alert payload。
func (d *WebshellDetector) Scan(_ context.Context, ev FileSampleEvent) ([]byte, bool) {
	if ev.Content == "" {
		return nil, false
	}
	ext := getExt(ev.FilePath)
	if !suspectExt(ext) {
		return nil, false
	}

	var hits []map[string]any
	for _, p := range d.patterns {
		if p.Lang != "any" && p.Lang != ext {
			continue
		}
		loc := p.Regex.FindStringIndex(ev.Content)
		if loc == nil {
			continue
		}
		hits = append(hits, map[string]any{
			"rule":     p.Name,
			"severity": p.Severity,
			"hint":     p.Hint,
			"offset":   loc[0],
			"snippet":  snippet(ev.Content, loc[0], 80),
		})
	}
	if len(hits) == 0 {
		return nil, false
	}
	payload, _ := json.Marshal(map[string]any{
		"host_id":   ev.HostID,
		"file_path": ev.FilePath,
		"action":    ev.Action,
		"ext":       ext,
		"hits":      hits,
		"would_action": map[string]any{
			"type":   "quarantine_file",
			"target": ev.FilePath,
			"reason": "命中 " + intToStr(len(hits)) + " 条 Webshell 启发式规则",
		},
	})
	return payload, true
}

func getExt(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return ""
	}
	return strings.ToLower(path[idx+1:])
}

func suspectExt(ext string) bool {
	switch ext {
	case "php", "php3", "php4", "php5", "phtml",
		"jsp", "jspx", "jspf",
		"asp", "aspx", "ashx",
		"py", "rb", "pl", "cgi":
		return true
	}
	return false
}

func snippet(s string, off, n int) string {
	end := off + n
	if end > len(s) {
		end = len(s)
	}
	return s[off:end]
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
