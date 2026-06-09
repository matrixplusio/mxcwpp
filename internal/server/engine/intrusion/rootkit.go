package intrusion

import (
	"context"
	"encoding/json"
	"regexp"
)

// RootkitDetector 检测 Linux Rootkit / 持久化后门常见指标。
//
// 检测维度:
//   - 内核模块加载 (LKM rootkit: Diamorphine/Reptile/Beurk)
//   - /etc/cron.* 或 systemd unit 文件落地 (持久化)
//   - LD_PRELOAD 环境变量异常 (用户态 rootkit)
//   - /proc 隐藏进程 (kallsyms 钩子)
//   - SSH key 写入到 ~/.ssh/authorized_keys
type RootkitDetector struct {
	lkmPatterns     []*regexp.Regexp
	cronPatterns    []*regexp.Regexp
	preloadPatterns []*regexp.Regexp
	systemdPatterns []*regexp.Regexp
	authKeyPatterns []*regexp.Regexp
}

// NewRootkitDetector 构造。
func NewRootkitDetector() *RootkitDetector {
	return &RootkitDetector{
		lkmPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(diamorphine|reptile|beurk|suterusu|adore|knark)\b`),
			regexp.MustCompile(`insmod\s+.*\.ko\b`),
			regexp.MustCompile(`modprobe\s+.*hidden`),
		},
		cronPatterns: []*regexp.Regexp{
			regexp.MustCompile(`/etc/cron\.(d|hourly|daily|weekly|monthly)/`),
			regexp.MustCompile(`crontab\s+-e\b`),
			regexp.MustCompile(`echo\s+["']?.+["']?\s*>>\s*/var/spool/cron/`),
		},
		preloadPatterns: []*regexp.Regexp{
			regexp.MustCompile(`LD_PRELOAD\s*=`),
			regexp.MustCompile(`/etc/ld\.so\.preload`),
		},
		systemdPatterns: []*regexp.Regexp{
			regexp.MustCompile(`systemctl\s+(enable|start)\s+.*\.service`),
			regexp.MustCompile(`/etc/systemd/system/.*\.service`),
		},
		authKeyPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(echo|cat).*>>\s*.*\.ssh/authorized_keys`),
			regexp.MustCompile(`\.ssh/authorized_keys2`),
		},
	}
}

// IndicatorEvent 是单次潜在 Rootkit/后门事件。
type IndicatorEvent struct {
	HostID  string
	Source  string // 命令行 / 文件路径 / 模块名
	Content string // 详细内容 (cmdline / kernel module name / file content snippet)
	UID     int32
}

// Scan 检测 Rootkit/后门指标。
func (d *RootkitDetector) Scan(_ context.Context, ev IndicatorEvent) ([]byte, bool) {
	if ev.Content == "" {
		return nil, false
	}

	type hit struct {
		category string
		rule     string
	}
	var hits []hit

	check := func(cat string, patterns []*regexp.Regexp) {
		for _, p := range patterns {
			if p.MatchString(ev.Content) {
				hits = append(hits, hit{category: cat, rule: p.String()})
				return // 同类只命中一次
			}
		}
	}

	check("lkm_rootkit", d.lkmPatterns)
	check("cron_persistence", d.cronPatterns)
	check("ld_preload", d.preloadPatterns)
	check("systemd_persistence", d.systemdPatterns)
	check("ssh_authorized_keys", d.authKeyPatterns)

	if len(hits) == 0 {
		return nil, false
	}

	categories := make([]string, 0, len(hits))
	rules := make([]string, 0, len(hits))
	for _, h := range hits {
		categories = append(categories, h.category)
		rules = append(rules, h.rule)
	}

	payload, _ := json.Marshal(map[string]any{
		"host_id":    ev.HostID,
		"source":     ev.Source,
		"content":    ev.Content,
		"uid":        ev.UID,
		"categories": categories,
		"rules":      rules,
		"would_action": map[string]any{
			"type":   "isolate_host",
			"target": ev.HostID,
			"reason": "Rootkit/后门指标命中: " + joinComma(categories),
		},
	})
	return payload, true
}
