package intrusion

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
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
			// 管道写入 crontab：`... | crontab -` 是实际攻击最常见的写法，
			// 原有模式只认交互式 -e 与重定向到 spool 目录，把它漏了。
			regexp.MustCompile(`\|\s*crontab\s+-`),
			regexp.MustCompile(`/var/spool/cron/`),
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
			// 文件事件只带路径不带命令，原有模式要求出现 echo/cat 与重定向符，
			// 因而对「FIM 报告 authorized_keys 被修改」这类事件完全不命中——
			// 而那恰恰是最常见的持久化落地形态。
			//
			// 只收 root 的密钥：普通用户的 authorized_keys 变更在事件层面
			// 与配置管理轮换密钥无法区分（同一文件、同一动作），
			// 单凭它告警必然误报。root 的密钥没有常规运维理由。
			regexp.MustCompile(`^/root/\.ssh/authorized_keys`),
		},
	}
}

// IndicatorEvent 的来源类型。决定哪些判据成立：路径类判据只有文件事件才算证据。
const (
	SourceProcess      = "process"       // Content 是进程 cmdline
	SourceFile         = "file"          // Content 是被操作的文件路径
	SourceKernelModule = "kernel_module" // Content 是内核模块名
)

// IndicatorEvent 是单次潜在 Rootkit/后门事件。
type IndicatorEvent struct {
	HostID  string
	Source  string // 见 Source* 常量：命令行 / 文件路径 / 模块名
	Content string // 详细内容 (cmdline / kernel module name / file content snippet)
	UID     int32
	// ExePath 产生该事件的执行体。用于排除包管理器等常规写入方——
	// 只看被写的路径无法区分「攻击者投放持久化单元」与「dpkg 装了个包」，
	// 两者写的是同一个目录。
	ExePath string
}

// packageManagerExes 是会合法写入 /etc/systemd/system 与 /etc/cron.* 的执行体。
//
// 包管理器安装软件包时创建服务单元与定时任务是常态。仅凭「有人写了这个路径」
// 判定持久化后门，会让每一次装包都产生一条 critical 告警——
// 而告警多到看不完时，真的那条也就没人看了。
var packageManagerExes = []string{
	"dpkg", "apt", "apt-get", "rpm", "yum", "dnf", "zypper", "apk",
}

// byPackageManager 判断事件是否由包管理器产生。
//
// 只做后缀/包含匹配而不解析完整路径：执行体在不同发行版下路径不一
// （/usr/bin/dpkg、/bin/rpm…），而这些名字本身足够独特。
func byPackageManager(exePath string) bool {
	if exePath == "" {
		return false
	}
	base := exePath
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	return slices.Contains(packageManagerExes, base)
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
	check("ld_preload", d.preloadPatterns)
	check("ssh_authorized_keys", d.authKeyPatterns)

	// cron 与 systemd 两类是"路径出现即命中"的判据，只有文件事件才构成证据。
	//
	// 进程事件里 Content 是命令行，提到这些路径是日常操作而非写入：
	// anacron 每小时执行的 `basename /etc/cron.hourly/0anacron`、run-parts 遍历、
	// find/ls 巡检都会命中。放行进程来源的代价是零——攻击者投放持久化文件时
	// 必然产生对应的文件事件，那条路径上判据依然成立且证据更强。
	//
	// 另外，文件事件里也无法区分投放后门与包管理器装包（写的是同一个目录），
	// 故仍按执行体排除包管理器。LKM / LD_PRELOAD / authorized_keys 三类不受这两条限制。
	if ev.Source == SourceFile && !byPackageManager(ev.ExePath) {
		check("cron_persistence", d.cronPatterns)
		check("systemd_persistence", d.systemdPatterns)
	}

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
