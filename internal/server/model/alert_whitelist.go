// Package model 提供数据库模型定义
package model

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// AlertWhitelist 告警白名单模型
// 匹配规则：各字段为空或"*"表示匹配所有，非空则精确匹配。
// SourceIPCIDR 是非告警维度的扩展字段，用于 ScanDetector 等需要按
// 源 IP 段豁免的检测器（如 k8s/GKE node pool 健康探测）。
// Exe/Cmdline 维度供 CEL/EDR 告警路径按进程/命令行豁免（P2-B 自动调优采纳的 exception）。
type AlertWhitelist struct {
	TenantID     string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name         string `gorm:"column:name;type:varchar(100);not null" json:"name"`           // 白名单描述名称
	RuleID       string `gorm:"column:rule_id;type:varchar(64)" json:"rule_id"`               // 空或*表示匹配所有规则
	HostID       string `gorm:"column:host_id;type:varchar(64)" json:"host_id"`               // 空或*表示匹配所有主机
	Category     string `gorm:"column:category;type:varchar(50)" json:"category"`             // 空或*表示匹配所有类别
	Severity     string `gorm:"column:severity;type:varchar(20)" json:"severity"`             // 空或*表示匹配所有级别
	Exe          string `gorm:"column:exe;type:varchar(255)" json:"exe"`                      // 进程完整路径（精确匹配）；空表示不约束。历史条目里的 basename 仍按 basename 匹配
	Cmdline      string `gorm:"column:cmdline;type:varchar(500)" json:"cmdline"`              // 命令行子串，空表示不约束；CEL 路径按 cmdline 包含匹配
	SourceIPCIDR string `gorm:"column:source_ip_cidr;type:varchar(64)" json:"source_ip_cidr"` // 源 IP CIDR（如 10.0.0.0/24），供 ScanDetector 等使用
	Reason       string `gorm:"column:reason;type:text" json:"reason"`                        // 加入白名单的原因
	// ExpiresAt 到期后自动失效。豁免会过时——环境变了、进程换了，当初的判断不再成立——
	// 所以每条都有期限，到期前在「即将到期」列表里复查。为空表示历史数据，迁移时补齐。
	ExpiresAt *LocalTime `gorm:"column:expires_at;type:timestamp;null;index" json:"expires_at"`
	// Enabled 停用后不再匹配，但保留记录与它压下过的命中，便于追溯。
	Enabled   bool      `gorm:"column:enabled;not null;default:true" json:"enabled"`
	CreatedBy string    `gorm:"column:created_by;type:varchar(100)" json:"created_by"` // 创建人
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (AlertWhitelist) TableName() string {
	return "alert_whitelists"
}

// Matches 判断白名单条目是否匹配告警
func (w *AlertWhitelist) Matches(ruleID, hostID, category, severity string) bool {
	if !matchField(w.RuleID, ruleID) {
		return false
	}
	if !matchField(w.HostID, hostID) {
		return false
	}
	if !matchField(w.Category, category) {
		return false
	}
	if !matchField(w.Severity, severity) {
		return false
	}
	return true
}

// matchField 判断白名单字段是否匹配目标值（空或"*"匹配所有）
func matchField(whitelistVal, targetVal string) bool {
	if whitelistVal == "" || whitelistVal == "*" {
		return true
	}
	return whitelistVal == targetVal
}

// MatchesAlert 在 CEL/EDR 告警路径判断白名单是否命中（在 Matches 基础上增加 exe/cmdline 维度）。
//
// fields 为告警事件字段（exe/comm/cmdline 等）。匹配语义：
//   - rule/host/category/severity 沿用 matchField（空或"*"匹配所有）。
//   - exe：按 basename 匹配 fields["exe"]（兼容 agent 的 comm）。
//   - cmdline：按子串包含匹配 fields["cmdline"]（大小写不敏感）。
//
// 安全约束：必须至少有 host/exe/cmdline 之一为具体值，否则视为不命中。
// 防止仅按 rule/category 的宽泛条目把整类告警全部抑制（错抑制风险高于漏抑制）。
func (w *AlertWhitelist) MatchesAlert(ruleID, hostID, category, severity string, fields map[string]string) bool {
	if !w.HasConcreteNarrowing() {
		return false
	}
	if !w.Matches(ruleID, hostID, category, severity) {
		return false
	}
	if !matchExe(w.Exe, fields) {
		return false
	}
	if !matchCmdlineContains(w.Cmdline, fields["cmdline"]) {
		return false
	}
	return true
}

// Active 判断条目此刻是否生效：已启用且未过期。
func (w *AlertWhitelist) Active(now time.Time) bool {
	if !w.Enabled {
		return false
	}
	return w.ExpiresAt == nil || time.Time(*w.ExpiresAt).After(now)
}

// HasEvidenceCondition 判断条目是否约束了具体证据（进程 / 命令行 / 来源网段）。
//
// 只写「规则 + 主机」的豁免等于让这台主机上这条规则整体失明。对 critical 规则
// 不允许这样做：必须说清是哪个进程、哪条命令、哪个来源，证据之外的命中照常告警。
func (w *AlertWhitelist) HasEvidenceCondition() bool {
	return isConcrete(w.Exe) || isConcrete(w.Cmdline) || isConcrete(w.SourceIPCIDR)
}

// HasConcreteNarrowing 判断条目是否至少约束了 host/exe/cmdline 之一（防全通配误抑制）。
// 导出供 API 层在创建/更新时前置校验：不满足的条目存进去也永远不会命中，
// 与其让用户建出一条静默失效的白名单，不如在接口上直接拒绝。
func (w *AlertWhitelist) HasConcreteNarrowing() bool {
	return isConcrete(w.HostID) || isConcrete(w.Exe) || isConcrete(w.Cmdline)
}

func isConcrete(v string) bool {
	return v != "" && v != "*"
}

// matchExe 匹配 exe（空白名单值=不约束；兼容 fields["comm"]）。
//
// 白名单写的是完整路径时按路径精确匹配：只按程序名豁免的话，攻击者把自己的程序
// 改成同名放到任意目录就能借用这条豁免。只写了程序名的是历史条目，仍按 basename
// 匹配，等逐条复核后收窄；新条目保存时已不允许只写程序名（见 ScopeProblem）。
func matchExe(wlExe string, fields map[string]string) bool {
	if !isConcrete(wlExe) {
		return true
	}
	exe := fields["exe"]
	if exe == "" {
		exe = fields["comm"]
	}
	if exe == "" {
		return false
	}
	if ExeIsPath(wlExe) {
		return exe == wlExe
	}
	return strings.EqualFold(filepath.Base(exe), filepath.Base(wlExe))
}

// ExeIsPath 判断白名单的 exe 是否写成了绝对路径。
func ExeIsPath(exe string) bool {
	return strings.HasPrefix(exe, "/")
}

// ScopeProblem 检查条目的豁免范围是否足够窄，返回不通过的原因；为空表示通过。
//
// 豁免是在检测上开的口子，口子要窄到只覆盖确认过的那个正常来源：
//   - 进程必须写完整路径，不接受只写程序名（同名程序放到任意目录就能借用）；
//   - 对全部主机生效的条目必须指定规则，并写进程完整路径，可再加命令行。只写命令行不够：
//     命令行完全由执行者决定，攻击者在自己的命令里带上同一段字符串就能借用；
//   - 按进程或命令行豁免必须指定规则；
//   - 只按来源网段的条目只供扫描探测类检测使用，照旧允许。
//
// 业界通行的做法是例外至少写两个进程维度（例如程序加父进程）。父进程链、镜像、
// 哈希要等传感器补上这些字段后才能用，目前可用的最强维度是完整路径。
func (w *AlertWhitelist) ScopeProblem() string {
	if isConcrete(w.Exe) && !ExeIsPath(w.Exe) {
		return "进程请填写完整路径（例如 /usr/bin/dnf），只写程序名可被同名程序借用"
	}
	if isConcrete(w.SourceIPCIDR) && !isConcrete(w.Exe) && !isConcrete(w.Cmdline) && !isConcrete(w.HostID) {
		return ""
	}
	if !isConcrete(w.RuleID) && (isConcrete(w.Exe) || isConcrete(w.Cmdline)) {
		return "按进程或命令行豁免时必须指定规则：对所有规则豁免一个进程，等于让所有针对它的检测失效"
	}
	if isConcrete(w.HostID) {
		return ""
	}
	if !isConcrete(w.RuleID) {
		return "对全部主机生效的豁免必须指定规则，不能对所有规则一起豁免"
	}
	if !isConcrete(w.Exe) {
		return "对全部主机生效的豁免必须写进程完整路径（可再加命令行）；只写命令行可被攻击者在自己的命令里带上同一段字符串借用"
	}
	return ""
}

// exeLiteral 匹配规则表达式里对 exe / comm 的字面量判断，例如 exe.contains("bash")、comm == "nc"。
var exeLiteral = regexp.MustCompile(`\b(?:exe|comm)\s*(?:\.\s*(?:contains|endsWith|startsWith|matches)\s*\(\s*|==\s*)"([^"]+)"`)

// ConflictsWithRule 判断这条豁免的进程是否正是规则表达式里要求的那个进程。
//
// 规则写着「进程是 bash 且命令行清日志」，豁免又写「进程是 bash」——这条豁免就把
// 规则的成立条件整个抵消了，等于停用规则，而且停用得没人看得见。这种豁免一律不生效。
// 只看进程维度：命令行豁免与规则条件的关系判断不了，交给语料回放兜底。
func (w *AlertWhitelist) ConflictsWithRule(expression string) bool {
	if !isConcrete(w.Exe) || isConcrete(w.Cmdline) || isConcrete(w.HostID) {
		return false
	}
	base := strings.ToLower(filepath.Base(w.Exe))
	for _, loc := range exeLiteral.FindAllStringSubmatchIndex(expression, -1) {
		// 取反的判断（!exe.contains("x")、!(… || exe.contains("x"))）是规则自己排除的进程，豁免它不冲突。
		if negatedAt(expression, loc[0]) {
			continue
		}
		lit := strings.ToLower(filepath.Base(strings.TrimSpace(expression[loc[2]:loc[3]])))
		if sameProgram(base, lit) {
			return true
		}
	}
	return false
}

// sameProgram 判断豁免的程序是不是规则点名的那个程序。
//
// 按词边界比较：程序名等于字面量，或以字面量开头、后面紧跟版本号（数字、点、横线）。
// 解释器的真实路径常带版本号（python3 -> python3.9），只认完全相等会放过「豁免 python3.9
// 等于停用 python 反弹 shell 检测」；而规则写 exe.contains("ss") 时，豁免
// sssd 只是排除一个被误命中的程序，规则对真正的 ss 照常有效，不算冲突。
func sameProgram(base, lit string) bool {
	if lit == "" || !strings.HasPrefix(base, lit) {
		return false
	}
	rest := base[len(lit):]
	return rest == "" || strings.ContainsRune("0123456789.-", rune(rest[0]))
}

// negatedAt 判断表达式 pos 处的判断是否处在取反之下：紧挨着的 !，或包在 !( … ) 里。
// 取反层数为奇数才算取反。引号里的括号不计。
func negatedAt(expr string, pos int) bool {
	var groups []bool // 每层括号是否由 ! 打开
	inQuote := false
	for i := 0; i < pos; i++ {
		c := expr[i]
		switch {
		case c == '\\' && inQuote:
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			groups = append(groups, endsWithBang(expr[:i]))
		case c == ')':
			if len(groups) > 0 {
				groups = groups[:len(groups)-1]
			}
		}
	}
	neg := endsWithBang(expr[:pos])
	for _, g := range groups {
		if g {
			neg = !neg
		}
	}
	return neg
}

func endsWithBang(prefix string) bool {
	return strings.HasSuffix(strings.TrimRight(prefix, " \t"), "!")
}

// matchCmdlineContains 按子串包含匹配 cmdline（空白名单值=不约束；大小写不敏感）。
func matchCmdlineContains(wlCmdline, cmdline string) bool {
	if !isConcrete(wlCmdline) {
		return true
	}
	if cmdline == "" {
		return false
	}
	return strings.Contains(strings.ToLower(cmdline), strings.ToLower(wlCmdline))
}
