package celengine

import (
	"net"
	"path/filepath"
	"strings"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// alertWhitelistRule 描述一条告警白名单规则。
//
// 告警生成前调用 IsWhitelisted 判断；命中即抑制（不入 alerts 表、不入 storyline、不通知）。
// 设计目标：纯函数 + 零依赖，不查 DB / 不调外部服务，<1us 决策。
//
// 当前内置规则全部是 prod 实测高频误报模式（2026-05-28 prod 巡检）：
//   - nginx/httpd/envoy 等反代进程命中网络类规则
//   - 业务进程访问 RFC1918 内网命中 C2/cryptominer 端口规则
//
// 后续需要 hot reload / yaml 配置 / per-tenant 自定义时再演进。
type alertWhitelistRule struct {
	// RuleNamePattern 规则 name 子串匹配（空串 = 所有规则）。
	RuleNamePattern string

	// RuleCategoryPattern 规则 category 子串匹配（空串 = 所有 category）。
	RuleCategoryPattern string

	// ExeBasenameIn 进程 basename 命中即抑制（如 nginx / httpd）。
	ExeBasenameIn []string

	// DstIPInPrivate 目的 IP 在 RFC1918 / 回环 / 链路本地范围内即抑制。
	DstIPInPrivate bool

	// Reason 触发该规则时记录的原因（用于审计 + log）。
	Reason string
}

// defaultAlertWhitelist 内置白名单规则集（prod 实测误报模式）。
//
// 维护原则：只放"高置信度业务模式"，宁可漏抑制也不要错抑制（漏抑制只是告警多，
// 错抑制可能错过真攻击）。
//
// 匹配策略说明：
//   - **优先按 RuleCategoryPattern 匹配**（agent yaml 与 server DetectionRule
//     的 name 字段有时不一致：yaml `name: c2_high_risk_port`，server 端 DB
//     name 可能是中文显示名如"高危端口外连"，但 category 相对稳定）。
//   - RuleNamePattern 作为兜底/精确匹配补充，子串匹配兼容中英文混排。
//
// 当前覆盖 prod 高频误报：
//   - c2_communication 类全部规则（高危端口/Cobalt Strike 端口/Tor/IRC 等）
//   - 反代进程 / 内网 IP
//   - cryptomining 类 + 内网 IP
var defaultAlertWhitelist = []alertWhitelistRule{
	{
		// 任意 C2 通信类规则 + 反代进程：99% 是 backend 上游连接
		RuleCategoryPattern: "c2_communication",
		ExeBasenameIn:       []string{"nginx", "httpd", "apache2", "envoy", "haproxy", "caddy", "traefik", "kube-proxy", "kubelet"},
		Reason:              "reverse_proxy_upstream",
	},
	{
		// 任意 C2 通信类规则 + 内网 IP：跨节点业务通信
		RuleCategoryPattern: "c2_communication",
		DstIPInPrivate:      true,
		Reason:              "internal_network_connection",
	},
	{
		// 矿池/cryptomining 类 + 内网 IP：业务用 3333/7777/9999 等端口很常见
		RuleCategoryPattern: "cryptomining",
		DstIPInPrivate:      true,
		Reason:              "internal_network_connection",
	},
	{
		// impact 类（含 cryptominer impact tactic）+ 内网 IP
		RuleCategoryPattern: "impact",
		DstIPInPrivate:      true,
		Reason:              "internal_network_connection",
	},
	// 兼容 agent yaml 原始 rule name 匹配（如果 server 端直接透传）
	{
		RuleNamePattern: "c2_high_risk_port",
		ExeBasenameIn:   []string{"nginx", "httpd", "apache2", "envoy", "haproxy", "caddy", "traefik"},
		Reason:          "reverse_proxy_upstream",
	},
	{
		RuleNamePattern: "c2_high_risk_port",
		DstIPInPrivate:  true,
		Reason:          "internal_network_connection",
	},
	{
		RuleNamePattern: "cryptominer_pool_port",
		DstIPInPrivate:  true,
		Reason:          "internal_network_connection",
	},
	{
		RuleNamePattern: "c2_irc_connect",
		DstIPInPrivate:  true,
		Reason:          "internal_network_connection",
	},
}

// privateCIDRs 是 RFC1918 + 回环 + 链路本地网段列表。
var privateCIDRs = mustParseCIDRs([]string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"fc00::/7",
	"::1/128",
	"fe80::/10",
})

func mustParseCIDRs(s []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(s))
	for _, c := range s {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func ipIsPrivate(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	for _, n := range privateCIDRs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// exeBasenameMatch 检查 exe 路径的 basename 是否在 list 中（大小写不敏感）。
func exeBasenameMatch(exe string, list []string) bool {
	if exe == "" || len(list) == 0 {
		return false
	}
	base := strings.ToLower(filepath.Base(exe))
	for _, e := range list {
		if strings.ToLower(e) == base {
			return true
		}
	}
	return false
}

// IsAlertWhitelisted 判断给定告警是否命中白名单。
//
// 返回 (whitelisted, reason)。reason 用于审计日志。
//
// 规则匹配语义：
//   - RuleNamePattern 必须命中（子串匹配规则 name 或 result_id）。
//   - RuleCategoryPattern（如填）必须命中规则 category。
//   - ExeBasenameIn + DstIPInPrivate 是 OR 关系：任一命中即抑制。
//   - 同一白名单条只有 ExeBasenameIn 或只有 DstIPInPrivate 时即只需该项命中。
func IsAlertWhitelisted(rule *model.DetectionRule, fields map[string]string) (bool, string) {
	if rule == nil {
		return false, ""
	}
	// 兼容字段名差异：
	//   - server CEL 引擎填充 fields 时常用 exe
	//   - agent ebpf 上报 EDR 事件用 comm（短进程名，如 "nginx"）
	//   - dst_ip 与 remote_addr 同义（agent 用 remote_addr）
	exe := fields["exe"]
	if exe == "" {
		exe = fields["comm"]
	}
	dstIP := fields["dst_ip"]
	if dstIP == "" {
		dstIP = fields["remote_addr"]
	}

	for _, w := range defaultAlertWhitelist {
		if w.RuleNamePattern != "" && !strings.Contains(rule.Name, w.RuleNamePattern) {
			continue
		}
		if w.RuleCategoryPattern != "" && !strings.Contains(rule.Category, w.RuleCategoryPattern) {
			continue
		}

		// 至少一个具体条件命中才抑制（防止"只匹配规则名就抑制"误抑制）
		matched := false
		if len(w.ExeBasenameIn) > 0 && exeBasenameMatch(exe, w.ExeBasenameIn) {
			matched = true
		}
		if w.DstIPInPrivate && ipIsPrivate(dstIP) {
			matched = true
		}
		if matched {
			return true, w.Reason
		}
	}
	return false, ""
}
