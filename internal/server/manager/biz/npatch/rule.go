// Package npatch 是 mxsec 的虚拟补丁规则模型 (对标青藤云幕 NPatch)。
//
// 设计文档: ref/06-漏洞.md §5 + ref/00-总体评估与商业化路线.md §3 C-9
//
// 核心思想: 对于"老旧系统 / 业务依赖强 / 修复空窗期"等无法即时打补丁场景,
// 用网络/进程行为侧的旁路检测+阻断,使漏洞利用失效。
//
// 检测方式 (Agent 端 eBPF + 用户态):
//   - cgroup_skb 钩子: 出/入站流量包模式匹配
//   - tracepoint syscall: 危险参数模式匹配 (CVE-2022-0847 splice 等)
//   - LSM hook: 进程能力/路径/文件描述符检查
//   - 用户态 netfilter NFQUEUE fallback (eBPF 不支持的 kernel)
//
// 本 PR 仅定义服务端规则模型 + 30 条内置 RCE 规则示例 (Log4j/Shellshock/Spring4Shell).
package npatch

import (
	"encoding/json"
	"time"
)

// RuleKind 是 NPatch 规则类型。
type RuleKind string

const (
	KindNetworkPattern RuleKind = "network_pattern" // 网络流量模式
	KindSyscallParam   RuleKind = "syscall_param"   // syscall 参数模式
	KindLSMHook        RuleKind = "lsm_hook"        // LSM 进程/文件检查
)

// EnforceMode 是规则执行模式。
type EnforceMode string

const (
	EnforceMonitor EnforceMode = "monitor" // 仅命中告警, 不阻断
	EnforceBlock   EnforceMode = "block"   // 命中即阻断
)

// Rule 是单条 NPatch 规则。
type Rule struct {
	ID          string                 `json:"id"` // npatch-CVE-2022-22965
	CVE         string                 `json:"cve"`
	CVEName     string                 `json:"cve_name"` // Spring4Shell
	Kind        RuleKind               `json:"kind"`
	Mode        EnforceMode            `json:"mode"`
	Pattern     map[string]interface{} `json:"pattern"` // kind-specific 匹配规则
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	CreatedAt   time.Time              `json:"created_at"`
}

// MarshalPattern 把 pattern 转 JSON (落库前)。
func (r *Rule) MarshalPattern() ([]byte, error) {
	return json.Marshal(r.Pattern)
}

// BuiltinRules 返回内置 30 条 RCE 类 NPatch 规则。
//
// 覆盖近 3 年高危 RCE: Log4j / Spring4Shell / Shellshock /
// CVE-2022-0847 (DirtyPipe) / CVE-2021-3156 (Sudoedit) /
// PolKit pwnkit / CVE-2024-27198 (TeamCity) 等。
func BuiltinRules() []Rule {
	now := time.Now()
	return []Rule{
		{
			ID: "npatch-CVE-2021-44228", CVE: "CVE-2021-44228", CVEName: "Log4j RCE",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"regex":     `\$\{jndi:(ldap|rmi|dns)://`,
				"protocols": []string{"http", "https"},
			},
			Description: "Log4j JNDI lookup ${jndi:ldap://} 阻断",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2022-22965", CVE: "CVE-2022-22965", CVEName: "Spring4Shell",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"regex":     `class\.module\.classLoader|class\[module\]\[classLoader\]`,
			},
			Description: "Spring Framework ClassLoader 绑定参数攻击",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2014-6271", CVE: "CVE-2014-6271", CVEName: "Shellshock",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"regex":     `\(\)\s*\{\s*:;\s*\}\s*;`,
				"headers":   []string{"User-Agent", "Cookie", "Referer", "X-*"},
			},
			Description: "Bash Shellshock 环境变量函数定义",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2022-0847", CVE: "CVE-2022-0847", CVEName: "DirtyPipe",
			Kind: KindSyscallParam, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"syscall":  "splice",
				"target":   "/etc/passwd",
				"min_size": 0,
			},
			Description: "DirtyPipe 通过 splice 写入只读文件 (/etc/passwd 等)",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2021-3156", CVE: "CVE-2021-3156", CVEName: "Sudoedit",
			Kind: KindSyscallParam, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"binary":  "sudoedit",
				"argv_re": `\\\\$`,
			},
			Description: "Sudoedit 反斜杠堆溢出提权",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2021-4034", CVE: "CVE-2021-4034", CVEName: "PwnKit",
			Kind: KindLSMHook, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"binary":        "pkexec",
				"argc":          0,
				"non_priv_user": true,
			},
			Description: "PolKit pkexec 无参数调用提权",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2024-3094", CVE: "CVE-2024-3094", CVEName: "xz-utils backdoor",
			Kind: KindNetworkPattern, Mode: EnforceMonitor, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction":  "inbound",
				"sshd":       true,
				"version_re": `^OpenSSH_(8\.[56789]|9\.[01234567])`,
			},
			Description: "xz-utils 5.6.0/5.6.1 SSH 后门",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2017-5638", CVE: "CVE-2017-5638", CVEName: "Apache Struts2 S2-045",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"regex":     `Content-Type:.*%\{\(#_='multipart`,
				"headers":   []string{"Content-Type"},
			},
			Description: "Struts2 Jakarta Multipart Parser OGNL 注入",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2017-9805", CVE: "CVE-2017-9805", CVEName: "Apache Struts2 S2-052",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction":    "inbound",
				"regex":        `<map>.*<entry>.*ProcessBuilder.*</entry>.*</map>`,
				"content_type": "application/xml",
			},
			Description: "Struts2 REST XStream 反序列化 RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2017-12149", CVE: "CVE-2017-12149", CVEName: "JBoss EAP/AS 6.x",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/invoker/(readonly|JMXInvokerServlet)`,
				"method":    "POST",
			},
			Description: "JBoss invoker servlet 反序列化",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2020-14882", CVE: "CVE-2020-14882", CVEName: "WebLogic Console RCE",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/console/css/%252e%252e%252f|/console/images/%252e%252e%252f`,
			},
			Description: "Oracle WebLogic 控制台路径穿越 RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2019-2725", CVE: "CVE-2019-2725", CVEName: "WebLogic XMLDecoder",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/_async/AsyncResponseService|/wls-wsat/CoordinatorPortType`,
				"regex":     `<java><object class="java\.lang\.ProcessBuilder">`,
			},
			Description: "WebLogic wls-async/wls-wsat XMLDecoder 反序列化",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2022-26134", CVE: "CVE-2022-26134", CVEName: "Confluence OGNL",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `\$\{.*new javax\.script\.|\$\{Runtime`,
			},
			Description: "Confluence OGNL 注入 RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2023-22515", CVE: "CVE-2023-22515", CVEName: "Confluence Broken Access",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/server-info\.action\?bootstrapStatusProvider`,
				"method":    "POST",
			},
			Description: "Confluence setup wizard 未授权创建 admin",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2021-22205", CVE: "CVE-2021-22205", CVEName: "GitLab ExifTool RCE",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction":  "inbound",
				"path_re":    `/uploads/user|/api/v\d+/users.*\.(jpg|png)`,
				"content_re": `(?i)DjVu|FORM|ANTa`,
				"method":     "POST",
			},
			Description: "GitLab DjVu 解析 ExifTool RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-ThinkPHP-RCE", CVE: "CVE-2018-20062", CVEName: "ThinkPHP 5.x RCE",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "high",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `index\.php\?s=/Index/\\think.*invokefunction`,
			},
			Description: "ThinkPHP 5.0.x/5.1.x 调用 think.app/invokefunction RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2024-23897", CVE: "CVE-2024-23897", CVEName: "Jenkins CLI Arbitrary Read",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/cli\?remoting=false`,
				"method":    "POST",
				"regex":     `@/.*`,
			},
			Description: "Jenkins CLI args4j @file 任意文件读 (Args4J 解析器)",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2023-46604", CVE: "CVE-2023-46604", CVEName: "ActiveMQ OpenWire RCE",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"dst_port":  61616,
				"regex":     `org\.springframework\.context\.support\.ClassPathXmlApplicationContext`,
			},
			Description: "ActiveMQ OpenWire 协议反序列化 RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2024-27198", CVE: "CVE-2024-27198", CVEName: "TeamCity Auth Bypass",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/app/rest/users/.*\?something=jsp/.*`,
			},
			Description: "TeamCity 重定向认证绕过 → 创建 admin 账号 RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2023-50164", CVE: "CVE-2023-50164", CVEName: "Struts2 S2-066 Upload Path Traversal",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"regex":     `[Uu]pload[Ff]ile[Nn]ame=\\.\\.|filename=.*\.\./`,
				"method":    "POST",
			},
			Description: "Apache Struts2 文件上传路径穿越 RCE",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2022-30190", CVE: "CVE-2022-30190", CVEName: "Microsoft Follina MSDT",
			Kind: KindNetworkPattern, Mode: EnforceMonitor, Severity: "high",
			Pattern: map[string]interface{}{
				"direction": "outbound",
				"regex":     `ms-msdt:/id PCWDiagnostic.*IT_RebrowseForFile`,
			},
			Description: "MSDT URL 协议利用 (主要 Windows; Linux 跨平台触发监控)",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2022-36804", CVE: "CVE-2022-36804", CVEName: "Bitbucket Command Injection",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/rest/api/.*archive\?at=`,
				"regex":     `--upload-pack|--exec`,
			},
			Description: "Atlassian Bitbucket archive endpoint 命令注入",
			CreatedAt:   now,
		},
		{
			ID: "npatch-Fastjson-RCE", CVE: "CVE-2022-25845", CVEName: "Fastjson AutoType",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"regex":     `"@type":\s*"com\.sun\.rowset\.JdbcRowSetImpl"|"@type":\s*"org\.apache\.commons\.dbcp2\.BasicDataSource"`,
			},
			Description: "Fastjson AutoType 反序列化经典 sink",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2019-17564", CVE: "CVE-2019-17564", CVEName: "Apache Dubbo Hessian",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "high",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"dst_port":  20880,
				"regex":     `\$\$Lambda|org\.springframework\.cglib`,
			},
			Description: "Apache Dubbo Hessian 反序列化",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2021-26084", CVE: "CVE-2021-26084", CVEName: "Confluence Webwork OGNL",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/(pages|users)/.*createpage\.action.*queryString=`,
				"regex":     `\\u0027|\\u0022.*new\\u0020`,
			},
			Description: "Confluence Webwork OGNL 注入",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2023-20887", CVE: "CVE-2023-20887", CVEName: "VMware Aria Operations",
			Kind: KindNetworkPattern, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"path_re":   `/casa/nodes/thumbprints`,
				"method":    "POST",
				"regex":     `<castor:.*runtime`,
			},
			Description: "VMware Aria Operations Networks 命令注入",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2024-1086", CVE: "CVE-2024-1086", CVEName: "Linux nft_double_free LPE",
			Kind: KindSyscallParam, Mode: EnforceMonitor, Severity: "high",
			Pattern: map[string]interface{}{
				"syscall":       "nf_tables",
				"verdict_op":    "NFT_MSG_NEWCHAIN",
				"non_priv_user": true,
			},
			Description: "Linux netfilter nft 双重释放本地提权 (nft 命令异常)",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2023-32233", CVE: "CVE-2023-32233", CVEName: "Linux nftables UAF",
			Kind: KindSyscallParam, Mode: EnforceMonitor, Severity: "high",
			Pattern: map[string]interface{}{
				"syscall":       "setsockopt",
				"level":         "NF_NETLINK",
				"argv_re":       `nft_set_destroy|nft_chain_use`,
				"non_priv_user": true,
			},
			Description: "Linux netfilter nf_tables Use-After-Free 提权",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2024-21626", CVE: "CVE-2024-21626", CVEName: "runc Leaky Vessels",
			Kind: KindLSMHook, Mode: EnforceBlock, Severity: "critical",
			Pattern: map[string]interface{}{
				"binary":            "runc",
				"argv_re":           `WORKDIR.*\/proc\/self\/fd\/[0-9]+`,
				"container_context": true,
			},
			Description: "runc 文件描述符泄露容器逃逸 (Leaky Vessels)",
			CreatedAt:   now,
		},
		{
			ID: "npatch-CVE-2024-21762", CVE: "CVE-2024-21762", CVEName: "FortiOS SSL VPN OOB Write",
			Kind: KindNetworkPattern, Mode: EnforceMonitor, Severity: "critical",
			Pattern: map[string]interface{}{
				"direction": "inbound",
				"dst_port":  443,
				"path_re":   `/remote/`,
				"regex":     `Content-Length:\s*0+[1-9]\d{6,}`,
			},
			Description: "FortiOS SSL VPN 越界写 RCE (异常 Content-Length)",
			CreatedAt:   now,
		},
	}
}
