package celengine

import "strings"

// techniqueTactic 把 ATT&CK 技术 ID(T####)映射到其主战术 ID(TA####)。
//
// 用途：告警落库时回填 alerts.attck_tactic,供杀伤链视图 / incident 关联按战术排序
// (incident_correlation 的 attckTacticOrder 也用 TA-id) / ATT&CK 覆盖热图。
//
// 一个技术可归多个战术,这里取「安全研判最相关的主战术」。仅覆盖 prod 规则实际使用的技术
// (detection_rules / sequence_rules 的 mitre_id + IOC/端口扫描内置技术),新增技术在此补条目即可。
// 战术 ID 对照:
//
//	TA0001 初始访问  TA0002 执行      TA0003 持久化    TA0004 提权
//	TA0005 防御规避  TA0006 凭据访问  TA0007 发现      TA0008 横向移动
//	TA0009 收集      TA0010 数据渗出  TA0011 C2 通信   TA0040 影响
var techniqueTactic = map[string]string{
	"T1003": "TA0006", // OS Credential Dumping
	"T1005": "TA0009", // Data from Local System
	"T1014": "TA0005", // Rootkit
	"T1016": "TA0007", // System Network Config Discovery
	"T1018": "TA0007", // Remote System Discovery
	"T1021": "TA0008", // Remote Services
	"T1027": "TA0005", // Obfuscated Files or Information
	"T1033": "TA0007", // System Owner/User Discovery
	"T1036": "TA0005", // Masquerading
	"T1037": "TA0003", // Boot or Logon Init Scripts
	"T1040": "TA0006", // Network Sniffing
	"T1041": "TA0010", // Exfiltration Over C2 Channel
	"T1046": "TA0007", // Network Service Discovery
	"T1047": "TA0002", // Windows Management Instrumentation
	"T1048": "TA0010", // Exfiltration Over Alternative Protocol
	"T1053": "TA0003", // Scheduled Task/Job
	"T1055": "TA0005", // Process Injection
	"T1056": "TA0006", // Input Capture
	"T1057": "TA0007", // Process Discovery
	"T1059": "TA0002", // Command and Scripting Interpreter
	"T1068": "TA0004", // Exploitation for Privilege Escalation
	"T1070": "TA0005", // Indicator Removal
	"T1071": "TA0011", // Application Layer Protocol
	"T1078": "TA0005", // Valid Accounts
	"T1082": "TA0007", // System Information Discovery
	"T1083": "TA0007", // File and Directory Discovery
	"T1087": "TA0007", // Account Discovery
	"T1090": "TA0011", // Proxy
	"T1095": "TA0011", // Non-Application Layer Protocol
	"T1098": "TA0003", // Account Manipulation
	"T1105": "TA0011", // Ingress Tool Transfer
	"T1110": "TA0006", // Brute Force
	"T1113": "TA0009", // Screen Capture
	"T1115": "TA0009", // Clipboard Data
	"T1123": "TA0009", // Audio Capture
	"T1133": "TA0001", // External Remote Services
	"T1135": "TA0007", // Network Share Discovery
	"T1136": "TA0003", // Create Account
	"T1140": "TA0005", // Deobfuscate/Decode Files or Information
	"T1190": "TA0001", // Exploit Public-Facing Application
	"T1202": "TA0005", // Indirect Command Execution
	"T1204": "TA0002", // User Execution
	"T1218": "TA0005", // System Binary Proxy Execution
	"T1222": "TA0005", // File and Directory Permissions Modification
	"T1482": "TA0007", // Domain Trust Discovery
	"T1485": "TA0040", // Data Destruction
	"T1486": "TA0040", // Data Encrypted for Impact
	"T1490": "TA0040", // Inhibit System Recovery
	"T1496": "TA0040", // Resource Hijacking
	"T1499": "TA0040", // Endpoint Denial of Service
	"T1505": "TA0003", // Server Software Component
	"T1542": "TA0003", // Pre-OS Boot
	"T1543": "TA0003", // Create or Modify System Process
	"T1546": "TA0003", // Event Triggered Execution
	"T1547": "TA0003", // Boot or Logon Autostart Execution
	"T1548": "TA0004", // Abuse Elevation Control Mechanism
	"T1552": "TA0006", // Unsecured Credentials
	"T1555": "TA0006", // Credentials from Password Stores
	"T1556": "TA0006", // Modify Authentication Process
	"T1558": "TA0006", // Steal or Forge Kerberos Tickets
	"T1560": "TA0009", // Archive Collected Data
	"T1561": "TA0040", // Disk Wipe
	"T1562": "TA0005", // Impair Defenses
	"T1564": "TA0005", // Hide Artifacts
	"T1565": "TA0040", // Data Manipulation
	"T1567": "TA0010", // Exfiltration Over Web Service
	"T1571": "TA0011", // Non-Standard Port
	"T1572": "TA0011", // Protocol Tunneling
	"T1573": "TA0011", // Encrypted Channel
	"T1574": "TA0003", // Hijack Execution Flow
	"T1609": "TA0002", // Container Administration Command
	"T1610": "TA0002", // Deploy Container
	"T1611": "TA0004", // Escape to Host
	"T1613": "TA0007", // Container and Resource Discovery
	"T1614": "TA0007", // System Location Discovery
	"T1620": "TA0005", // Reflective Code Loading
}

// tacticFromTechnique 由技术 ID 返回主战术 ID(TA####)。
//
// 子技术(T1059.004)按 base 技术(T1059)查表;多技术逗号分隔时取首个;未知或空返回 ""
// (不硬塞,让 attck_tactic 保持空而非填错战术,溯源宁缺勿错)。
func tacticFromTechnique(mitreID string) string {
	if mitreID == "" {
		return ""
	}
	// 取首个(rule 可能逗号分隔多技术)
	if i := strings.IndexByte(mitreID, ','); i >= 0 {
		mitreID = mitreID[:i]
	}
	mitreID = strings.TrimSpace(mitreID)
	// 子技术 → base
	if i := strings.IndexByte(mitreID, '.'); i >= 0 {
		mitreID = mitreID[:i]
	}
	return techniqueTactic[mitreID]
}
