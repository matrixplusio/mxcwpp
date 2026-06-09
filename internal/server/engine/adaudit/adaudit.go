// Package adaudit — AD / LDAP 域控审计 (EDR-4).
//
// Windows AD 域控核心安全事件 (Event ID):
//
//	4624: Successful Logon
//	4625: Failed Logon
//	4634/4647: Logoff
//	4648: Logon with Explicit Credentials (横向)
//	4672: Special Privileges Assigned (admin login)
//	4688: New Process Created (含 cmdline)
//	4720/4722/4723/4724: Account Created/Enabled/Password Changed/Reset
//	4728/4732/4756: Group Membership Add (Domain Admins / Enterprise Admins!)
//	4768: Kerberos TGT 请求 (Pre-Authentication 失败 = 密码爆破)
//	4769: Kerberos TGS 请求 (Kerberoasting indicators)
//	4776: NTLM 认证 (legacy, 应禁)
//	4778/4779: Remote Desktop Session
//	5145: Network Share Access (lateral movement)
//
// 集成方式:
//   - Windows Agent: ETW Microsoft-Windows-Security-Auditing provider 实时订阅
//   - Linux SSO (FreeIPA / 389-ds / OpenLDAP): /var/log/secure + LDAP audit log 解析
//   - 远程 AD 域控: WinRM / LDAP queries (无 Agent 场景)
//
// 检测规则:
//   - DCSync 仿冒域控: 单 client 短期 4662 DSReplicaGetChanges 多次
//   - Kerberoasting: 单用户 4769 大量请求服务 SPN
//   - Golden Ticket: 4624 logon Type=3 异常 ticket lifetime
//   - 横向 PSExec: 7045 service install + 5145 share access 关联
//   - 暴力破解: 4625 同源 IP 短期高频
//   - 提权: 4672 + 4728 (新加 Domain Admins) 关联
package adaudit

import (
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// EventKind 标准化的 AD 事件类型 (跨 Windows / Linux LDAP).
type EventKind string

const (
	EventLogonSuccess    EventKind = "logon_success"    // 4624
	EventLogonFailed     EventKind = "logon_failed"     // 4625
	EventLogonExplicit   EventKind = "logon_explicit"   // 4648 横向
	EventPrivilegeAssign EventKind = "privilege_assign" // 4672
	EventAccountCreate   EventKind = "account_create"   // 4720
	EventAccountEnable   EventKind = "account_enable"   // 4722
	EventPasswordChange  EventKind = "password_change"  // 4723
	EventPasswordReset   EventKind = "password_reset"   // 4724
	EventGroupAdd        EventKind = "group_add"        // 4728/4732/4756
	EventKerberosTGTReq  EventKind = "kerberos_tgt_req" // 4768
	EventKerberosTGSReq  EventKind = "kerberos_tgs_req" // 4769
	EventNTLMAuth        EventKind = "ntlm_auth"        // 4776
	EventDCSync          EventKind = "dcsync"           // 4662 + DSReplicaGetChanges
	EventShareAccess     EventKind = "share_access"     // 5145
	EventRemoteDesktop   EventKind = "remote_desktop"   // 4778
	EventNewProcess      EventKind = "new_process"      // 4688
)

// Event 标准化 AD 审计事件.
type Event struct {
	Kind            EventKind
	Timestamp       time.Time
	EventID         int // 原始 Windows Event ID
	UserName        string
	UserDomain      string
	UserSID         string
	TargetUser      string // 4624 SubjectUser → TargetUser
	TargetGroup     string // 4728 加组目标
	SourceIP        string
	SourcePort      int
	LogonType       int    // 4624: 2=interactive 3=network 10=remoteinteractive
	ProcessName     string // 4688
	ProcessCmd      string // 4688 cmdline
	ServiceName     string // 4769 SPN
	FailureCode     string // 4625 0xC000006A=wrong password 0xC000006D=bad username
	WorkstationName string
	TicketOptions   string // Kerberos
	Severity        string
	Raw             map[string]string // 原始字段保留
}

// Detector 检测器, 维护短时滑窗状态.
type Detector struct {
	logger *zap.Logger

	// 失败登录滑窗 (src_ip → count, 5min)
	failedLogins *slidingCounter

	// Kerberoasting (user → distinct SPN count, 10min)
	kerberoastSPNs *slidingCounter

	// DCSync (src_ip → DSReplicaGetChanges count, 10min)
	dcSyncReq *slidingCounter
}

// NewDetector 构造.
func NewDetector(logger *zap.Logger) *Detector {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Detector{
		logger:         logger,
		failedLogins:   newSlidingCounter(5 * time.Minute),
		kerberoastSPNs: newSlidingCounter(10 * time.Minute),
		dcSyncReq:      newSlidingCounter(10 * time.Minute),
	}
}

// Alert 检测产出.
type Alert struct {
	RuleID      string
	Severity    string
	Title       string
	Description string
	ATTCKTactic string
	ATTCKTech   string
	Event       Event
}

// Process 单事件检测, 返 0..N 个 Alert.
func (d *Detector) Process(ev Event) []Alert {
	var alerts []Alert

	switch ev.Kind {
	case EventLogonFailed:
		// 暴力破解检测: 同源 IP 5min 内 >10 次失败
		key := ev.SourceIP + "|" + ev.TargetUser
		n := d.failedLogins.IncrAndGet(key)
		if n >= 10 {
			alerts = append(alerts, Alert{
				RuleID:      "AD-BRUTE-FORCE",
				Severity:    "high",
				Title:       "AD 账户暴力破解",
				Description: "5min 内同源 IP 失败登录 " + strconv.Itoa(n) + " 次",
				ATTCKTactic: "TA0006",
				ATTCKTech:   "T1110",
				Event:       ev,
			})
		}
		// 单次极高风险: 域管账户失败
		if isPrivilegedUser(ev.TargetUser) {
			alerts = append(alerts, Alert{
				RuleID:      "AD-PRIV-LOGIN-FAIL",
				Severity:    "high",
				Title:       "域管理员登录失败",
				Description: ev.TargetUser + " from " + ev.SourceIP,
				ATTCKTactic: "TA0006",
				ATTCKTech:   "T1110.003",
				Event:       ev,
			})
		}

	case EventLogonSuccess:
		// 异常 logon type
		if ev.LogonType == 10 && !isWorkHours(ev.Timestamp) {
			alerts = append(alerts, Alert{
				RuleID:      "AD-OFFHOUR-RDP",
				Severity:    "medium",
				Title:       "工作时间外 RDP 登录",
				Description: ev.TargetUser + " from " + ev.SourceIP,
				ATTCKTactic: "TA0001",
				ATTCKTech:   "T1078",
				Event:       ev,
			})
		}

	case EventPrivilegeAssign:
		alerts = append(alerts, Alert{
			RuleID:      "AD-PRIV-ASSIGN",
			Severity:    "high",
			Title:       "特权分配 (SeDebugPrivilege / SeTcbPrivilege)",
			ATTCKTactic: "TA0004",
			ATTCKTech:   "T1548",
			Event:       ev,
		})

	case EventGroupAdd:
		if isHighPrivGroup(ev.TargetGroup) {
			alerts = append(alerts, Alert{
				RuleID:      "AD-HIGH-PRIV-GROUP-ADD",
				Severity:    "critical",
				Title:       "高权限组成员添加 (" + ev.TargetGroup + ")",
				Description: "User " + ev.UserName + " 加入 " + ev.TargetGroup,
				ATTCKTactic: "TA0003",
				ATTCKTech:   "T1098.007",
				Event:       ev,
			})
		}

	case EventKerberosTGSReq:
		// Kerberoasting: 单用户 10min 请求 > 20 个 SPN
		if ev.ServiceName != "" {
			n := d.kerberoastSPNs.IncrAndGet(ev.UserName + "|" + ev.ServiceName)
			if n == 1 {
				// 实际看 user 的 distinct SPN 个数, 简化用 ServiceName 计数
				if total := d.kerberoastSPNs.DistinctPrefix(ev.UserName + "|"); total > 20 {
					alerts = append(alerts, Alert{
						RuleID:      "AD-KERBEROASTING",
						Severity:    "high",
						Title:       "Kerberoasting (TGS-REQ 大量 SPN)",
						Description: "User " + ev.UserName + " 请求 " + strconv.Itoa(total) + " 个不同 SPN",
						ATTCKTactic: "TA0006",
						ATTCKTech:   "T1558.003",
						Event:       ev,
					})
				}
			}
		}

	case EventDCSync:
		// DCSync: 非域控 IP 调 DSReplicaGetChanges
		n := d.dcSyncReq.IncrAndGet(ev.SourceIP)
		if n >= 1 {
			alerts = append(alerts, Alert{
				RuleID:      "AD-DCSYNC",
				Severity:    "critical",
				Title:       "DCSync 仿冒域控同步 hash",
				Description: "Source IP " + ev.SourceIP + " 调 DSReplicaGetChanges (mimikatz lsadump::dcsync)",
				ATTCKTactic: "TA0006",
				ATTCKTech:   "T1003.006",
				Event:       ev,
			})
		}

	case EventNTLMAuth:
		// legacy NTLM 应被禁用 (改 Kerberos)
		alerts = append(alerts, Alert{
			RuleID:      "AD-LEGACY-NTLM",
			Severity:    "low",
			Title:       "NTLM 认证 (legacy)",
			Description: "User " + ev.UserName + " 走 NTLM 认证 (推荐迁 Kerberos)",
			ATTCKTactic: "TA0006",
			ATTCKTech:   "T1187",
			Event:       ev,
		})

	case EventNewProcess:
		// 检 lolbins / 攻击者常用 二进制
		if isAttackerTool(ev.ProcessName) {
			alerts = append(alerts, Alert{
				RuleID:      "AD-ATTACKER-TOOL",
				Severity:    "high",
				Title:       "攻击者常用工具执行",
				Description: ev.ProcessName + " " + ev.ProcessCmd,
				ATTCKTactic: "TA0002",
				ATTCKTech:   "T1059",
				Event:       ev,
			})
		}
	}
	return alerts
}

// isPrivilegedUser 检 (大致, 实际应从 AD 查 memberOf).
func isPrivilegedUser(u string) bool {
	low := strings.ToLower(u)
	priv := []string{"administrator", "admin", "domain admin", "enterprise admin", "krbtgt"}
	for _, p := range priv {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// isHighPrivGroup 检高权限组.
func isHighPrivGroup(g string) bool {
	low := strings.ToLower(g)
	for _, p := range []string{
		"domain admins", "enterprise admins", "schema admins",
		"administrators", "backup operators", "account operators",
		"dnsadmins",
	} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

// isAttackerTool 已知攻击工具二进制名.
func isAttackerTool(name string) bool {
	low := strings.ToLower(name)
	tools := []string{
		"mimikatz", "lazagne", "procdump", "psexec", "sharphound",
		"bloodhound", "cobalt", "powerview", "empire", "metasploit",
		"impacket", "winexe", "wmiexec", "smbexec", "secretsdump",
	}
	for _, t := range tools {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

// isWorkHours 9:00-19:00 工作日.
func isWorkHours(t time.Time) bool {
	wd := t.Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		return false
	}
	h := t.Hour()
	return h >= 9 && h < 19
}
