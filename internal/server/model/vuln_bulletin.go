package model

import "database/sql/driver"

// ============================================================
// 漏洞通报分级常量
// ============================================================

// BulletinPriority 通报优先级
const (
	BulletinPriorityP0 = "P0" // 紧急：在野利用 + 远程 RCE / 0day
	BulletinPriorityP1 = "P1" // 高：有 EXP + 高危远程 / 本地提权
	BulletinPriorityP2 = "P2" // 中：高危无 EXP / 有 EXP 但仅本地
	BulletinPriorityP3 = "P3" // 低：中低危无 EXP
)

// BulletinStatus 通报状态
const (
	BulletinStatusPending      = "pending"      // 待处理
	BulletinStatusNotified     = "notified"     // 已通知
	BulletinStatusAcknowledged = "acknowledged" // 已确认
	BulletinStatusResolved     = "resolved"     // 已修复
	BulletinStatusIgnored      = "ignored"      // 已忽略
)

// VulnType 漏洞类型常量
const (
	VulnTypeRCE            = "rce"             // 远程代码执行
	VulnTypeLPE            = "lpe"             // 本地提权
	VulnTypeDoS            = "dos"             // 拒绝服务
	VulnTypeInfoDisclosure = "info_disclosure" // 信息泄露
	VulnTypeAuthBypass     = "auth_bypass"     // 认证绕过
	VulnTypeXSS            = "xss"             // 跨站脚本
	VulnTypeSQLi           = "sqli"            // SQL 注入
	VulnTypeSSRF           = "ssrf"            // 服务端请求伪造
	VulnTypeOther          = "other"           // 其他
	VulnTypeUnknown        = "unknown"         // 未知
)

// AttackVector 攻击向量常量
const (
	AttackVectorNetwork  = "network"
	AttackVectorAdjacent = "adjacent"
	AttackVectorLocal    = "local"
	AttackVectorPhysical = "physical"
)

// ============================================================
// PriorityFactors 分级依据（JSON 字段）
// ============================================================

// PriorityFactors 记录分级判断的各项因子
type PriorityFactors struct {
	CvssScore    float64 `json:"cvss_score"`
	CvssVector   string  `json:"cvss_vector,omitempty"`
	AttackVector string  `json:"attack_vector"`
	VulnType     string  `json:"vuln_type"`
	HasExploit   bool    `json:"has_exploit"`
	InKEV        bool    `json:"in_kev"`
	PatchAvail   bool    `json:"patch_available"`
	EpssScore    float64 `json:"epss_score,omitempty"`
	Reason       string  `json:"reason"` // 可读的分级理由
}

// Value 实现 driver.Valuer 接口
func (f PriorityFactors) Value() (driver.Value, error) { return JSONValue(f) }

// Scan 实现 sql.Scanner 接口
func (f *PriorityFactors) Scan(value any) error { return JSONScan(f, value) }

// ============================================================
// VulnBulletin 漏洞通报模型
// ============================================================

// VulnBulletin 漏洞通报
type VulnBulletin struct {
	TenantID   string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	BulletinNo string `gorm:"column:bulletin_no;type:varchar(30);uniqueIndex;not null" json:"bulletinNo"` // MX-2026-0001
	VulnID     uint   `gorm:"column:vuln_id;not null;index" json:"vulnId"`
	CveID      string `gorm:"column:cve_id;type:varchar(50);not null;index" json:"cveId"`

	// — 分级 —
	Priority        string          `gorm:"column:priority;type:varchar(5);not null;index" json:"priority"` // P0/P1/P2/P3
	PriorityFactors PriorityFactors `gorm:"column:priority_factors;type:json" json:"priorityFactors"`

	// — 漏洞快照（通报创建时冻结） —
	Component    string  `gorm:"column:component;type:varchar(200)" json:"component"`
	Severity     string  `gorm:"column:severity;type:varchar(20)" json:"severity"`
	CvssScore    float64 `gorm:"column:cvss_score;type:decimal(4,1)" json:"cvssScore"`
	CvssVector   string  `gorm:"column:cvss_vector;type:varchar(200)" json:"cvssVector"`
	VulnType     string  `gorm:"column:vuln_type;type:varchar(30)" json:"vulnType"`
	AttackVector string  `gorm:"column:attack_vector;type:varchar(20)" json:"attackVector"`
	Description  string  `gorm:"column:description;type:text" json:"description"`

	// — 影响范围 —
	AffectedAssets   int    `gorm:"column:affected_assets;default:0" json:"affectedAssets"`
	AffectedVersions string `gorm:"column:affected_versions;type:varchar(500)" json:"affectedVersions"`

	// — 修复信息 —
	FixedVersion   string `gorm:"column:fixed_version;type:varchar(100)" json:"fixedVersion"`
	FixSuggestion  string `gorm:"column:fix_suggestion;type:text" json:"fixSuggestion"`
	Workaround     string `gorm:"column:workaround;type:text" json:"workaround"`
	PatchAvailable bool   `gorm:"column:patch_available;default:false" json:"patchAvailable"`

	// — 威胁情报 —
	Source     string  `gorm:"column:source;type:varchar(50)" json:"source"`
	HasExploit bool    `gorm:"column:has_exploit;default:false" json:"hasExploit"`
	InKEV      bool    `gorm:"column:in_kev;default:false" json:"inKev"`
	EpssScore  float64 `gorm:"column:epss_score;type:decimal(5,4);default:0" json:"epssScore"`
	ExploitRef string  `gorm:"column:exploit_ref;type:varchar(500)" json:"exploitRef"`

	// — 生命周期 —
	Status         string     `gorm:"column:status;type:varchar(20);not null;default:'pending';index" json:"status"`
	NotifiedAt     *LocalTime `gorm:"column:notified_at;type:timestamp" json:"notifiedAt"`
	AcknowledgedAt *LocalTime `gorm:"column:acknowledged_at;type:timestamp" json:"acknowledgedAt"`
	AcknowledgedBy string     `gorm:"column:acknowledged_by;type:varchar(100)" json:"acknowledgedBy"`
	ResolvedAt     *LocalTime `gorm:"column:resolved_at;type:timestamp" json:"resolvedAt"`
	ResolvedBy     string     `gorm:"column:resolved_by;type:varchar(100)" json:"resolvedBy"`
	ResolveComment string     `gorm:"column:resolve_comment;type:text" json:"resolveComment"`
	IgnoredAt      *LocalTime `gorm:"column:ignored_at;type:timestamp" json:"ignoredAt"`
	IgnoredBy      string     `gorm:"column:ignored_by;type:varchar(100)" json:"ignoredBy"`
	IgnoreReason   string     `gorm:"column:ignore_reason;type:text" json:"ignoreReason"`

	// — SLA —
	SLAAckDeadline     *LocalTime `gorm:"column:sla_ack_deadline;type:timestamp" json:"slaAckDeadline"`
	SLAResolveDeadline *LocalTime `gorm:"column:sla_resolve_deadline;type:timestamp" json:"slaResolveDeadline"`
	SLABreached        bool       `gorm:"column:sla_breached;default:false;index" json:"slaBreached"`

	// — 通知追踪 —
	NotifyCount    int        `gorm:"column:notify_count;default:0" json:"notifyCount"`
	LastNotifiedAt *LocalTime `gorm:"column:last_notified_at;type:timestamp" json:"lastNotifiedAt"`

	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`

	// 关联
	Vulnerability Vulnerability `gorm:"foreignKey:VulnID" json:"vulnerability,omitempty"`
}

// TableName 指定表名
func (VulnBulletin) TableName() string {
	return "vuln_bulletins"
}

// ============================================================
// VulnBulletinConfig 通报配置（存储在 system_configs 表）
// ============================================================

// VulnBulletinConfig 漏洞通报全局配置
type VulnBulletinConfig struct {
	Enabled          bool     `json:"enabled"`           // 是否启用通报
	AutoCreate       bool     `json:"auto_create"`       // 扫描发现新漏洞自动创建通报
	NotifyPriorities []string `json:"notify_priorities"` // 启用通报的优先级列表，如 ["P0","P1"]

	// SLA 时限（小时）
	P0AckHours     int `json:"p0_ack_hours"`
	P0ResolveHours int `json:"p0_resolve_hours"`
	P1AckHours     int `json:"p1_ack_hours"`
	P1ResolveHours int `json:"p1_resolve_hours"`
	P2AckHours     int `json:"p2_ack_hours"`
	P2ResolveHours int `json:"p2_resolve_hours"`
	P3AckHours     int `json:"p3_ack_hours"`
	P3ResolveHours int `json:"p3_resolve_hours"`

	// 升级通知
	EscalationEnabled   bool `json:"escalation_enabled"`
	P0EscalationMinutes int  `json:"p0_escalation_minutes"`
	P1EscalationMinutes int  `json:"p1_escalation_minutes"`
}

// DefaultVulnBulletinConfig 返回默认配置
func DefaultVulnBulletinConfig() VulnBulletinConfig {
	return VulnBulletinConfig{
		Enabled:             true,
		AutoCreate:          true,
		NotifyPriorities:    []string{BulletinPriorityP0, BulletinPriorityP1, BulletinPriorityP2},
		P0AckHours:          1,
		P0ResolveHours:      24,
		P1AckHours:          4,
		P1ResolveHours:      72,
		P2AckHours:          24,
		P2ResolveHours:      168,
		P3AckHours:          168,
		P3ResolveHours:      720,
		EscalationEnabled:   true,
		P0EscalationMinutes: 240,
		P1EscalationMinutes: 1440,
	}
}

// GetAckHours 获取指定优先级的确认时限
func (c VulnBulletinConfig) GetAckHours(priority string) int {
	switch priority {
	case BulletinPriorityP0:
		return c.P0AckHours
	case BulletinPriorityP1:
		return c.P1AckHours
	case BulletinPriorityP2:
		return c.P2AckHours
	case BulletinPriorityP3:
		return c.P3AckHours
	default:
		return 24
	}
}

// GetResolveHours 获取指定优先级的修复时限
func (c VulnBulletinConfig) GetResolveHours(priority string) int {
	switch priority {
	case BulletinPriorityP0:
		return c.P0ResolveHours
	case BulletinPriorityP1:
		return c.P1ResolveHours
	case BulletinPriorityP2:
		return c.P2ResolveHours
	case BulletinPriorityP3:
		return c.P3ResolveHours
	default:
		return 168
	}
}

// GetEscalationMinutes 获取指定优先级的升级通知间隔（分钟），0 表示不升级
func (c VulnBulletinConfig) GetEscalationMinutes(priority string) int {
	if !c.EscalationEnabled {
		return 0
	}
	switch priority {
	case BulletinPriorityP0:
		return c.P0EscalationMinutes
	case BulletinPriorityP1:
		return c.P1EscalationMinutes
	default:
		return 0 // P2/P3 不升级
	}
}

// IsPriorityEnabled 检查指定优先级是否在启用列表中
func (c VulnBulletinConfig) IsPriorityEnabled(priority string) bool {
	for _, p := range c.NotifyPriorities {
		if p == priority {
			return true
		}
	}
	return false
}

// PriorityRank 返回优先级数值（用于比较，数值越小优先级越高）
func PriorityRank(priority string) int {
	switch priority {
	case BulletinPriorityP0:
		return 0
	case BulletinPriorityP1:
		return 1
	case BulletinPriorityP2:
		return 2
	case BulletinPriorityP3:
		return 3
	default:
		return 99
	}
}
