// Package model 提供数据库模型定义
package model

// 安全事件(Incident)状态。
const (
	IncidentStatusActive        = "active"
	IncidentStatusInvestigating = "investigating"
	IncidentStatusResolved      = "resolved"
)

// 研判结论。关闭事件必须给出结论——"关掉了"和"判过了"是两件事。
//
// 结论同时是检测质量的唯一可信来源：precision 只能由它算出，
// 拿 resolved 数量代替会把"没人看所以批量关掉"算成检测准确。
const (
	// VerdictTruePositive 真实威胁。
	VerdictTruePositive = "true_positive"
	// VerdictFalsePositive 误报，检测本身有问题。
	VerdictFalsePositive = "false_positive"
	// VerdictBenignTruePositive 检测正确但行为无害（如运维自己的操作）。
	// 单独一档很关键：把它算进误报会让规则被错误地调松。
	VerdictBenignTruePositive = "benign_true_positive"
)

// IncidentEventType 是事件时间线上的动作类型。
const (
	IncidentEventAssigned  = "assigned"
	IncidentEventAcked     = "acked"
	IncidentEventComment   = "comment"
	IncidentEventEvidence  = "evidence"
	IncidentEventEscalated = "escalated"
	IncidentEventVerdict   = "verdict"
	IncidentEventResolved  = "resolved"
)

// 值班层级。升级沿层级向上，每层对应一组值班人。
const (
	OncallTierL1       = "l1"       // 一线值班：默认接单
	OncallTierL2       = "l2"       // 二线：L1 升级目标
	OncallTierSecurity = "security" // 安全负责人：最终升级目标
)

// OncallShift 是一条值班安排。
//
// 没有值班表，新事件就永远是"无人负责"，超时告警只会天天响而没人知道该找谁。
// 排班按时间窗而非固定人：值班是轮换的，把负责人写死在配置里意味着换班要改配置。
type OncallShift struct {
	TenantID string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Tier     string    `gorm:"column:tier;type:varchar(20);not null;index" json:"tier"`
	Username string    `gorm:"column:username;type:varchar(100);not null" json:"username"`
	StartsAt LocalTime `gorm:"column:starts_at;type:timestamp;not null;index" json:"starts_at"`
	EndsAt   LocalTime `gorm:"column:ends_at;type:timestamp;not null;index" json:"ends_at"`

	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (OncallShift) TableName() string { return "oncall_shifts" }

// NextTier 返回升级链上的下一层。已在最高层则返回空串。
//
// 升级必须有确定的下一站：让人自己填"升级给谁"，在半夜三点是行不通的。
func NextTier(tier string) string {
	switch tier {
	case OncallTierL1:
		return OncallTierL2
	case OncallTierL2:
		return OncallTierSecurity
	default:
		return ""
	}
}

// IncidentEvent 是一条事件时间线记录：状态变更、研判备注、证据附加都落在这里。
//
// 单表承载而非拆成评论/审计/证据三张：调查过程本身就是一条连续的叙事，
// 拆开会让"谁在什么时候基于什么做了什么决定"需要跨表拼接，而这恰恰是复盘要看的东西。
type IncidentEvent struct {
	TenantID   string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	IncidentID string `gorm:"column:incident_id;type:varchar(128);not null;index" json:"incident_id"`
	Type       string `gorm:"column:type;type:varchar(20);not null;index" json:"type"`
	Actor      string `gorm:"column:actor;type:varchar(100);not null" json:"actor"`
	Body       string `gorm:"column:body;type:text" json:"body"`
	// Ref 指向证据所在位置（如 storyline id、告警 result_id、外部工单号）。
	Ref       string    `gorm:"column:ref;type:varchar(255)" json:"ref,omitempty"`
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"created_at"`
}

// TableName 指定表名
func (IncidentEvent) TableName() string { return "incident_events" }

// Incident 安全事件：把同主机、同时间窗内的多源信号(CEL 告警 + BDE 行为异常 + storyline)
// 关联成一个事件，按 ATT&CK 战术阶段排列，聚合风险。对齐 XDR「碎片告警 → 攻击链事件」。
//
// 关联层覆盖在 alerts 之上，不改动 storyline 引擎；每主机至多一条 active incident，
// 新信号并入、按 kill-chain 推进抬升风险。
type Incident struct {
	TenantID   string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	IncidentID string `gorm:"column:incident_id;type:varchar(128);uniqueIndex;not null" json:"incident_id"` // 格式 "inc-{64位host_id}-{unix秒}"，长 79 字符，需 >64

	HostID    string  `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Hostname  string  `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	Status    string  `gorm:"column:status;type:varchar(20);not null;default:'active';index" json:"status"`
	Severity  string  `gorm:"column:severity;type:varchar(20);index" json:"severity"`      // 成员最高级别
	RiskScore float64 `gorm:"column:risk_score;type:decimal(5,1);index" json:"risk_score"` // 聚合风险(成员 max + 多战术 boost)

	Tactics     string `gorm:"column:tactics;type:varchar(255)" json:"tactics"` // 逗号分隔、按 kill-chain 排序的 ATT&CK 战术 ID
	TacticCount int    `gorm:"column:tactic_count" json:"tactic_count"`

	AlertIDs           StringArray `gorm:"column:alert_ids;type:json" json:"alert_ids"` // 成员 CEL/告警 ID
	AlertCount         int         `gorm:"column:alert_count" json:"alert_count"`
	BehaviorAlertCount int         `gorm:"column:behavior_alert_count" json:"behavior_alert_count"`
	StorylineIDs       StringArray `gorm:"column:storyline_ids;type:json" json:"storyline_ids"`

	Title   string `gorm:"column:title;type:varchar(255)" json:"title"`
	Summary string `gorm:"column:summary;type:text" json:"summary"`

	// --- 运营闭环字段 ---
	//
	// 此前事件只有 active/investigating/resolved 三态与一个 resolved_by（实际只会是
	// "auto"）：没有负责人、没有响应时限、没有研判结论、关闭不需要理由。
	// 结果是告警越准积压越多，最后没人看——检测能力再强也变不成处置能力。

	// Owner 负责人。无 owner 的事件不计入 MTTA/MTTR，只计入覆盖率。
	Owner      string     `gorm:"column:owner;type:varchar(100);index" json:"owner,omitempty"`
	AssignedAt *LocalTime `gorm:"column:assigned_at;type:timestamp" json:"assigned_at,omitempty"`
	AssignedBy string     `gorm:"column:assigned_by;type:varchar(100)" json:"assigned_by,omitempty"`

	// AckedAt 认领时间，MTTA 的终点。与 AssignedAt 分开：被指派不等于有人开始看。
	AckedAt *LocalTime `gorm:"column:acked_at;type:timestamp" json:"acked_at,omitempty"`
	AckedBy string     `gorm:"column:acked_by;type:varchar(100)" json:"acked_by,omitempty"`

	// AckDueAt / ResolveDueAt 按严重级别在事件创建时算出，用于识别超时。
	AckDueAt     *LocalTime `gorm:"column:ack_due_at;type:timestamp;index" json:"ack_due_at,omitempty"`
	ResolveDueAt *LocalTime `gorm:"column:resolve_due_at;type:timestamp;index" json:"resolve_due_at,omitempty"`

	// Verdict 研判结论，关闭时必填。检测质量的 precision 只能由它算出。
	Verdict       string `gorm:"column:verdict;type:varchar(30);index" json:"verdict,omitempty"`
	VerdictReason string `gorm:"column:verdict_reason;type:text" json:"verdict_reason,omitempty"`

	// Escalated 升级标记。升级必须留下对象与原因，否则"升级了"无从追溯。
	Escalated   bool       `gorm:"column:escalated;default:false;index" json:"escalated"`
	EscalatedAt *LocalTime `gorm:"column:escalated_at;type:timestamp" json:"escalated_at,omitempty"`
	EscalatedTo string     `gorm:"column:escalated_to;type:varchar(100)" json:"escalated_to,omitempty"`

	// CloseReason 关闭原因，必填。"关掉了"和"判过了"是两件事。
	CloseReason string `gorm:"column:close_reason;type:text" json:"close_reason,omitempty"`

	FirstSeenAt LocalTime  `gorm:"column:first_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"first_seen_at"`
	LastSeenAt  LocalTime  `gorm:"column:last_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"last_seen_at"`
	ResolvedAt  *LocalTime `gorm:"column:resolved_at;type:timestamp" json:"resolved_at"`
	ResolvedBy  string     `gorm:"column:resolved_by;type:varchar(100)" json:"resolved_by"`
	CreatedAt   LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (Incident) TableName() string {
	return "incidents"
}
