// Package model — AD / LDAP 域控审计事件 + 告警 (EDR-4).
package model

// ADAuditEvent 来自 Windows DC 或 Linux 域成员的 AD 审计原始事件.
//
// Agent 通过 WinEventLog 拉取 / Linux 域成员通过 winbind 日志解析
// → 上报 → 引擎 (internal/server/engine/adaudit) 匹配规则 → 写 ADAuditAlert.
type ADAuditEvent struct {
	TenantID        string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID              uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Kind            string    `gorm:"column:kind;type:varchar(40);not null;index" json:"kind"` // login_success/failure/priv_assign/group_add/...
	EventID         int       `gorm:"column:event_id;type:int;index" json:"event_id"`          // Windows event_id 4624/4625/...
	Timestamp       LocalTime `gorm:"column:timestamp;type:timestamp;not null;default:CURRENT_TIMESTAMP;index" json:"timestamp"`
	Username        string    `gorm:"column:username;type:varchar(128);index" json:"username"`
	UserDomain      string    `gorm:"column:user_domain;type:varchar(128)" json:"user_domain"`
	TargetUser      string    `gorm:"column:target_user;type:varchar(128)" json:"target_user"`
	TargetGroup     string    `gorm:"column:target_group;type:varchar(128)" json:"target_group"`
	SourceIP        string    `gorm:"column:source_ip;type:varchar(64);index" json:"source_ip"`
	LogonType       int       `gorm:"column:logon_type;type:int" json:"logon_type"`
	ProcessName     string    `gorm:"column:process_name;type:varchar(256)" json:"process_name"`
	ProcessCmd      string    `gorm:"column:process_cmd;type:varchar(1024)" json:"process_cmd"`
	ServiceName     string    `gorm:"column:service_name;type:varchar(128)" json:"service_name"`
	FailureCode     string    `gorm:"column:failure_code;type:varchar(20)" json:"failure_code"`
	WorkstationName string    `gorm:"column:workstation_name;type:varchar(128)" json:"workstation_name"`
	Severity        string    `gorm:"column:severity;type:varchar(20);not null;default:'low'" json:"severity"`
}

// TableName 表名.
func (ADAuditEvent) TableName() string { return "ad_audit_events" }

// ADAuditAlert AD 审计命中规则后的告警.
type ADAuditAlert struct {
	TenantID       string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID             uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	RuleID         string    `gorm:"column:rule_id;type:varchar(64);not null;index" json:"rule_id"`
	Severity       string    `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`
	Title          string    `gorm:"column:title;type:varchar(256);not null" json:"title"`
	Description    string    `gorm:"column:description;type:varchar(1024)" json:"description"`
	AttckTactic    string    `gorm:"column:attck_tactic;type:varchar(64)" json:"attck_tactic"`
	AttckTechnique string    `gorm:"column:attck_technique;type:varchar(64)" json:"attck_technique"`
	EventID        uint      `gorm:"column:event_id;type:int unsigned;index" json:"event_id"`
	DetectedAt     LocalTime `gorm:"column:detected_at;type:timestamp;not null;default:CURRENT_TIMESTAMP;index" json:"detected_at"`
	Status         string    `gorm:"column:status;type:varchar(20);not null;default:'open';index" json:"status"`
}

// TableName 表名.
func (ADAuditAlert) TableName() string { return "ad_audit_alerts" }
