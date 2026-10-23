package model

// RuleCriticalAdmission 记录一条规则是否被允许产生 critical 告警。
//
// critical 的含义是「需要立即有人看」，它直接决定推送。规则作者写的级别只是声明，
// 一条写着 critical 的规则命中几百次、没有一次是真的，它就不该继续占用这个级别。
// 所以 critical 要单独准入：表里没有、或 allowed=false 的规则，告警最高到 high。
//
// 与 DetectionRule.Severity 分开存，而不是直接改规则的级别：
// 规则声明的级别还决定自动响应与观察期豁免，那些语义不该跟着降；
// 而且准入要覆盖 CEL、攻击链、硬编码检测三种来源，后两者没有同一张规则表。
type RuleCriticalAdmission struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	// RuleID 与告警的 rule_id 同格式：cel-12 / seq-3 / ROOTKIT_BACKDOOR。
	RuleID  string `gorm:"column:rule_id;primaryKey;type:varchar(128)" json:"ruleId"`
	Allowed bool   `gorm:"column:allowed;not null;default:false;index" json:"allowed"`
	// Reason 最近一次变更的原因。人工变更必须写。
	Reason string `gorm:"column:reason;type:varchar(500)" json:"reason"`
	// ChangedBy 变更者：用户名，或 seed（初始清单）。
	ChangedBy string `gorm:"column:changed_by;type:varchar(64)" json:"changedBy"`
	// DecidedAt 最近一次变更的时间。降级建议只看这之后产生的告警：
	// 人工确认保留准入之后，不能被确认之前的旧研判记录立刻再提一次。
	DecidedAt LocalTime `gorm:"column:decided_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"decidedAt"`

	// DemotionSuggestedAt / DemotionSuggestion 系统按研判结果提出的「建议移出准入」，等人确认。
	//
	// 只提建议、不自动生效：是否配得上 critical 是规则管理的决定，而研判结论是处置权限就能写的。
	// 自动生效等于让能关告警的人间接改了检测分级，而且没有人会收到通知。
	DemotionSuggestedAt *LocalTime `gorm:"column:demotion_suggested_at;type:timestamp;null" json:"demotionSuggestedAt"`
	DemotionSuggestion  string     `gorm:"column:demotion_suggestion;type:varchar(500)" json:"demotionSuggestion"`
}

// TableName 指定表名。
func (RuleCriticalAdmission) TableName() string { return "rule_critical_admissions" }

// 准入记录的变更者（非人工）。
const AdmissionChangedBySeed = "seed"
