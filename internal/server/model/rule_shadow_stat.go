package model

// RuleShadowStat 记录影子阶段规则的命中量。
//
// 影子规则不产生告警，也就不会产生事件与研判结论——如果晋级一律要求精确率，
// 影子规则永远凑不齐样本，会卡死在影子阶段。所以 shadow → context 这一跳改看
// 命中量：先回答"它到底会响多少次"，再谈准不准。
type RuleShadowStat struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	// RuleID 形如 "cel-12"，与告警的 rule_id 同格式。
	RuleID string `gorm:"column:rule_id;type:varchar(64);not null;uniqueIndex" json:"rule_id"`
	// Hits 累计命中次数。
	Hits int64 `gorm:"column:hits;not null;default:0" json:"hits"`
	// Hosts 命中过的主机数。只在一台机器上响的规则说明不了什么，
	// 它可能只是那台机器的特例。
	Hosts int `gorm:"column:hosts;not null;default:0" json:"hosts"`

	FirstHitAt *LocalTime `gorm:"column:first_hit_at;type:timestamp;null" json:"first_hit_at,omitempty"`
	LastHitAt  *LocalTime `gorm:"column:last_hit_at;type:timestamp;null" json:"last_hit_at,omitempty"`
	// ObservedSince 进入影子阶段的时间，用于计算观察时长。
	//
	// 与 FirstHitAt 分开：一条从没响过的规则，观察时长照样在走。
	// 只看首次命中会让"零命中"看起来像"还没开始观察"。
	ObservedSince LocalTime `gorm:"column:observed_since;type:timestamp;default:CURRENT_TIMESTAMP" json:"observed_since"`
}

// TableName 指定表名。
func (RuleShadowStat) TableName() string { return "rule_shadow_stats" }
