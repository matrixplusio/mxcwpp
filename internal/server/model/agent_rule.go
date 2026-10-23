package model

// AgentRule Agent 端检测规则模型
// 存储 YAML 格式规则文本，通过 gRPC Task 推送给 Agent 热加载
type AgentRule struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	RuleID    string    `gorm:"column:rule_id;type:varchar(100);not null;uniqueIndex" json:"rule_id"` // YAML 中的 id 字段
	Name      string    `gorm:"type:varchar(200);not null" json:"name"`
	Category  string    `gorm:"type:varchar(50);index" json:"category"` // process / file / network
	Severity  string    `gorm:"type:varchar(20);not null;index" json:"severity"`
	Content   string    `gorm:"type:text;not null" json:"content"` // 完整 YAML 规则文本
	Enabled   bool      `gorm:"default:true;index" json:"enabled"`
	Version   int       `gorm:"default:1" json:"version"` // 规则版本号
	CreatedAt LocalTime `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (AgentRule) TableName() string {
	return "agent_rules"
}
