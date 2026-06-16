package model

import "database/sql/driver"

// CheckConfig 检查配置（JSON 格式）
type CheckConfig struct {
	Condition string      `json:"condition"` // all/any/none
	Rules     []CheckRule `json:"rules"`
}

// CheckRule 单个检查规则
type CheckRule struct {
	Type   string   `json:"type"`
	Param  []string `json:"param"`
	Result string   `json:"result,omitempty"`
}

// FixConfig 修复配置（JSON 格式）
type FixConfig struct {
	Suggestion      string   `json:"suggestion"`
	Command         string   `json:"command,omitempty"`
	RestartServices []string `json:"restart_services,omitempty"` // 修复后需重启的服务
}

func (c CheckConfig) Value() (driver.Value, error) { return JSONValue(c) }
func (c *CheckConfig) Scan(value any) error        { return JSONScan(c, value) }
func (f FixConfig) Value() (driver.Value, error)   { return JSONValue(f) }
func (f *FixConfig) Scan(value any) error          { return JSONScan(f, value) }

// Rule 规则模型
type Rule struct {
	TenantID     string      `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	RuleID       string      `gorm:"primaryKey;column:rule_id;type:varchar(64);not null" json:"rule_id"`
	PolicyID     string      `gorm:"column:policy_id;type:varchar(64);not null;index" json:"policy_id"`
	Category     string      `gorm:"column:category;type:varchar(50)" json:"category"`
	Title        string      `gorm:"column:title;type:varchar(255)" json:"title"`
	Description  string      `gorm:"column:description;type:text" json:"description"`
	Severity     string      `gorm:"column:severity;type:varchar(20)" json:"severity"`
	Enabled      bool        `gorm:"column:enabled;type:boolean;default:true" json:"enabled"`
	Builtin      bool        `gorm:"column:builtin;type:boolean;default:false;index" json:"builtin"`       // 内置规则(文件同步管理)；false=用户导入/自建，启动同步永不覆盖
	TargetType   string      `gorm:"column:target_type;type:varchar(20);default:'all'" json:"target_type"` // 废弃，保留向后兼容
	RuntimeTypes StringArray `gorm:"column:runtime_types;type:json" json:"runtime_types"`                  // 适用的运行时类型：["vm", "docker", "k8s"]，空表示全部
	CheckConfig  CheckConfig `gorm:"column:check_config;type:json" json:"check_config"`
	FixConfig    FixConfig   `gorm:"column:fix_config;type:json" json:"fix_config"`
	CreatedAt    LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt    LocalTime   `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`

	// 关联关系
	Policy Policy `gorm:"foreignKey:PolicyID;references:ID" json:"policy,omitempty"`
}

// MatchesRuntimeType 检查规则是否适用于指定的运行时类型
// 注意：规则默认继承策略的 RuntimeTypes 设置
// - 如果规则的 RuntimeTypes 为空，表示继承策略设置（由策略层面过滤，规则层面不限制）
// - 如果规则有自己的 RuntimeTypes 设置，可以覆盖策略的设置
func (r *Rule) MatchesRuntimeType(runtimeType RuntimeType) bool {
	// 如果 RuntimeTypes 为空，表示继承策略设置（规则不做额外限制）
	// 策略会先过滤运行时类型，所以规则为空时直接返回 true
	if len(r.RuntimeTypes) == 0 {
		return true
	}
	// 检查是否包含指定的运行时类型
	for _, rt := range r.RuntimeTypes {
		if RuntimeType(rt) == runtimeType {
			return true
		}
	}
	return false
}

// TableName 指定表名
func (Rule) TableName() string {
	return "rules"
}
