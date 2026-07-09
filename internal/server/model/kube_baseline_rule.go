package model

import "database/sql/driver"

// KubeCheckConfig CEL 检查配置
type KubeCheckConfig struct {
	ResourceType string `json:"resourceType"` // pods, deployments, services, nodes...
	APIGroup     string `json:"apiGroup"`     // "", "apps", "rbac.authorization.k8s.io"...
	Namespace    string `json:"namespace"`    // "*" 全部, "!system" 排除系统, "" 集群级
	Expression   string `json:"expression"`   // CEL 表达式
	MatchPolicy  string `json:"matchPolicy"`  // "any_match_fail" 或 "no_match_fail"
}

// Value 实现 driver.Valuer 接口
func (c KubeCheckConfig) Value() (driver.Value, error) { return JSONValue(c) }

// Scan 实现 sql.Scanner 接口
func (c *KubeCheckConfig) Scan(value any) error { return JSONScan(c, value) }

// KubeBaselineRule 容器基线检查规则定义
type KubeBaselineRule struct {
	TenantID    string           `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint             `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	CheckID     string           `gorm:"column:check_id;type:varchar(50);uniqueIndex;not null" json:"checkId"`
	CheckName   string           `gorm:"column:check_name;type:varchar(255);not null" json:"checkName"`
	Category    string           `gorm:"column:category;type:varchar(50);not null;index" json:"category"`
	Severity    string           `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`
	Description string           `gorm:"column:description;type:text" json:"description"`
	Remediation string           `gorm:"column:remediation;type:text" json:"remediation"`
	Benchmark   string           `gorm:"column:benchmark;type:varchar(255)" json:"benchmark"`
	ControlRef  string           `gorm:"column:control_ref;type:varchar(255)" json:"controlRef"` // 框架条款映射(PSS/NSA/CIS 章节)
	CheckConfig *KubeCheckConfig `gorm:"column:check_config;type:json" json:"checkConfig"`
	Enabled     bool             `gorm:"column:enabled;type:boolean;default:true" json:"enabled"`
	Builtin     bool             `gorm:"column:builtin;type:boolean;default:false" json:"builtin"`
	CreatedAt   LocalTime        `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   LocalTime        `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (KubeBaselineRule) TableName() string {
	return "kube_baseline_rules"
}

// KubeExpressionTemplate CEL 表达式模板
type KubeExpressionTemplate struct {
	TenantID     string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name         string    `gorm:"column:name;type:varchar(100);not null" json:"name"`
	Description  string    `gorm:"column:description;type:varchar(500)" json:"description"`
	ResourceType string    `gorm:"column:resource_type;type:varchar(50);not null" json:"resourceType"`
	APIGroup     string    `gorm:"column:api_group;type:varchar(100)" json:"apiGroup"`
	Namespace    string    `gorm:"column:namespace;type:varchar(50)" json:"namespace"`
	Expression   string    `gorm:"column:expression;type:text;not null" json:"expression"`
	MatchPolicy  string    `gorm:"column:match_policy;type:varchar(30);default:any_match_fail" json:"matchPolicy"`
	Builtin      bool      `gorm:"column:builtin;type:boolean;default:false" json:"builtin"`
	CreatedAt    LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (KubeExpressionTemplate) TableName() string {
	return "kube_expression_templates"
}
