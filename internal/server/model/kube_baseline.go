package model

import "database/sql/driver"

// AffectedResource 受影响的 K8s 资源
type AffectedResource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// AffectedResources 受影响资源列表（JSON 数组）
type AffectedResources []AffectedResource

// Value 实现 driver.Valuer 接口
func (a AffectedResources) Value() (driver.Value, error) { return JSONValue(a) }

// Scan 实现 sql.Scanner 接口
func (a *AffectedResources) Scan(value any) error { return JSONScan(a, value) }

// KubeBaseline CIS 基线检查结果
type KubeBaseline struct {
	TenantID          string            `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID                uint              `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ClusterID         uint              `gorm:"column:cluster_id;not null;index" json:"clusterId"`
	ClusterName       string            `gorm:"column:cluster_name;type:varchar(255)" json:"clusterName"`
	TaskID            uint              `gorm:"column:task_id;index" json:"taskId"` // 所属检查任务
	Category          string            `gorm:"column:category;type:varchar(50);not null;index" json:"category"`
	CheckID           string            `gorm:"column:check_id;type:varchar(50);not null" json:"checkId"`
	CheckName         string            `gorm:"column:check_name;type:varchar(255)" json:"checkName"`
	Title             string            `gorm:"column:title;type:varchar(255)" json:"title"`
	Description       string            `gorm:"column:description;type:text" json:"description"`
	Severity          string            `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`
	Result            string            `gorm:"column:result;type:varchar(20);not null;index" json:"result"`
	Remediation       string            `gorm:"column:remediation;type:text" json:"remediation"`
	Benchmark         string            `gorm:"column:benchmark;type:varchar(255)" json:"benchmark"`
	ControlRef        string            `gorm:"column:control_ref;type:varchar(255)" json:"controlRef"` // 框架条款映射(PSS/NSA/CIS 章节)
	AffectedResources AffectedResources `gorm:"column:affected_resources;type:json" json:"affectedResources"`
	CheckedAt         LocalTime         `gorm:"column:checked_at;type:timestamp;not null;index" json:"checkedAt"`
	CreatedAt         LocalTime         `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

func (KubeBaseline) TableName() string {
	return "kube_baselines"
}
