package model

import "fmt"

// KubeBaselineAlertStatus 基线告警状态
type KubeBaselineAlertStatus string

const (
	KubeBaselineAlertStatusActive   KubeBaselineAlertStatus = "active"   // 活跃（检查未通过）
	KubeBaselineAlertStatusResolved KubeBaselineAlertStatus = "resolved" // 已恢复（重新检查通过）
	KubeBaselineAlertStatusIgnored  KubeBaselineAlertStatus = "ignored"  // 已忽略
)

// KubeBaselineAlert 容器 CIS 基线告警
// 与 KubeAlarm（运行时威胁）分离，专用于合规性基线违规
type KubeBaselineAlert struct {
	TenantID          string                  `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID                uint                    `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ClusterID         uint                    `gorm:"column:cluster_id;not null;index" json:"clusterId"`
	ClusterName       string                  `gorm:"column:cluster_name;type:varchar(255)" json:"clusterName"`
	CheckID           string                  `gorm:"column:check_id;type:varchar(50);not null;index" json:"checkId"`
	CheckName         string                  `gorm:"column:check_name;type:varchar(255)" json:"checkName"`
	Category          string                  `gorm:"column:category;type:varchar(50);not null;index" json:"category"`
	Severity          string                  `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`
	Description       string                  `gorm:"column:description;type:text" json:"description"`
	Remediation       string                  `gorm:"column:remediation;type:text" json:"remediation"`
	AffectedResources AffectedResources       `gorm:"column:affected_resources;type:json" json:"affectedResources"`
	Fingerprint       string                  `gorm:"column:fingerprint;type:varchar(128);not null;uniqueIndex" json:"fingerprint"`
	Status            KubeBaselineAlertStatus `gorm:"column:status;type:varchar(20);not null;default:'active';index" json:"status"`
	FirstSeenAt       LocalTime               `gorm:"column:first_seen_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"firstSeenAt"`
	LastSeenAt        LocalTime               `gorm:"column:last_seen_at;type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"lastSeenAt"`
	ResolvedAt        *LocalTime              `gorm:"column:resolved_at;type:timestamp" json:"resolvedAt"`
	CreatedAt         LocalTime               `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"createdAt"`
	UpdatedAt         LocalTime               `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (KubeBaselineAlert) TableName() string {
	return "kube_baseline_alerts"
}

// BaselineAlertFingerprint 生成基线告警去重键
func BaselineAlertFingerprint(clusterID uint, checkID string) string {
	return fmt.Sprintf("cis-baseline-%d-%s", clusterID, checkID)
}
