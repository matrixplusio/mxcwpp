package model

import (
	"database/sql/driver"
	"encoding/json"
)

// KubeClusterStatus 集群状态
type KubeClusterStatus string

const (
	KubeClusterStatusRunning KubeClusterStatus = "running"
	KubeClusterStatusWarning KubeClusterStatus = "warning"
	KubeClusterStatusOffline KubeClusterStatus = "offline"
)

// RawJSON 原始 JSON 类型，存储为 JSON，序列化时保持原始 JSON 格式
type RawJSON json.RawMessage

// Value 实现 driver.Valuer 接口
func (j RawJSON) Value() (driver.Value, error) { return JSONValue(j) }

// Scan 实现 sql.Scanner 接口
func (j *RawJSON) Scan(value any) error { return JSONScan(j, value) }

// MarshalJSON 实现 json.Marshaler 接口
func (j RawJSON) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return []byte(j), nil
}

// UnmarshalJSON 实现 json.Unmarshaler 接口
func (j *RawJSON) UnmarshalJSON(data []byte) error {
	if data == nil {
		*j = nil
		return nil
	}
	*j = append((*j)[0:0], data...)
	return nil
}

// KubeCluster Kubernetes 集群模型
type KubeCluster struct {
	TenantID       string            `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID             uint              `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name           string            `gorm:"column:name;type:varchar(255);not null;uniqueIndex" json:"name"`
	ApiServer      string            `gorm:"column:api_server;type:varchar(500)" json:"apiServer"`
	KubeConfig     string            `gorm:"column:kube_config;type:text" json:"-"`
	AuditToken     string            `gorm:"column:audit_token;type:varchar(64);uniqueIndex" json:"auditToken"`
	Status         KubeClusterStatus `gorm:"column:status;type:varchar(20);default:'offline'" json:"status"`
	Version        string            `gorm:"column:version;type:varchar(50)" json:"version"`
	NodeCount      int               `gorm:"column:node_count;type:int;default:0" json:"nodeCount"`
	PodCount       int               `gorm:"column:pod_count;type:int;default:0" json:"podCount"`
	NamespaceCount int               `gorm:"column:namespace_count;type:int;default:0" json:"namespaceCount"`
	HealthScore    int               `gorm:"column:health_score;type:int;default:100" json:"healthScore"`
	Remark         string            `gorm:"column:remark;type:text" json:"remark"`
	// GCP Pub/Sub 配置（GKE 审计日志接入，per-cluster）
	GCPEnabled         bool   `gorm:"column:gcp_enabled;type:tinyint(1);default:0" json:"gcpEnabled"`
	GCPProjectID       string `gorm:"column:gcp_project_id;type:varchar(255)" json:"gcpProjectId,omitempty"`
	GCPSubscription    string `gorm:"column:gcp_subscription;type:varchar(255)" json:"gcpSubscription,omitempty"`
	GCPCredentialsJSON string `gorm:"column:gcp_credentials_json;type:text" json:"-"` // SA JSON Key 内容，API 不直接暴露
	// GKE Container API 坐标（托管层基线检查用，复用 GCPProjectID + GCPCredentialsJSON）
	GCPLocation    string    `gorm:"column:gcp_location;type:varchar(64)" json:"gcpLocation,omitempty"`         // 集群 region/zone
	GCPClusterName string    `gorm:"column:gcp_cluster_name;type:varchar(255)" json:"gcpClusterName,omitempty"` // GKE 集群 ID（缺省取 Name）
	CreatedAt      LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt      LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (KubeCluster) TableName() string {
	return "kube_clusters"
}
