package model

// KubeWhitelistStatus 白名单状态
type KubeWhitelistStatus string

const (
	KubeWhitelistStatusEnabled  KubeWhitelistStatus = "enabled"
	KubeWhitelistStatusDisabled KubeWhitelistStatus = "disabled"
)

// KubeWhitelist 容器告警白名单
type KubeWhitelist struct {
	TenantID    string      `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint        `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name        string      `gorm:"column:name;type:varchar(255);not null" json:"name"`
	ClusterID   *uint       `gorm:"column:cluster_id;index" json:"clusterId"`
	ClusterName string      `gorm:"column:cluster_name;type:varchar(255)" json:"clusterName"`
	AlarmTypes  StringArray `gorm:"column:alarm_types;type:json" json:"alarmTypes"`
	Namespace   string      `gorm:"column:namespace;type:varchar(255)" json:"namespace"`
	PodPattern  string      `gorm:"column:pod_pattern;type:varchar(500)" json:"podPattern"`
	// Users 只放行这些操作者（审计告警里的 user.username，如 system:serviceaccount:ns:name），空表示不限。
	Users StringArray `gorm:"column:users;type:json" json:"users"`
	// RuleIDs 只放行这些规则的告警（如 K8S-014），空表示不限。
	RuleIDs   StringArray         `gorm:"column:rule_ids;type:json" json:"ruleIds"`
	Status    KubeWhitelistStatus `gorm:"column:status;type:varchar(20);not null;default:'enabled'" json:"status"`
	HitCount  int                 `gorm:"column:hit_count;type:int;default:0" json:"hitCount"`
	Remark    string              `gorm:"column:remark;type:text" json:"remark"`
	CreatedAt LocalTime           `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt LocalTime           `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (KubeWhitelist) TableName() string {
	return "kube_whitelists"
}
