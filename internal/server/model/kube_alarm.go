package model

// KubeAlarmType 容器告警类型
type KubeAlarmType string

const (
	KubeAlarmTypeContainerEscape     KubeAlarmType = "container_escape"
	KubeAlarmTypeAbnormalProcess     KubeAlarmType = "abnormal_process"
	KubeAlarmTypeAbnormalNetwork     KubeAlarmType = "abnormal_network"
	KubeAlarmTypeFileTamper          KubeAlarmType = "file_tamper"
	KubeAlarmTypePrivilegeEscalation KubeAlarmType = "privilege_escalation"
	KubeAlarmTypeReverseShell        KubeAlarmType = "reverse_shell"
	KubeAlarmTypeCryptoMining        KubeAlarmType = "crypto_mining"
)

// KubeAlarmStatus 告警状态
type KubeAlarmStatus string

const (
	KubeAlarmStatusPending   KubeAlarmStatus = "pending"
	KubeAlarmStatusProcessed KubeAlarmStatus = "processed"
	KubeAlarmStatusIgnored   KubeAlarmStatus = "ignored"
)

// KubeAlarm 容器安全告警
type KubeAlarm struct {
	TenantID       string          `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID             uint            `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ClusterID      uint            `gorm:"column:cluster_id;not null;index" json:"clusterId"`
	ClusterName    string          `gorm:"column:cluster_name;type:varchar(255)" json:"clusterName"`
	Severity       string          `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`
	AlarmType      KubeAlarmType   `gorm:"column:alarm_type;type:varchar(50);not null;index" json:"alarmType"`
	RuleID         string          `gorm:"column:rule_id;type:varchar(20);index" json:"ruleId"`
	Title          string          `gorm:"column:title;type:varchar(255)" json:"title"`
	Description    string          `gorm:"column:description;type:text" json:"description"`
	Remediation    string          `gorm:"column:remediation;type:text" json:"remediation"`
	Message        string          `gorm:"column:message;type:text" json:"message"`
	Namespace      string          `gorm:"column:namespace;type:varchar(255)" json:"namespace"`
	PodName        string          `gorm:"column:pod_name;type:varchar(255)" json:"podName"`
	ContainerName  string          `gorm:"column:container_name;type:varchar(255)" json:"containerName"`
	ContainerID    string          `gorm:"column:container_id;type:varchar(64)" json:"containerId"`
	NodeName       string          `gorm:"column:node_name;type:varchar(255)" json:"nodeName"`
	ImageName      string          `gorm:"column:image_name;type:varchar(500)" json:"imageName"`
	Target         string          `gorm:"column:target;type:varchar(500)" json:"target"`
	Fingerprint    string          `gorm:"column:fingerprint;type:varchar(64)" json:"fingerprint"`
	Count          int             `gorm:"column:count;type:int;not null;default:1" json:"count"`
	RawData        RawJSON         `gorm:"column:raw_data;type:json" json:"rawData"`
	Status         KubeAlarmStatus `gorm:"column:status;type:varchar(20);not null;default:'pending';index" json:"status"`
	FirstSeenAt    LocalTime       `gorm:"column:first_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"firstSeenAt"`
	LastSeenAt     LocalTime       `gorm:"column:last_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"lastSeenAt"`
	LastNotifiedAt *LocalTime      `gorm:"column:last_notified_at;type:timestamp" json:"lastNotifiedAt"`
	CreatedAt      LocalTime       `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"createdAt"`
	ResolvedAt     *LocalTime      `gorm:"column:resolved_at;type:timestamp" json:"resolvedAt"`
}

func (KubeAlarm) TableName() string {
	return "kube_alarms"
}
