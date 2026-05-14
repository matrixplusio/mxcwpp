package model

// KubeEventStatus 事件状态
type KubeEventStatus string

const (
	KubeEventStatusUnhandled KubeEventStatus = "unhandled"
	KubeEventStatusHandled   KubeEventStatus = "handled"
)

// KubeEvent 容器安全事件
type KubeEvent struct {
	ID            uint            `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ClusterID     uint            `gorm:"column:cluster_id;not null;index" json:"clusterId"`
	ClusterName   string          `gorm:"column:cluster_name;type:varchar(255)" json:"clusterName"`
	EventType     string          `gorm:"column:event_type;type:varchar(50);not null;index" json:"eventType"`
	Severity      string          `gorm:"column:severity;type:varchar(20);not null;index" json:"severity"`
	Title         string          `gorm:"column:title;type:varchar(255)" json:"title"`
	Message       string          `gorm:"column:message;type:text" json:"message"`
	Namespace     string          `gorm:"column:namespace;type:varchar(255)" json:"namespace"`
	PodName       string          `gorm:"column:pod_name;type:varchar(255)" json:"podName"`
	ContainerName string          `gorm:"column:container_name;type:varchar(255)" json:"containerName"`
	ContainerID   string          `gorm:"column:container_id;type:varchar(64)" json:"containerId"`
	NodeName      string          `gorm:"column:node_name;type:varchar(255)" json:"nodeName"`
	Image         string          `gorm:"column:image;type:varchar(500)" json:"image"`
	SourceIP      string          `gorm:"column:source_ip;type:varchar(50)" json:"sourceIP"`
	ProcessName   string          `gorm:"column:process_name;type:varchar(255)" json:"processName"`
	ProcessArgs   string          `gorm:"column:process_args;type:text" json:"processArgs"`
	ProcessInfo   string          `gorm:"column:process_info;type:text" json:"processInfo"`
	RawData       RawJSON         `gorm:"column:raw_data;type:json" json:"rawData"`
	Status        KubeEventStatus `gorm:"column:status;type:varchar(20);not null;default:'unhandled';index" json:"status"`
	CreatedAt     LocalTime       `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"createdAt"`
}

func (KubeEvent) TableName() string {
	return "kube_events"
}
