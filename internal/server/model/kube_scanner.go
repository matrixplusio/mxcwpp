package model

// KubeScannerState 集群内扫描器（trivy-operator）生命周期状态
type KubeScannerState string

const (
	ScannerStateNotInstalled KubeScannerState = "not_installed"
	ScannerStateInstalling   KubeScannerState = "installing"
	ScannerStateReady        KubeScannerState = "ready"
	ScannerStateDegraded     KubeScannerState = "degraded"
	ScannerStateUninstalling KubeScannerState = "uninstalling"
)

// KubeScanner 每集群 trivy-operator 扫描器的状态机记录
type KubeScanner struct {
	TenantID        string           `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID              uint             `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ClusterID       uint             `gorm:"column:cluster_id;not null;uniqueIndex" json:"clusterId"`
	State           KubeScannerState `gorm:"column:state;type:varchar(20);default:'not_installed'" json:"state"`
	OperatorVersion string           `gorm:"column:operator_version;type:varchar(32)" json:"operatorVersion"`
	ImageRegistry   string           `gorm:"column:image_registry;type:varchar(255)" json:"imageRegistry"` // 镜像地址覆盖（air-gap 私有 registry），空=默认 ghcr.io
	WebhookEnabled  bool             `gorm:"column:webhook_enabled;type:tinyint(1);default:0" json:"webhookEnabled"`
	LastSyncAt      *LocalTime       `gorm:"column:last_sync_at;type:timestamp" json:"lastSyncAt"`
	LastReportCount int              `gorm:"column:last_report_count;default:0" json:"lastReportCount"`
	LastError       string           `gorm:"column:last_error;type:text" json:"lastError"`
	CreatedAt       LocalTime        `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt       LocalTime        `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (KubeScanner) TableName() string {
	return "kube_scanners"
}
