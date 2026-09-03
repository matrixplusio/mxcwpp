package model

// ScanJobStatus 扫描任务状态
type ScanJobStatus string

const (
	ScanJobPending ScanJobStatus = "pending"
	ScanJobRunning ScanJobStatus = "running"
	ScanJobDone    ScanJobStatus = "done"
	ScanJobFailed  ScanJobStatus = "failed"
)

// ScanJob 中心化镜像扫描任务（manager 入队，独立 scanner 服务消费）
type ScanJob struct {
	TenantID     string        `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint          `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Image        string        `gorm:"column:image;type:varchar(500);not null" json:"image"`
	Source       string        `gorm:"column:source;type:varchar(20);default:'manual'" json:"source"` // manual / registry / ci / scheduled
	RegistryID   *uint         `gorm:"column:registry_id;index" json:"registryId,omitempty"`
	ResultScanID uint          `gorm:"column:result_scan_id;index" json:"resultScanId"` // 关联的 image_scans 记录
	Status       ScanJobStatus `gorm:"column:status;type:varchar(20);default:'pending';index" json:"status"`
	Attempt      int           `gorm:"column:attempt;default:0" json:"attempt"`
	ErrorMsg     string        `gorm:"column:error_msg;type:text" json:"errorMsg"`
	ClaimedBy    string        `gorm:"column:claimed_by;type:varchar(100)" json:"claimedBy"`
	ClaimedAt    *LocalTime    `gorm:"column:claimed_at;type:timestamp" json:"claimedAt"`
	CreatedAt    LocalTime     `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    LocalTime     `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (ScanJob) TableName() string {
	return "scan_jobs"
}
