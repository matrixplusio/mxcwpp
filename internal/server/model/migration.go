package model

// MigrationJob MVP1 → MVP2 数据迁移任务
type MigrationJob struct {
	ID           uint        `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	SourceURL    string      `gorm:"column:source_url;type:varchar(255);not null" json:"source_url"`
	SourceUser   string      `gorm:"column:source_user;type:varchar(64);not null" json:"source_user"`
	Scope        StringArray `gorm:"column:scope;type:json" json:"scope"`
	Status       string      `gorm:"column:status;type:varchar(32);index;default:'pending'" json:"status"` // pending / running / completed / failed / cancelled
	Progress     int         `gorm:"column:progress;type:int;default:0" json:"progress"`                   // 0-100
	CurrentTable string      `gorm:"column:current_table;type:varchar(64)" json:"current_table"`
	TotalRecords int         `gorm:"column:total_records;type:int;default:0" json:"total_records"`
	CreatedCount int         `gorm:"column:created_count;type:int;default:0" json:"created_count"`
	SkippedCount int         `gorm:"column:skipped_count;type:int;default:0" json:"skipped_count"`
	FailedCount  int         `gorm:"column:failed_count;type:int;default:0" json:"failed_count"`
	Report       string      `gorm:"column:report;type:longtext" json:"report"`
	Error        string      `gorm:"column:error;type:text" json:"error"`
	OperatorID   uint        `gorm:"column:operator_id" json:"operator_id"`
	StartedAt    *LocalTime  `gorm:"column:started_at;type:timestamp" json:"started_at"`
	FinishedAt   *LocalTime  `gorm:"column:finished_at;type:timestamp" json:"finished_at"`
	CreatedAt    LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt    LocalTime   `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

func (MigrationJob) TableName() string {
	return "migration_jobs"
}
