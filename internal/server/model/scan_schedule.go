package model

// ScanSchedule 漏洞扫描调度配置
type ScanSchedule struct {
	TenantID  string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name      string     `gorm:"column:name;type:varchar(100);not null" json:"name"`
	ScanType  string     `gorm:"column:scan_type;type:varchar(20);not null" json:"scanType"` // full_scan / incremental_scan / sync_only
	CronExpr  string     `gorm:"column:cron_expr;type:varchar(50);not null" json:"cronExpr"`
	Enabled   bool       `gorm:"column:enabled;default:true" json:"enabled"`
	LastRunAt *LocalTime `gorm:"column:last_run_at;type:timestamp" json:"lastRunAt"`
	NextRunAt *LocalTime `gorm:"column:next_run_at;type:timestamp" json:"nextRunAt"`
	CreatedBy string     `gorm:"column:created_by;type:varchar(64)" json:"createdBy"`
	CreatedAt LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (ScanSchedule) TableName() string {
	return "scan_schedules"
}

// ScanScheduleExecution 扫描计划执行记录
type ScanScheduleExecution struct {
	TenantID   string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ScheduleID uint       `gorm:"column:schedule_id;not null;index" json:"scheduleId"`
	ScanType   string     `gorm:"column:scan_type;type:varchar(20);not null" json:"scanType"`            // full_scan / incremental_scan / sync_only
	Status     string     `gorm:"column:status;type:varchar(16);not null;default:running" json:"status"` // running / success / failed
	ErrorMsg   string     `gorm:"column:error_msg;type:text" json:"errorMsg"`
	Duration   int        `gorm:"column:duration" json:"duration"` // 秒
	StartedAt  LocalTime  `gorm:"column:started_at;type:timestamp;not null" json:"startedAt"`
	FinishedAt *LocalTime `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
}

// TableName 指定表名
func (ScanScheduleExecution) TableName() string {
	return "scan_schedule_executions"
}
