package model

// IntelSyncSchedule 威胁情报同步计划（定时拉取 IOC Feed）
type IntelSyncSchedule struct {
	TenantID  string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name      string     `gorm:"column:name;type:varchar(100);not null" json:"name"`
	CronExpr  string     `gorm:"column:cron_expr;type:varchar(50);not null" json:"cronExpr"`
	Enabled   bool       `gorm:"column:enabled;default:true" json:"enabled"`
	LastRunAt *LocalTime `gorm:"column:last_run_at;type:timestamp" json:"lastRunAt"`
	NextRunAt *LocalTime `gorm:"column:next_run_at;type:timestamp" json:"nextRunAt"`
	CreatedBy string     `gorm:"column:created_by;type:varchar(64)" json:"createdBy"`
	CreatedAt LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (IntelSyncSchedule) TableName() string {
	return "intel_sync_schedules"
}

// IntelSyncExecution 情报同步计划执行记录
type IntelSyncExecution struct {
	TenantID   string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ScheduleID uint       `gorm:"column:schedule_id;not null;index" json:"scheduleId"`
	Status     string     `gorm:"column:status;type:varchar(16);not null;default:running" json:"status"` // running / success / failed
	ErrorMsg   string     `gorm:"column:error_msg;type:text" json:"errorMsg"`
	IOCCount   int64      `gorm:"column:ioc_count" json:"iocCount"` // 本次同步后 IOC 总数
	Duration   int        `gorm:"column:duration" json:"duration"`  // 秒
	StartedAt  LocalTime  `gorm:"column:started_at;type:timestamp;not null" json:"startedAt"`
	FinishedAt *LocalTime `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
}

// TableName 指定表名
func (IntelSyncExecution) TableName() string {
	return "intel_sync_executions"
}
