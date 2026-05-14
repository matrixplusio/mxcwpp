package model

// FIMTask FIM 任务模型
type FIMTask struct {
	TaskID              string       `gorm:"primaryKey;column:task_id;type:varchar(64);not null" json:"task_id"`
	PolicyID            string       `gorm:"column:policy_id;type:varchar(64)" json:"policy_id"`
	Status              string       `gorm:"column:status;type:varchar(20);default:'pending'" json:"status"` // pending/running/completed/failed
	TargetType          string       `gorm:"column:target_type;type:varchar(20)" json:"target_type"`
	TargetConfig        TargetConfig `gorm:"column:target_config;type:json" json:"target_config"`
	DispatchedHostCount int          `gorm:"column:dispatched_host_count;type:int;default:0" json:"dispatched_host_count"`
	CompletedHostCount  int          `gorm:"column:completed_host_count;type:int;default:0" json:"completed_host_count"`
	TotalEvents         int          `gorm:"column:total_events;type:int;default:0" json:"total_events"`
	CreatedAt           LocalTime    `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	ExecutedAt          *LocalTime   `gorm:"column:executed_at;type:timestamp" json:"executed_at"`
	CompletedAt         *LocalTime   `gorm:"column:completed_at;type:timestamp" json:"completed_at"`
}

// TableName 指定表名
func (FIMTask) TableName() string {
	return "fim_tasks"
}

// FIMTaskHostStatus FIM 任务主机状态
type FIMTaskHostStatus struct {
	ID           uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	TaskID       string     `gorm:"column:task_id;type:varchar(64);not null;index:idx_fim_ths_task_id" json:"task_id"`
	HostID       string     `gorm:"column:host_id;type:varchar(64);not null;index:idx_fim_ths_host_id" json:"host_id"`
	Hostname     string     `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	Status       string     `gorm:"column:status;type:varchar(20);default:'dispatched'" json:"status"` // dispatched/completed/timeout/failed
	TotalEntries int        `gorm:"column:total_entries;type:int;default:0" json:"total_entries"`
	AddedCount   int        `gorm:"column:added_count;type:int;default:0" json:"added_count"`
	RemovedCount int        `gorm:"column:removed_count;type:int;default:0" json:"removed_count"`
	ChangedCount int        `gorm:"column:changed_count;type:int;default:0" json:"changed_count"`
	RunTimeSec   int        `gorm:"column:run_time_sec;type:int;default:0" json:"run_time_sec"`
	ErrorMessage string     `gorm:"column:error_message;type:text" json:"error_message"`
	DispatchedAt *LocalTime `gorm:"column:dispatched_at;type:timestamp" json:"dispatched_at"`
	CompletedAt  *LocalTime `gorm:"column:completed_at;type:timestamp" json:"completed_at"`
}

// TableName 指定表名
func (FIMTaskHostStatus) TableName() string {
	return "fim_task_host_status"
}
