package model

// ScheduledJob 是一个后台定时任务的排期与最近一次执行情况。
//
// 排期存库而不是写在代码里，有两个原因：什么时候压数据库、什么时候打到主机，是运营决定，
// 不该要发版才能改；上次执行时间也必须落库——只记在内存里的话，进程每重启一次，
// 所有任务都从头计时，「启动即跑」的那些还会立刻再跑一轮。
type ScheduledJob struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	JobKey   string `gorm:"column:job_key;primaryKey;type:varchar(64)" json:"jobKey"`
	// IntervalHours 每隔几小时执行一次；StartHour 从几点开始算（0–23，服务端本地时间）。
	// 例：间隔 6、起始 1 → 01:00、07:00、13:00、19:00。
	IntervalHours int  `gorm:"column:interval_hours;type:int;not null" json:"intervalHours"`
	StartHour     int  `gorm:"column:start_hour;type:int;not null" json:"startHour"`
	Enabled       bool `gorm:"column:enabled;not null;default:true" json:"enabled"`

	LastRunAt      *LocalTime `gorm:"column:last_run_at;type:timestamp;null" json:"lastRunAt"`
	LastStatus     string     `gorm:"column:last_status;type:varchar(16)" json:"lastStatus"`
	LastError      string     `gorm:"column:last_error;type:varchar(500)" json:"lastError"`
	LastDurationMs int64      `gorm:"column:last_duration_ms;not null;default:0" json:"lastDurationMs"`
	// LastTrigger 最近一次是到点执行（schedule）还是有人点了立即执行（manual）。
	LastTrigger string `gorm:"column:last_trigger;type:varchar(16)" json:"lastTrigger"`

	UpdatedBy string    `gorm:"column:updated_by;type:varchar(64)" json:"updatedBy"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名。
func (ScheduledJob) TableName() string { return "scheduled_jobs" }

// 定时任务最近一次执行的状态。
const (
	JobStatusRunning     = "running"
	JobStatusOK          = "ok"
	JobStatusFailed      = "failed"
	JobStatusInterrupted = "interrupted" // 执行中进程退出

	JobTriggerSchedule = "schedule"
	JobTriggerManual   = "manual"
)

// JobKeyAlertDigest 未处理告警日报。它由通知分发器自己发，只从这张表读开始时刻。
const JobKeyAlertDigest = "alert_digest"

// DefaultAlertDigestHour 日报的默认发送时刻。
const DefaultAlertDigestHour = 9

// ScheduledJobIntervals 允许的执行间隔（小时）。
// 一天以内的取 24 的约数，这样每天的执行时刻固定；更长的取整天。
var ScheduledJobIntervals = []int{1, 2, 3, 4, 6, 8, 12, 24, 48, 72, 168}

// ValidScheduledJobInterval 判断间隔是否在允许范围内。
func ValidScheduledJobInterval(h int) bool {
	for _, v := range ScheduledJobIntervals {
		if v == h {
			return true
		}
	}
	return false
}
