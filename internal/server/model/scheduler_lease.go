package model

// SchedulerLease 多实例间的调度租约：同名调度器同一时刻只在持有者上运行。
type SchedulerLease struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	Name      string    `gorm:"column:name;type:varchar(64);primaryKey" json:"name"`
	Holder    string    `gorm:"column:holder;type:varchar(64);not null" json:"holder"`
	ExpiresAt LocalTime `gorm:"column:expires_at;type:timestamp;not null" json:"expires_at"`
}

// TableName 指定表名
func (SchedulerLease) TableName() string { return "scheduler_leases" }
