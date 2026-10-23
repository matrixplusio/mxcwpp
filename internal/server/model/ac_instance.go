package model

// ACInstanceRecord 一台 AgentCenter 实例的管理地址，由各实例周期写入。
//
// 多台 AC 时，推送调度器在一台上跑，目标 agent 却可能连在另一台：按 hosts.ac_instance
// 找到所属实例，再按这里的地址把命令转过去。放 MySQL 而不是 Redis：AC 本来就共用这个库，
// 不必为此给 AC 增加一个依赖。
type ACInstanceRecord struct {
	TenantID   string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	InstanceID string    `gorm:"column:instance_id;type:varchar(64);primaryKey" json:"instance_id"`
	HTTPAddr   string    `gorm:"column:http_addr;type:varchar(255);not null" json:"http_addr"`
	UpdatedAt  LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (ACInstanceRecord) TableName() string { return "ac_instances" }
