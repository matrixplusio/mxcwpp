package model

// HostAnomalyScore 是单台主机最近的异常分，用于给已有告警排序。
//
// 为什么要落表：异常检测跑在 consumer 进程，告警风险分算在 engine 进程，两者不共享内存。
// 与资产权重、关联加权走同一条路——写表 + 周期快照，热路径零 DB 查。
//
// **这张表只影响告警的排列顺序，不产生任何告警。** 分数高只说明这台主机最近的行为
// 与它自己的历史不同，不说明它被入侵了。
type HostAnomalyScore struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	HostID   string `gorm:"column:host_id;type:varchar(64);not null;uniqueIndex" json:"host_id"`
	// Score 最近一次异常评分，0.0~1.0。
	Score float64 `gorm:"column:score;type:double;not null;default:0" json:"score"`
	// ObservedAt 该分数对应的观测时间。过期分数不参与排序——
	// 一台主机上周异常不代表现在异常，拿旧分排序会让分析师一直盯着已经恢复正常的机器。
	ObservedAt LocalTime `gorm:"column:observed_at;type:timestamp;not null;index" json:"observed_at"`
	UpdatedAt  LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名。
func (HostAnomalyScore) TableName() string { return "host_anomaly_scores" }
