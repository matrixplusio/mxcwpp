// Package model 提供数据库模型定义
package model

// HostMetric 主机监控指标模型
type HostMetric struct {
	ID           uint64    `gorm:"primaryKey;column:id;type:bigint;autoIncrement" json:"id"`
	HostID       string    `gorm:"column:host_id;type:varchar(64);not null;index:idx_host_collected" json:"host_id"`
	CPUUsage     *float64  `gorm:"column:cpu_usage;type:decimal(5,2)" json:"cpu_usage"`
	MemUsage     *float64  `gorm:"column:mem_usage;type:decimal(5,2)" json:"mem_usage"`
	DiskUsage    *float64  `gorm:"column:disk_usage;type:decimal(5,2)" json:"disk_usage"`
	NetBytesSent *uint64   `gorm:"column:net_bytes_sent;type:bigint" json:"net_bytes_sent"`
	NetBytesRecv *uint64   `gorm:"column:net_bytes_recv;type:bigint" json:"net_bytes_recv"`
	CollectedAt  LocalTime `gorm:"column:collected_at;type:timestamp;not null;index:idx_host_collected;index:idx_collected_at" json:"collected_at"`
}

// TableName 指定表名
func (HostMetric) TableName() string {
	return "host_metrics"
}

// HostMetricHourly 主机监控指标聚合表（按小时）
type HostMetricHourly struct {
	ID                uint64    `gorm:"primaryKey;column:id;type:bigint;autoIncrement" json:"id"`
	HostID            string    `gorm:"column:host_id;type:varchar(64);not null;index:idx_host_hour" json:"host_id"`
	CPUUsageAvg       *float64  `gorm:"column:cpu_usage_avg;type:decimal(5,2)" json:"cpu_usage_avg"`
	CPUUsageMax       *float64  `gorm:"column:cpu_usage_max;type:decimal(5,2)" json:"cpu_usage_max"`
	MemUsageAvg       *float64  `gorm:"column:mem_usage_avg;type:decimal(5,2)" json:"mem_usage_avg"`
	MemUsageMax       *float64  `gorm:"column:mem_usage_max;type:decimal(5,2)" json:"mem_usage_max"`
	DiskUsageAvg      *float64  `gorm:"column:disk_usage_avg;type:decimal(5,2)" json:"disk_usage_avg"`
	NetBytesSentTotal *uint64   `gorm:"column:net_bytes_sent_total;type:bigint" json:"net_bytes_sent_total"`
	NetBytesRecvTotal *uint64   `gorm:"column:net_bytes_recv_total;type:bigint" json:"net_bytes_recv_total"`
	HourStart         LocalTime `gorm:"column:hour_start;type:timestamp;not null;index:idx_host_hour" json:"hour_start"`
}

// TableName 指定表名
func (HostMetricHourly) TableName() string {
	return "host_metrics_hourly"
}
