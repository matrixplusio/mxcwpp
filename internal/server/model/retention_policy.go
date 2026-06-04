package model

// RetentionPolicy 定义 ClickHouse 各表的数据保留天数。
//
// 修改后管理端 API 立即下发 ALTER TABLE ... MODIFY TTL ...，
// 旧数据将在下次 MergeTree merge 时被清理。
//
// 字段约定:
//   - CHTable: CH 端实际表名（如 ebpf_events / storyline_events）
//   - RetentionDays 范围 1-3650
type RetentionPolicy struct {
	ID            uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	CHTable       string    `gorm:"column:ch_table;type:varchar(64);uniqueIndex;not null" json:"ch_table"`
	DisplayName   string    `gorm:"column:display_name;type:varchar(100);not null" json:"display_name"`
	Description   string    `gorm:"column:description;type:text" json:"description"`
	RetentionDays int       `gorm:"column:retention_days;not null;default:30" json:"retention_days"`
	UpdatedBy     string    `gorm:"column:updated_by;type:varchar(100)" json:"updated_by"`
	UpdatedAt     LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
	CreatedAt     LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 指定表名
func (RetentionPolicy) TableName() string {
	return "retention_policies"
}

// RetentionSeed AutoMigrate 后 seed 默认值。
type RetentionSeed struct {
	CHTable     string
	DisplayName string
	Description string
	Days        int
}

// DefaultRetentionPolicies 列出内置策略。
var DefaultRetentionPolicies = []RetentionSeed{
	{"ebpf_events", "EDR 事件", "agent ebpf 上报的进程/文件/网络/DNS 原始事件", 7},
	{"storyline_events", "攻击故事线事件", "EDR 关联生成的故事线事件流", 90},
	{"audit_log", "审计日志", "用户操作 / 管理动作审计（合规留存）", 180},
	{"alert_events", "告警事件流", "告警生命周期事件", 90},
	{"fim_events", "FIM 事件", "文件完整性监控变更事件", 30},
	{"scan_results_history", "漏洞扫描历史", "扫描任务历史结果", 90},
	{"host_metrics", "主机指标", "CPU / 内存 / 磁盘 / 网络时序", 30},
	{"host_metrics_hourly", "主机指标小时聚合", "host_metrics 物化视图小时维度", 365},
	{"processes_snapshots", "进程快照", "周期上报的进程清单", 30},
	{"ports_snapshots", "端口快照", "周期上报的监听端口清单", 30},
	{"services_snapshots", "服务快照", "systemd / init 服务清单", 30},
	{"kernel_modules_snapshots", "内核模块快照", "已加载内核模块清单", 30},
}
