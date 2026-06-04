package model

// FeatureFlag 控制数据源路由（mysql / ch）、灰度功能开关等运行时配置。
//
// 当前用途：表数据存储位置路由（MySQL → CH 迁移期）。
// Key 命名: data_source.{table_name} → "mysql" | "ch" | "ch_with_mysql_fallback"
//
// 设计原则：
//   - 由 manager admin API 写入；consumer / manager 周期 reload 内存缓存
//   - 默认值在代码侧 hardcode，DB 缺失时 fallback
//   - 修改记审计日志（who/when/from/to）
type FeatureFlag struct {
	ID          uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Key         string    `gorm:"column:flag_key;type:varchar(128);uniqueIndex;not null" json:"key"`
	Value       string    `gorm:"column:value;type:varchar(255);not null" json:"value"`
	DefaultVal  string    `gorm:"column:default_value;type:varchar(255)" json:"default_value"`
	Description string    `gorm:"column:description;type:text" json:"description"`
	UpdatedBy   string    `gorm:"column:updated_by;type:varchar(100)" json:"updated_by"`
	UpdatedAt   LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
	CreatedAt   LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 指定表名
func (FeatureFlag) TableName() string {
	return "feature_flags"
}

// FeatureFlagKeys 集中定义已知 key 常量，避免散落 magic string。
const (
	FlagDataSourceStorylineEvents = "data_source.storyline_events"
	FlagDataSourceHostMetrics     = "data_source.host_metrics"
	FlagDataSourceAuditLog        = "data_source.audit_log"
	FlagDataSourceProcesses       = "data_source.processes"
	FlagDataSourcePorts           = "data_source.ports"
	FlagDataSourceServices        = "data_source.services"
	FlagDataSourceKernelModules   = "data_source.kernel_modules"
)

// FeatureFlagSeed 启动时 AutoMigrate 后 seed 的默认值。
// 已存在的 key 不覆盖，仅插入新 key。
type FeatureFlagSeed struct {
	Key         string
	Default     string
	Description string
}

// DefaultFeatureFlags 列出所有内置 flag 及其默认值。
var DefaultFeatureFlags = []FeatureFlagSeed{
	{FlagDataSourceStorylineEvents, "mysql", "storyline_events 表数据源 (mysql/ch)，CH 迁移试点"},
	{FlagDataSourceHostMetrics, "mysql", "host_metrics 表数据源（待修双写错配）"},
	{FlagDataSourceAuditLog, "mysql", "audit_log 表数据源（CH 表已建待启用）"},
	{FlagDataSourceProcesses, "mysql", "processes 资产快照数据源"},
	{FlagDataSourcePorts, "mysql", "ports 资产快照数据源"},
	{FlagDataSourceServices, "mysql", "services 资产快照数据源"},
	{FlagDataSourceKernelModules, "mysql", "kernel_modules 资产快照数据源"},
}
