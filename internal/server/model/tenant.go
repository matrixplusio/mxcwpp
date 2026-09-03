// Package model 提供数据库模型定义
package model

// TenantType 租户类型
type TenantType string

const (
	TenantTypeStandalone TenantType = "standalone"  // 独立租户
	TenantTypeMSSPParent TenantType = "mssp_parent" // MSSP 父租户
	TenantTypeMSSPChild  TenantType = "mssp_child"  // MSSP 子租户
	TenantTypeInternal   TenantType = "internal"    // 内部租户
)

// TenantStatus 租户状态
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// TenantMode 运行模式
type TenantMode string

const (
	TenantModeObserve TenantMode = "observe" // 监听模式（默认）
	TenantModeProtect TenantMode = "protect" // 防护模式（磨合达标后切）
)

// IsolationStrategy 多租户物理隔离策略
type IsolationStrategy string

const (
	IsolationShared    IsolationStrategy = "shared" // 共库共表 + tenant_id（默认）
	IsolationSchema    IsolationStrategy = "schema" // 独立 schema
	IsolationDedicated IsolationStrategy = "db"     // 独立 DB 实例
)

// DefaultTenantID 默认租户 ID。v1.x 升级到 v2.0 时，所有历史数据归属此租户。
const DefaultTenantID = "t-default"

// Tenant 租户
type Tenant struct {
	ID                  string            `gorm:"column:id;type:varchar(64);primaryKey" json:"id"`
	Name                string            `gorm:"column:name;type:varchar(255);not null" json:"name"`
	Type                TenantType        `gorm:"column:type;type:varchar(32);not null;default:'standalone'" json:"type"`
	ParentID            *string           `gorm:"column:parent_id;type:varchar(64);index" json:"parent_id,omitempty"`
	Status              TenantStatus      `gorm:"column:status;type:varchar(32);not null;default:'active'" json:"status"`
	DefaultMode         TenantMode        `gorm:"column:default_mode;type:varchar(32);not null;default:'observe'" json:"default_mode"`
	MLEnabled           bool              `gorm:"column:ml_enabled;type:tinyint(1);default:1" json:"ml_enabled"`
	LLMEnabled          bool              `gorm:"column:llm_enabled;type:tinyint(1);default:0" json:"llm_enabled"`
	LLMProvider         string            `gorm:"column:llm_provider;type:text" json:"llm_provider,omitempty"` // JSON, 见 docs/llmproxy-design.md
	QuotaAgents         int               `gorm:"column:quota_agents;type:int;default:100" json:"quota_agents"`
	QuotaLLMUSD         float64           `gorm:"column:quota_llm_usd;type:decimal(10,2);default:100.00" json:"quota_llm_usd"`
	QuotaEventsDay      int64             `gorm:"column:quota_events_per_day;type:bigint;default:1000000000" json:"quota_events_per_day"`
	RetentionAlertsDays int               `gorm:"column:retention_alerts_days;type:int;default:90" json:"retention_alerts_days"`
	RetentionEventsDays int               `gorm:"column:retention_events_days;type:int;default:30" json:"retention_events_days"`
	RetentionAuditDays  int               `gorm:"column:retention_audit_days;type:int;default:180" json:"retention_audit_days"`
	IsolationStrategy   IsolationStrategy `gorm:"column:isolation_strategy;type:varchar(32);default:'shared'" json:"isolation_strategy"`
	IsolatedDBDSN       string            `gorm:"column:isolated_db_dsn;type:varchar(512)" json:"-"` // 不返回前端
	CreatedAt           LocalTime         `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt           LocalTime         `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (Tenant) TableName() string {
	return "tenants"
}

// TenantConfig 租户级配置覆盖
//
// 配置层级（详见 docs/multi-tenant.md §7.3）：规则级 > 主机标签级 > 租户级 > 全局默认
//
// Key 命名规范：使用点分路径，例如 mode.default / ml.enabled / llm.provider / retention.alerts_days
type TenantConfig struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uk_tenant_key,priority:1" json:"tenant_id"`
	Key       string    `gorm:"column:config_key;type:varchar(255);not null;uniqueIndex:uk_tenant_key,priority:2" json:"key"`
	Value     string    `gorm:"column:config_value;type:text" json:"value"` // JSON 或字符串
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (TenantConfig) TableName() string {
	return "tenant_configs"
}
