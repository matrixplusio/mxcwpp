package model

import "time"

// IOCEntry 外部威胁情报持久化条目(替代原 Redis-only 24h TTL)。
//
// 设计目标:
//   - 扛断供:外部 feed 挂掉后 IOC 不随 Redis 24h 蒸发,用最后已知集继续检测。
//   - 溯源:记录来自哪个 feed、first_seen/last_seen,供研判与误报治理。
//   - 智能过期:按类型软过期(expires_at),而非一刀切 24h。每次 sync 命中即刷新 last_seen/expires_at。
//
// Redis/snapshot 降级为从本表派生的缓存。自有情报仍在 local_iocs(导出时与本表归一)。
type IOCEntry struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`

	IOCType string `gorm:"column:ioc_type;type:varchar(16);not null;uniqueIndex:uk_ioc_type_value,priority:1" json:"ioc_type"` // ip / domain / hash / url
	Value   string `gorm:"column:value;type:varchar(512);not null;uniqueIndex:uk_ioc_type_value,priority:2" json:"value"`
	Source  string `gorm:"column:source;type:varchar(64);not null;default:external" json:"source"` // feed 名称(如 abuse.ch Feodo IP)

	Severity  string     `gorm:"column:severity;type:varchar(16);default:high" json:"severity"`
	FirstSeen time.Time  `gorm:"column:first_seen" json:"first_seen"`       // 首次入库
	LastSeen  time.Time  `gorm:"column:last_seen;index" json:"last_seen"`   // 最近一次 sync 命中
	ExpiresAt *time.Time `gorm:"column:expires_at;index" json:"expires_at"` // 软过期(null=不过期);超期视为失效
	Enabled   bool       `gorm:"column:enabled;default:true;index" json:"enabled"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

// TableName 指定表名
func (IOCEntry) TableName() string {
	return "ioc_entries"
}

// IOCTypeTTL 按类型返回外部 IOC 软过期时长。
// IP/域名 rotate 快但仍持续数周;hash(恶意样本)近乎永久但需封顶;URL 钓鱼站短命。
func IOCTypeTTL(iocType string) time.Duration {
	switch iocType {
	case "ip":
		return 14 * 24 * time.Hour
	case "hash":
		return 180 * 24 * time.Hour
	case "url":
		return 30 * 24 * time.Hour
	case "domain":
		return 30 * 24 * time.Hour
	default:
		return 14 * 24 * time.Hour
	}
}
