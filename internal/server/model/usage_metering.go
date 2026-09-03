package model

import "time"

// UsageMetering 单租户单计费维度的用量记录 (P2-11)。
//
// 每小时 worker 聚合各维度数据 → 写入本表 (1 行/(tenant, dimension, hour)):
//
//	agents          — 同时连接的 Agent 数 (峰值)
//	events          — 上报事件总数
//	storage_gb      — DB + CH 占用 (按租户分摊)
//	alerts          — 产出 Alert 总数
//	llm_input_tokens — LLM 输入 token
//	llm_output_tokens
//	scan_count      — av-scanner / vuln 扫描次数
//
// 月底 BillingWorker 聚合 → MonthlyBill。
type UsageMetering struct {
	TenantID   string    `gorm:"column:tenant_id;type:varchar(64);not null;uniqueIndex:uk_tenant_dim_hour,priority:1" json:"tenant_id"`
	Dimension  string    `gorm:"column:dimension;type:varchar(64);not null;uniqueIndex:uk_tenant_dim_hour,priority:2" json:"dimension"`
	HourBucket time.Time `gorm:"column:hour_bucket;type:timestamp;not null;uniqueIndex:uk_tenant_dim_hour,priority:3" json:"hour_bucket"`
	Quantity   int64     `gorm:"column:quantity;type:bigint;not null;default:0" json:"quantity"`
	Unit       string    `gorm:"column:unit;type:varchar(32);not null" json:"unit"` // count / bytes / tokens / GB·hour
	CreatedAt  LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName.
func (UsageMetering) TableName() string { return "usage_metering" }

// MonthlyBill 月度账单。
//
// BillingWorker 每月 1 号凌晨生成上月账单 (status=draft),
// 财务对账 → status=approved → 发送给客户 → status=billed → 付款 → status=paid。
type MonthlyBill struct {
	TenantID        string  `gorm:"column:tenant_id;type:varchar(64);not null;index" json:"tenant_id"`
	ID              uint    `gorm:"primaryKey;autoIncrement" json:"id"`
	BillingMonth    string  `gorm:"column:billing_month;type:varchar(7);not null;index;uniqueIndex:uk_tenant_month,priority:2" json:"billing_month"` // 2026-06
	TenantUnique    string  `gorm:"column:tenant_unique;type:varchar(64);not null;uniqueIndex:uk_tenant_month,priority:1" json:"tenant_unique"`      // = tenant_id
	AgentsPeak      int64   `gorm:"column:agents_peak" json:"agents_peak"`
	EventsTotal     int64   `gorm:"column:events_total" json:"events_total"`
	StorageGBHours  float64 `gorm:"column:storage_gb_hours;type:decimal(18,4)" json:"storage_gb_hours"`
	AlertsTotal     int64   `gorm:"column:alerts_total" json:"alerts_total"`
	LLMInputTokens  int64   `gorm:"column:llm_input_tokens" json:"llm_input_tokens"`
	LLMOutputTokens int64   `gorm:"column:llm_output_tokens" json:"llm_output_tokens"`
	ScanCount       int64   `gorm:"column:scan_count" json:"scan_count"`

	// 计费
	TotalUSD      float64 `gorm:"column:total_usd;type:decimal(10,2)" json:"total_usd"`
	Currency      string  `gorm:"column:currency;type:varchar(8);default:'USD'" json:"currency"`
	BreakdownJSON string  `gorm:"column:breakdown;type:text" json:"breakdown"` // JSON 拆分: {agents:..., events:..., llm:...}

	Status    string    `gorm:"column:status;type:varchar(16);default:'draft';index" json:"status"` // draft / approved / billed / paid / cancelled
	IssuedAt  LocalTime `gorm:"column:issued_at;type:timestamp" json:"issued_at"`
	PaidAt    LocalTime `gorm:"column:paid_at;type:timestamp" json:"paid_at"`
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName.
func (MonthlyBill) TableName() string { return "monthly_bills" }
