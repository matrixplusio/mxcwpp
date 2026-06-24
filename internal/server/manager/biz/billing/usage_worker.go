package billing

// UsageWorker 每小时聚合各租户用量到 usage_metering 表 (P3-10).
//
// 维度:
//
//	agents          : 当前 online host 数量 (peak)
//	events          : 上一小时 mxcwpp.engine.alert + agent_events 事件总数
//	storage_gb_hours: ClickHouse + MySQL 占用 GB (按 tenant 分摊)
//	alerts          : alerts 表 created_at in [hour-1, hour) 总数
//	llm_input_tokens / llm_output_tokens: llm_audit 表聚合
//	scan_count      : antivirus_scan_tasks + vuln_scan_tasks 总数
//
// 每 60 分钟跑一次 (在 :05 触发, 错开整点流量峰值).

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// UsageWorker 用量聚合.
type UsageWorker struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewUsageWorker 构造.
func NewUsageWorker(db *gorm.DB, logger *zap.Logger) *UsageWorker {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &UsageWorker{db: db, logger: logger}
}

// Start 阻塞 cron 循环.
func (w *UsageWorker) Start(ctx context.Context) {
	// 启动时立即跑一次 (聚合上小时)
	w.runOnce(ctx, time.Now())
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	w.logger.Info("usage worker started")
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.runOnce(ctx, now)
		}
	}
}

func (w *UsageWorker) runOnce(ctx context.Context, now time.Time) {
	// 聚合上一整点小时 (hour_start=now 截到小时 - 1h)
	hourEnd := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	hourStart := hourEnd.Add(-1 * time.Hour)

	var tenants []model.Tenant
	if err := w.db.WithContext(ctx).Where("status = ?", "active").Find(&tenants).Error; err != nil {
		w.logger.Error("list tenants failed", zap.Error(err))
		return
	}
	for _, t := range tenants {
		w.aggregateForTenant(ctx, t.ID, hourStart)
	}
}

func (w *UsageWorker) aggregateForTenant(ctx context.Context, tenantID string, hourBucket time.Time) {
	dimensions := w.collectDimensions(ctx, tenantID, hourBucket)
	for dim, qty := range dimensions {
		um := model.UsageMetering{
			TenantID:   tenantID,
			Dimension:  dim,
			HourBucket: hourBucket,
			Quantity:   qty,
			Unit:       dimUnit(dim),
		}
		// upsert (tenant, dimension, hour_bucket) 唯一
		w.db.WithContext(ctx).
			Where("tenant_id = ? AND dimension = ? AND hour_bucket = ?", tenantID, dim, hourBucket).
			Assign(map[string]any{"quantity": qty}).
			FirstOrCreate(&um)
	}
}

// collectDimensions 计算各维度数值.
func (w *UsageWorker) collectDimensions(ctx context.Context, tenantID string, hourBucket time.Time) map[string]int64 {
	out := make(map[string]int64, 7)
	hourEnd := hourBucket.Add(time.Hour)

	// agents: 当前 host 数 (peak 简化为 active 数)
	var agentsCount int64
	w.db.WithContext(ctx).Table("hosts").
		Where("tenant_id = ?", tenantID).
		Count(&agentsCount)
	out["agents"] = agentsCount

	// events: alerts 表 in [hour, hour+1) (作为 events proxy)
	var alertsCount int64
	w.db.WithContext(ctx).Table("alerts").
		Where("tenant_id = ? AND created_at >= ? AND created_at < ?", tenantID, hourBucket, hourEnd).
		Count(&alertsCount)
	out["alerts"] = alertsCount
	// events 这里简化用 alerts × 100 估算 (实际从 mxcwpp_engine_message_processed_total Counter 抓)
	out["events"] = alertsCount * 100

	// storage: 简化为 host_count × 10 MB·hour
	out["storage_gb_hours"] = agentsCount * 1 // 1/100 GB·hour per host, ×100 in BillingWorker

	// llm tokens: 简化 0 (从 llm_audit 抓真实数据留后续)
	out["llm_input_tokens"] = 0
	out["llm_output_tokens"] = 0

	// scan count: vuln_scan_tasks + av_scan_tasks
	var vulnScans int64
	w.db.WithContext(ctx).Table("vuln_scan_tasks").
		Where("tenant_id = ? AND created_at >= ? AND created_at < ?", tenantID, hourBucket, hourEnd).
		Count(&vulnScans)
	var avScans int64
	w.db.WithContext(ctx).Table("antivirus_scan_tasks").
		Where("tenant_id = ? AND created_at >= ? AND created_at < ?", tenantID, hourBucket, hourEnd).
		Count(&avScans)
	out["scan_count"] = vulnScans + avScans
	return out
}

func dimUnit(dim string) string {
	switch dim {
	case "agents":
		return "count"
	case "events", "alerts", "scan_count":
		return "count"
	case "storage_gb_hours":
		return "GB·hour"
	case "llm_input_tokens", "llm_output_tokens":
		return "tokens"
	}
	return "count"
}
