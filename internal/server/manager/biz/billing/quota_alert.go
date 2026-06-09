// Package billing — 配额 80% 预警 worker (B4).
//
// 每小时跑一次, 对每个租户:
//
//  1. 查 tenants.quota_agents 上限
//  2. 查实际 hosts 数 (online + offline)
//  3. 若 >= 80% 且未在 24h 内告警过 → 产 alert
//  4. 若 >= 100% → critical alert
//
// alert 入 alerts 表, 走标准 alert 生命周期; 同时落 outbound (webhook/syslog).
package billing

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// QuotaAlertWorker 配额预警 worker.
type QuotaAlertWorker struct {
	db       *gorm.DB
	logger   *zap.Logger
	interval time.Duration
	cooldown time.Duration // 同租户同维度告警间隔
}

// NewQuotaAlertWorker 构造.
func NewQuotaAlertWorker(db *gorm.DB, logger *zap.Logger) *QuotaAlertWorker {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &QuotaAlertWorker{
		db:       db,
		logger:   logger,
		interval: 1 * time.Hour,
		cooldown: 24 * time.Hour,
	}
}

// Start 阻塞循环.
func (w *QuotaAlertWorker) Start(ctx context.Context) {
	w.logger.Info("quota alert worker started",
		zap.Duration("interval", w.interval),
		zap.Duration("cooldown", w.cooldown))
	w.runOnce(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.runOnce(ctx)
		}
	}
}

func (w *QuotaAlertWorker) runOnce(ctx context.Context) {
	var tenants []model.Tenant
	if err := w.db.WithContext(ctx).
		Where("status = ?", "active").
		Find(&tenants).Error; err != nil {
		w.logger.Warn("query tenants failed", zap.Error(err))
		return
	}
	for i := range tenants {
		w.checkTenant(ctx, &tenants[i])
	}
}

func (w *QuotaAlertWorker) checkTenant(ctx context.Context, t *model.Tenant) {
	if t.QuotaAgents <= 0 {
		return
	}
	var used int64
	if err := w.db.WithContext(ctx).
		Table("hosts").
		Where("tenant_id = ?", t.ID).
		Count(&used).Error; err != nil {
		return
	}
	pct := float64(used) / float64(t.QuotaAgents) * 100
	var severity, category string
	switch {
	case pct >= 100:
		severity, category = "critical", "quota_exceeded"
	case pct >= 80:
		severity, category = "high", "quota_warning"
	default:
		return
	}

	// cooldown: 24h 内同租户同维度不重复
	if w.recentlyAlerted(ctx, t.ID, category) {
		return
	}
	alert := &model.Alert{
		TenantID:    t.ID,
		Severity:    severity,
		Category:    category,
		Status:      "open",
		Source:      "quota_alert_worker",
		Title:       fmt.Sprintf("租户 %s 主机配额 %.1f%% (%d/%d)", t.ID, pct, used, t.QuotaAgents),
		Description: fmt.Sprintf("租户 %s (%s) 已用 %d 台主机, 配额 %d, 占用率 %.1f%%", t.ID, t.Name, used, t.QuotaAgents, pct),
		CreatedAt:   model.LocalTime(time.Now()),
	}
	if err := w.db.WithContext(ctx).Create(alert).Error; err != nil {
		w.logger.Warn("create quota alert failed",
			zap.String("tenant_id", t.ID),
			zap.Error(err))
		return
	}
	w.logger.Info("quota alert created",
		zap.String("tenant_id", t.ID),
		zap.String("severity", severity),
		zap.Float64("pct", pct))
}

func (w *QuotaAlertWorker) recentlyAlerted(ctx context.Context, tenantID, category string) bool {
	var n int64
	since := time.Now().Add(-w.cooldown)
	_ = w.db.WithContext(ctx).
		Table("alerts").
		Where("tenant_id = ? AND category = ? AND source = ? AND created_at >= ?",
			tenantID, category, "quota_alert_worker", since).
		Count(&n).Error
	return n > 0
}
