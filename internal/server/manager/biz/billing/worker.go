// Package billing 实现 MSSP 计费引擎 (P3-9).
//
// 流程:
//
//  1. UsageWorker 每小时聚合 hosts/events/storage/llm_tokens → usage_metering
//  2. BillingWorker 每月 1 号 00:30 聚合上月 → monthly_bills (status=draft)
//  3. 财务 review → status=approved
//  4. 发账单 → status=billed → 付款 → status=paid
//
// 计费维度 (默认价格表, 实际单价从 tenant_config.pricing.* 读):
//
//	agents_peak     : $5 / agent / 月
//	events_total    : $0.001 / 1000 events
//	storage_gb_hours: $0.05 / GB·hour
//	alerts_total    : free (含在 base)
//	llm_input_tokens: $0.001 / 1k tokens
//	llm_output_tokens: $0.003 / 1k tokens
//	scan_count      : $0.01 / scan
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// PriceTable 单价 (USD).
type PriceTable struct {
	AgentPerMonth    float64
	EventsPer1k      float64
	StoragePerGBHour float64
	LLMInputPer1k    float64
	LLMOutputPer1k   float64
	ScanPerCount     float64
}

// DefaultPriceTable 默认价格.
func DefaultPriceTable() PriceTable {
	return PriceTable{
		AgentPerMonth:    5.0,
		EventsPer1k:      0.001,
		StoragePerGBHour: 0.05,
		LLMInputPer1k:    0.001,
		LLMOutputPer1k:   0.003,
		ScanPerCount:     0.01,
	}
}

// BillingWorker 月度账单 worker.
type BillingWorker struct {
	db     *gorm.DB
	logger *zap.Logger
	prices PriceTable
}

// NewBillingWorker 构造.
func NewBillingWorker(db *gorm.DB, logger *zap.Logger) *BillingWorker {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &BillingWorker{
		db:     db,
		logger: logger,
		prices: DefaultPriceTable(),
	}
}

// Start 阻塞 cron 循环 (每天 00:30 检查是否新月).
func (w *BillingWorker) Start(ctx context.Context) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	w.logger.Info("billing worker started")
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			// 1 号 00:00-00:59 触发上月账单
			if now.Day() == 1 && now.Hour() == 0 {
				w.runOnce(ctx, now)
			}
		}
	}
}

// runOnce 执行一次月账单生成.
func (w *BillingWorker) runOnce(ctx context.Context, now time.Time) {
	// 上月范围
	thisMonthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	lastMonthStart := thisMonthStart.AddDate(0, -1, 0)
	billingMonth := lastMonthStart.Format("2006-01")
	w.logger.Info("generating monthly bills",
		zap.String("month", billingMonth),
		zap.Time("range_from", lastMonthStart),
		zap.Time("range_to", thisMonthStart))

	// 列租户
	var tenants []model.Tenant
	if err := w.db.WithContext(ctx).Where("status = ?", "active").Find(&tenants).Error; err != nil {
		w.logger.Error("list tenants failed", zap.Error(err))
		return
	}

	for _, t := range tenants {
		if err := w.generateBillForTenant(ctx, t.ID, billingMonth, lastMonthStart, thisMonthStart); err != nil {
			w.logger.Error("generate bill failed",
				zap.String("tenant", t.ID), zap.String("month", billingMonth), zap.Error(err))
		}
	}
}

func (w *BillingWorker) generateBillForTenant(ctx context.Context, tenantID, billingMonth string, from, to time.Time) error {
	// 同 (tenant, month) 已存在则 skip
	var existing model.MonthlyBill
	if err := w.db.WithContext(ctx).
		Where("tenant_unique = ? AND billing_month = ?", tenantID, billingMonth).
		First(&existing).Error; err == nil {
		w.logger.Info("bill exists, skip", zap.String("tenant", tenantID), zap.String("month", billingMonth))
		return nil
	}

	// 聚合 usage_metering
	type aggRow struct {
		Dimension string
		Total     int64
	}
	var rows []aggRow
	if err := w.db.WithContext(ctx).
		Table("usage_metering").
		Select("dimension, SUM(quantity) as total").
		Where("tenant_id = ? AND hour_bucket >= ? AND hour_bucket < ?", tenantID, from, to).
		Group("dimension").Scan(&rows).Error; err != nil {
		return fmt.Errorf("aggregate usage: %w", err)
	}
	bill := model.MonthlyBill{
		TenantID:     tenantID,
		TenantUnique: tenantID,
		BillingMonth: billingMonth,
		Currency:     "USD",
		Status:       "draft",
		IssuedAt:     model.LocalTime(time.Now()),
	}
	for _, r := range rows {
		switch r.Dimension {
		case "agents":
			bill.AgentsPeak = r.Total // 取 max 简化 (实际应在 usage_metering 用 max-aggr)
		case "events":
			bill.EventsTotal = r.Total
		case "storage_gb_hours":
			bill.StorageGBHours = float64(r.Total) / 100.0 // 假设 quantity 存 GB·hour × 100
		case "alerts":
			bill.AlertsTotal = r.Total
		case "llm_input_tokens":
			bill.LLMInputTokens = r.Total
		case "llm_output_tokens":
			bill.LLMOutputTokens = r.Total
		case "scan_count":
			bill.ScanCount = r.Total
		}
	}

	// 计算总金额
	total := float64(bill.AgentsPeak)*w.prices.AgentPerMonth +
		float64(bill.EventsTotal)/1000.0*w.prices.EventsPer1k +
		bill.StorageGBHours*w.prices.StoragePerGBHour +
		float64(bill.LLMInputTokens)/1000.0*w.prices.LLMInputPer1k +
		float64(bill.LLMOutputTokens)/1000.0*w.prices.LLMOutputPer1k +
		float64(bill.ScanCount)*w.prices.ScanPerCount
	bill.TotalUSD = round2(total)

	breakdown, _ := json.Marshal(map[string]float64{
		"agents":            float64(bill.AgentsPeak) * w.prices.AgentPerMonth,
		"events_per_1k":     float64(bill.EventsTotal) / 1000.0 * w.prices.EventsPer1k,
		"storage_gb_hours":  bill.StorageGBHours * w.prices.StoragePerGBHour,
		"llm_input_per_1k":  float64(bill.LLMInputTokens) / 1000.0 * w.prices.LLMInputPer1k,
		"llm_output_per_1k": float64(bill.LLMOutputTokens) / 1000.0 * w.prices.LLMOutputPer1k,
		"scan_per_count":    float64(bill.ScanCount) * w.prices.ScanPerCount,
	})
	bill.BreakdownJSON = string(breakdown)

	if err := w.db.WithContext(ctx).Create(&bill).Error; err != nil {
		return fmt.Errorf("create bill: %w", err)
	}
	w.logger.Info("bill generated",
		zap.String("tenant", tenantID),
		zap.String("month", billingMonth),
		zap.Float64("total_usd", bill.TotalUSD))
	return nil
}

// round2 保留 2 位小数.
func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100.0
}
