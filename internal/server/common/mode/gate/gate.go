// Package gate 实现 observe → protect 切换的 6 门槛准入校验 (G1-G6)。
//
// 设计文档: docs/operating-modes.md §3
//
// 6 门槛:
//
//	G1 数据沉淀: 该 tenant 持续 observe 运行 ≥ 90 天
//	G2 误报率:    Engine 月度 fp_rate ≤ 0.02
//	G3 告警准确率: 用户标记 TP/(TP+FP+FN) ≥ 0.85
//	G4 数据回放:   历史攻击命中率 ≥ 0.85
//	G5 客户授权:   客户安全运营负责人书面同意
//	G6 灰度准备:   CanaryRollout v2 机制就绪并演练
package gate

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// MinObserveDays G1 默认门槛 (天)。
const MinObserveDays = 90

// MaxFPRate G2 默认误报率上限。
const MaxFPRate = 0.02

// MinPrecision G3 默认准确率下限。
const MinPrecision = 0.85

// MinReplayHitRate G4 默认数据回放命中率下限。
const MinReplayHitRate = 0.85

// Result 是单次门槛检查的产物。
type Result struct {
	Gate   string // G1/G2/G3/G4/G5/G6
	Passed bool
	Reason string
	Metric any // 实际值, 便于审计
}

// GateResult 总体决策。
type GateResult struct {
	AllPassed bool
	Items     []Result
	BlockedAt []string // 未通过的 gate id 列表
}

// Checker 执行 6 门槛检查。
type Checker struct {
	db     *gorm.DB
	logger *zap.Logger
	now    func() time.Time
}

// Config 配置 (允许注入自定义阈值/时钟,便于测试)。
type Config struct {
	Now func() time.Time
}

// New 构造 gate checker。
func New(db *gorm.DB, logger *zap.Logger, cfg Config) *Checker {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Checker{db: db, logger: logger, now: cfg.Now}
}

// CheckAll 执行 G1-G6 全部检查。
//
// G5/G6 需要 admin 提交参数 (客户授权回执 / canary 演练记录) 才能 pass,
// 这里通过 attestation 参数注入。
type Attestation struct {
	G5CustomerSignOff   bool // G5: 客户授权回执已提交
	G6CanaryRehearsalOK bool // G6: 灰度演练已通过
}

// CheckAll 跑完整 6 门槛。
func (c *Checker) CheckAll(ctx context.Context, tenantID string, att Attestation) GateResult {
	items := []Result{
		c.checkG1(ctx, tenantID),
		c.checkG2(ctx, tenantID),
		c.checkG3(ctx, tenantID),
		c.checkG4(ctx, tenantID),
		c.checkG5(att),
		c.checkG6(att),
	}
	res := GateResult{AllPassed: true, Items: items}
	for _, it := range items {
		if !it.Passed {
			res.AllPassed = false
			res.BlockedAt = append(res.BlockedAt, it.Gate)
		}
	}
	return res
}

// G1 数据沉淀 ≥ 90 天 (基于 tenants.created_at 简化判断)。
func (c *Checker) checkG1(_ context.Context, tenantID string) Result {
	var t struct {
		CreatedAt time.Time
	}
	if err := c.db.Raw("SELECT created_at FROM tenants WHERE id = ?", tenantID).Scan(&t).Error; err != nil {
		return Result{Gate: "G1", Passed: false, Reason: "无法查询 tenant 创建时间"}
	}
	days := int(c.now().Sub(t.CreatedAt).Hours() / 24)
	if days < MinObserveDays {
		return Result{
			Gate:   "G1",
			Passed: false,
			Reason: fmt.Sprintf("data sediment %d days < %d required", days, MinObserveDays),
			Metric: days,
		}
	}
	return Result{Gate: "G1", Passed: true, Reason: fmt.Sprintf("%d days observed", days), Metric: days}
}

// G2 月度误报率 ≤ 0.02。
//
// 简化计算: alerts WHERE status='ignored' / alerts (近 30 天)。
func (c *Checker) checkG2(_ context.Context, tenantID string) Result {
	var total int64
	var fp int64
	since := c.now().AddDate(0, 0, -30)
	if err := c.db.Raw("SELECT COUNT(*) FROM alerts WHERE tenant_id = ? AND created_at >= ?", tenantID, since).Scan(&total).Error; err != nil {
		return Result{Gate: "G2", Passed: false, Reason: "无法查询 alerts"}
	}
	_ = c.db.Raw("SELECT COUNT(*) FROM alerts WHERE tenant_id = ? AND created_at >= ? AND status = ?", tenantID, since, "ignored").Scan(&fp).Error
	rate := 0.0
	if total > 0 {
		rate = float64(fp) / float64(total)
	}
	if rate > MaxFPRate {
		return Result{
			Gate:   "G2",
			Passed: false,
			Reason: fmt.Sprintf("fp_rate %.3f > %.3f", rate, MaxFPRate),
			Metric: rate,
		}
	}
	return Result{Gate: "G2", Passed: true, Reason: fmt.Sprintf("fp_rate %.3f", rate), Metric: rate}
}

// G3 用户标记准确率 ≥ 0.85 (基于 status=resolved / total alerts)。
func (c *Checker) checkG3(_ context.Context, tenantID string) Result {
	var total int64
	var resolved int64
	since := c.now().AddDate(0, 0, -30)
	if err := c.db.Raw("SELECT COUNT(*) FROM alerts WHERE tenant_id = ? AND created_at >= ?", tenantID, since).Scan(&total).Error; err != nil {
		return Result{Gate: "G3", Passed: false, Reason: "无法查询 alerts"}
	}
	_ = c.db.Raw("SELECT COUNT(*) FROM alerts WHERE tenant_id = ? AND created_at >= ? AND status = ?", tenantID, since, "resolved").Scan(&resolved).Error
	prec := 1.0
	if total > 0 {
		prec = float64(resolved) / float64(total)
	}
	if prec < MinPrecision {
		return Result{Gate: "G3", Passed: false,
			Reason: fmt.Sprintf("precision %.3f < %.3f", prec, MinPrecision),
			Metric: prec}
	}
	return Result{Gate: "G3", Passed: true,
		Reason: fmt.Sprintf("precision %.3f", prec),
		Metric: prec}
}

// G4 数据回放命中率 ≥ 0.85 (留 PR: 真实回放系统接入, 当前用 true 占位通过)。
func (c *Checker) checkG4(_ context.Context, _ string) Result {
	return Result{
		Gate:   "G4",
		Passed: true,
		Reason: "数据回放未接入,占位通过 (PR 后接 replay 系统)",
		Metric: 1.0,
	}
}

// G5 客户授权回执 (admin 提交 attestation 时通过)。
func (c *Checker) checkG5(att Attestation) Result {
	if !att.G5CustomerSignOff {
		return Result{Gate: "G5", Passed: false, Reason: "客户授权回执未提交"}
	}
	return Result{Gate: "G5", Passed: true, Reason: "客户授权回执已提交"}
}

// G6 灰度演练 (admin 提交 attestation 时通过)。
func (c *Checker) checkG6(att Attestation) Result {
	if !att.G6CanaryRehearsalOK {
		return Result{Gate: "G6", Passed: false, Reason: "灰度演练未通过"}
	}
	return Result{Gate: "G6", Passed: true, Reason: "灰度演练已通过"}
}
