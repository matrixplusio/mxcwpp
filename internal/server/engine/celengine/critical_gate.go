package celengine

import (
	"context"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const criticalGateReloadInterval = time.Minute

// CriticalGate 决定一条规则的告警能不能落成 critical（见 model.RuleCriticalAdmission）。
//
// 只约束单条规则直接产生的告警。跨主机扫描、已确认攻击源连入这类由关联得出的告警
// 不经过这里：多个信号对上了才是 critical，这正是它们该有的级别。
type CriticalGate struct {
	db      *gorm.DB
	log     *zap.Logger
	allowed atomic.Pointer[map[string]struct{}]
}

// NewCriticalGate 构造并立即加载一次。db 为 nil 时返回 nil，调用方按「未启用」处理。
func NewCriticalGate(db *gorm.DB, logger *zap.Logger) *CriticalGate {
	if db == nil {
		return nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	g := &CriticalGate{db: db, log: logger}
	g.reload()
	return g
}

// StartReload 周期刷新准入快照。
func (g *CriticalGate) StartReload(ctx context.Context) {
	if g == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(criticalGateReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.reload()
			}
		}
	}()
}

func (g *CriticalGate) reload() {
	var rows []model.RuleCriticalAdmission
	if err := g.db.Find(&rows).Error; err != nil {
		// 读失败沿用上一份快照；从未读到过则保持未就绪（见 Cap）。
		g.log.Warn("critical 准入清单加载失败", zap.Error(err))
		return
	}
	if len(rows) == 0 {
		// 空表不是「没有规则被准入」，而是初始清单还没写进来（表刚建、manager 尚未升级）。
		// 初始清单至少含几条硬编码规则，写入之后表不会再变空。此时照空表执行会把所有
		// critical 一起压掉，所以按未就绪处理。
		g.log.Warn("critical 准入清单为空，暂不限制级别")
		return
	}
	snap := make(map[string]struct{}, len(rows))
	for i := range rows {
		if rows[i].Allowed {
			snap[rows[i].RuleID] = struct{}{}
		}
	}
	g.allowed.Store(&snap)
}

// Cap 返回该规则的告警实际应落的级别：未获准入的规则 critical 降为 high。
//
// 清单未就绪时原样返回。宁可暂时沿用规则声明的级别，也不在读不到清单时把真正的
// critical 压下去——后者是静默的，没人会发现。
func (g *CriticalGate) Cap(ruleID, severity string) string {
	if g == nil || severity != "critical" {
		return severity
	}
	snap := g.allowed.Load()
	if snap == nil {
		return severity
	}
	if _, ok := (*snap)[ruleID]; ok {
		return severity
	}
	return "high"
}
