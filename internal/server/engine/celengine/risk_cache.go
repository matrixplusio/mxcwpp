package celengine

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// assetWeightReloadInterval 资产权重快照刷新周期。主机 criticality 极少变更，
	// 10min 延迟无碍风险打分（打分本为模糊加权）。
	assetWeightReloadInterval = 10 * time.Minute
	// correlationReloadInterval 关联度快照刷新周期。反映同主机近 1h 多类活跃告警，
	// 1min 刷新对攻击链关联升级的时效足够（IOA 是趋势信号，非精确计数）。
	correlationReloadInterval = 1 * time.Minute
	// correlationWindow 关联度统计窗口：同主机近此时长内活跃告警跨越的 category 数。
	correlationWindow = time.Hour
)

// reloadAssetWeightCache 全量加载主机 criticality → 资产权重，原子替换快照。
//
// 替代 assetWeight 每事件一次 `SELECT criticality FROM hosts WHERE host_id=?`：高事件量
// （IOC 扫描 / sshd fork 风暴）下该查询达数千次/秒，打满 MySQL 连接池，engine goroutine
// 全阻塞在 DB 上 → CPU 飙高。criticality 极少变更，全量缓存后热路径零 DB。
// 失败保留旧快照（宁可用旧权重也不中断打分）。
func (g *AlertGenerator) reloadAssetWeightCache() {
	var rows []struct {
		HostID      string
		Criticality string
	}
	if err := g.db.Model(&model.Host{}).Select("host_id, criticality").Scan(&rows).Error; err != nil {
		g.log.Warn("加载资产权重快照失败，保留旧快照", zap.Error(err))
		return
	}
	m := make(map[string]float64, len(rows))
	for _, r := range rows {
		m[r.HostID] = weightFromCriticality(r.Criticality)
	}
	g.assetWeightCache.Store(&m)
}

// weightFromCriticality 资产关键性 → 权重（语义与原 assetWeight 一致）。
func weightFromCriticality(criticality string) float64 {
	switch criticality {
	case "critical":
		return 1.3
	case "high":
		return 1.15
	case "low":
		return 0.8
	default: // normal / 空
		return 1.0
	}
}

// reloadCorrelationBoostCache 单条聚合查询加载所有主机近 1h 活跃告警跨越的 category 数，
// 算成关联加权后原子替换快照。
//
// 替代 correlationBoost 每事件一次 `SELECT COUNT(DISTINCT category) ... WHERE host_id=?`
// （无复合索引全扫，实测数百 ms）。关联度是趋势信号，1min 快照足够。失败保留旧快照。
func (g *AlertGenerator) reloadCorrelationBoostCache() {
	since := time.Now().Add(-correlationWindow)
	var rows []struct {
		HostID string
		Cnt    int64
	}
	if err := g.db.Model(&model.Alert{}).
		Select("host_id, COUNT(DISTINCT category) AS cnt").
		Where("status = ? AND last_seen_at >= ?", model.AlertStatusActive, since).
		Group("host_id").
		Scan(&rows).Error; err != nil {
		g.log.Warn("加载关联度快照失败，保留旧快照", zap.Error(err))
		return
	}
	m := make(map[string]float64, len(rows))
	for _, r := range rows {
		m[r.HostID] = boostFromCategoryCount(r.Cnt)
	}
	g.correlationBoostCache.Store(&m)
}

// boostFromCategoryCount 同主机活跃告警 category 数 → 关联加权（语义与原 correlationBoost 一致）。
func boostFromCategoryCount(n int64) float64 {
	switch {
	case n >= 3:
		return 1.5
	case n >= 2:
		return 1.2
	default:
		return 1.0
	}
}

// StartRiskCacheReload 启动后台 goroutine 周期刷新资产权重 / 关联度快照（ctx 取消时退出）。
// 调用方需保证只调用一次。
func (g *AlertGenerator) StartRiskCacheReload(ctx context.Context) {
	if g == nil {
		return
	}
	go func() {
		assetTicker := time.NewTicker(assetWeightReloadInterval)
		corrTicker := time.NewTicker(correlationReloadInterval)
		defer assetTicker.Stop()
		defer corrTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-assetTicker.C:
				g.reloadAssetWeightCache()
			case <-corrTicker.C:
				g.reloadCorrelationBoostCache()
				// 异常分与关联加权同频刷新：两者都是分钟级变化的排序输入，
				// 各自起一个 ticker 只是多一份定时器开销。
				g.reloadMLRankCache()
			}
		}
	}()
}
