package celengine

import (
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ML 异常分参与告警排序（ranking 档）。
//
// 异常检测跑在 consumer 进程，风险分算在 engine 进程，两者不共享内存，
// 因而经 host_anomaly_scores 表 + 周期快照传递——与资产权重、关联加权同一条路，
// 热路径零 DB 查。
//
// **边界**：ML 只在同一严重度带内重排，不跨带提升。
// 一条 medium 告警不会因为主机异常而变成 high——那是定罪，不是排序。
// 无监督异常检测给出的是"少见"而不是"恶意"，只配用来决定先看哪个。

const (
	// mlRankMaxBoost 异常分带来的最大加权。
	//
	// 1.15 是刻意压低的：severity 相邻两档的基础分差是 20（如 high 60 → critical 80），
	// 而 60 × 1.15 = 69，够不到 80。也就是说**再异常的主机也无法把一条 high 顶成
	// critical 的分数**，ML 只能在同级之间调顺序。这个上限是结构性保证，不是调参。
	mlRankMaxBoost = 1.15

	// mlScoreFloor 低于该异常分不加权。
	//
	// IForest 的分数天然在 0.5 附近徘徊（见 iforest_test：正常样本 0.45），
	// 不设下限会让所有主机都拿到一点加权，等于没有区分度。
	mlScoreFloor = 0.6

	// mlScoreMaxAge 异常分的有效期。
	//
	// 一台主机上周异常不代表现在异常。过期分数仍参与排序会让分析师
	// 一直盯着已经恢复正常的机器，而真正在变化的主机反而排在后面。
	mlScoreMaxAge = 2 * time.Hour
)

// reloadMLRankCache 刷新异常分快照。
func (g *AlertGenerator) reloadMLRankCache() {
	var rows []struct {
		HostID     string
		Score      float64
		ObservedAt time.Time
	}
	err := g.db.Model(&model.HostAnomalyScore{}).
		Select("host_id, score, observed_at").Scan(&rows).Error
	if err != nil {
		// 保留旧快照：读不到就退回上一份，而不是清空。
		// 清空会让排序在一次数据库抖动后静默失去 ML 输入。
		g.log.Warn("加载异常分快照失败，保留旧快照", zap.Error(err))
		return
	}
	now := time.Now()
	m := make(map[string]float64, len(rows))
	for _, r := range rows {
		if now.Sub(r.ObservedAt) > mlScoreMaxAge {
			continue
		}
		if w := mlBoostFromScore(r.Score); w > 1.0 {
			m[r.HostID] = w
		}
	}
	g.mlRankCache.Store(&m)
}

// mlBoostFromScore 把异常分映射为加权系数。
//
// 线性映射到 [1.0, mlRankMaxBoost]：分数越高排得越靠前，但封顶写死，
// 无论模型给出多离谱的分数都无法越过严重度边界。
func mlBoostFromScore(score float64) float64 {
	if score < mlScoreFloor {
		return 1.0
	}
	if score > 1.0 {
		score = 1.0
	}
	ratio := (score - mlScoreFloor) / (1.0 - mlScoreFloor)
	return 1.0 + ratio*(mlRankMaxBoost-1.0)
}

// mlRankBoost 返回该主机的排序加权，未命中或未启用为 1.0（不影响排序）。
func (g *AlertGenerator) mlRankBoost(hostID string) float64 {
	snap := g.mlRankCache.Load()
	if snap == nil {
		return 1.0
	}
	if w, ok := (*snap)[hostID]; ok {
		return w
	}
	return 1.0
}
