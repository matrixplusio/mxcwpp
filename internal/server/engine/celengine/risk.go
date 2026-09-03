package celengine

import (
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 风险分级（P2-A，对齐 CrowdStrike risk-based alerting）：
//
//	risk = base(severity) × fidelityWeight × assetWeight × correlationBoost × mlRankBoost，封顶 100。
//
// mlRankBoost 是 ML 异常分带来的排序加权（仅 ranking/alert 档生效，见 ml_rank.go）。
// 它封顶 1.15，够不到相邻严重度档之间 20 分的基础分差——**ML 只能在同级之间调顺序，
// 不能把一条告警顶进更高的档**。
//
// 单信号低保真规则已被 P1 在 Generate 拦截（不入此路径）；保留 fidelity 权重以防
// 未来低保真经关联升级后仍走打分。correlationBoost 体现 IOA「多信号关联升级」。
func (g *AlertGenerator) computeRiskScore(hostID string, rule *model.DetectionRule) int {
	base := severityBase(rule.Severity)
	score := float64(base) * fidelityWeight(rule.Fidelity) * g.assetWeight(hostID) *
		g.correlationBoost(hostID) * g.mlRankBoost(hostID)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return int(score)
}

// computeRiskScoreForExisting 重算已存在告警的风险分（重触发时）。
// 已在告警 = 已过 P1 保真闸门，fidelity 视为 high；用告警自身 severity + 主机 + 关联。
func (g *AlertGenerator) computeRiskScoreForExisting(a *model.Alert) int {
	score := float64(severityBase(a.Severity)) * g.assetWeight(a.HostID) *
		g.correlationBoost(a.HostID) * g.mlRankBoost(a.HostID)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return int(score)
}

func severityBase(sev string) int {
	switch sev {
	case "critical":
		return 80
	case "high":
		return 60
	case "medium":
		return 40
	default: // low / 未知
		return 20
	}
}

func fidelityWeight(f string) float64 {
	if f == model.RuleFidelityLow {
		return 0.5
	}
	return 1.0
}

// assetWeight 按主机资产关键性加权；读原子快照零 DB，未命中按 normal(1.0)。
// 快照由 StartRiskCacheReload 周期刷新（详见 risk_cache.go）——原每事件一次
// `SELECT criticality FROM hosts` 在高事件量下打满连接池，是 engine CPU 高根因。
func (g *AlertGenerator) assetWeight(hostID string) float64 {
	snap := g.assetWeightCache.Load()
	if snap == nil {
		return 1.0
	}
	if w, ok := (*snap)[hostID]; ok {
		return w
	}
	return 1.0
}

// correlationBoost 体现多信号关联：同主机近 1h 活跃告警跨越的不同 category 越多，
// 越可能是攻击链（非孤立误报），分越高。≥3 类 ×1.5，≥2 类 ×1.2，否则 ×1.0。
// 读原子快照零 DB（原每事件一次 COUNT(DISTINCT category) 无索引全扫，是 engine CPU 高根因）；
// 快照由 StartRiskCacheReload 每分钟刷新（详见 risk_cache.go）。
func (g *AlertGenerator) correlationBoost(hostID string) float64 {
	snap := g.correlationBoostCache.Load()
	if snap == nil {
		return 1.0
	}
	if b, ok := (*snap)[hostID]; ok {
		return b
	}
	return 1.0
}
