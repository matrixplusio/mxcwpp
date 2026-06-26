package celengine

import (
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 风险分级（P2-A，对齐 CrowdStrike risk-based alerting）：
//
//	risk = base(severity) × fidelityWeight × assetWeight × correlationBoost，封顶 100。
//
// 单信号低保真规则已被 P1 在 Generate 拦截（不入此路径）；保留 fidelity 权重以防
// 未来低保真经关联升级后仍走打分。correlationBoost 体现 IOA「多信号关联升级」。
func (g *AlertGenerator) computeRiskScore(hostID string, rule *model.DetectionRule) int {
	base := severityBase(rule.Severity)
	score := float64(base) * fidelityWeight(rule.Fidelity) * g.assetWeight(hostID) * g.correlationBoost(hostID)
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
	score := float64(severityBase(a.Severity)) * g.assetWeight(a.HostID) * g.correlationBoost(a.HostID)
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

// assetWeight 按主机资产关键性加权；查不到按 normal。
func (g *AlertGenerator) assetWeight(hostID string) float64 {
	var h model.Host
	if err := g.db.Select("criticality").Where("host_id = ?", hostID).First(&h).Error; err != nil {
		return 1.0
	}
	switch h.Criticality {
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

// correlationBoost 体现多信号关联：同主机近 1h 活跃告警跨越的不同 category 越多，
// 越可能是攻击链（非孤立误报），分越高。≥3 类 ×1.5，≥2 类 ×1.2，否则 ×1.0。
func (g *AlertGenerator) correlationBoost(hostID string) float64 {
	since := time.Now().Add(-time.Hour)
	var distinctCategories int64
	g.db.Model(&model.Alert{}).
		Where("host_id = ? AND status = ? AND last_seen_at >= ?", hostID, model.AlertStatusActive, since).
		Distinct("category").
		Count(&distinctCategories)
	switch {
	case distinctCategories >= 3:
		return 1.5
	case distinctCategories >= 2:
		return 1.2
	default:
		return 1.0
	}
}
