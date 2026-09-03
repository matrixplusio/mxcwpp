package celengine

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ML 加权绝不能把一条告警顶进更高的严重度档。
//
// 这是 ranking 档能否被信任的前提：排序意味着"决定先看哪个"，定罪意味着"决定它有多严重"。
// 一旦异常分能跨档提升，ML 就在实质上参与定罪了，而它给出的只是"少见"，不是"恶意"。
//
// 用相邻档之间的基础分差来卡：high=60、critical=80，60 × 上限 必须 < 80。
func TestMLBoostCannotCrossSeverityBand(t *testing.T) {
	bands := []struct {
		lower, upper string
	}{
		{"low", "medium"},
		{"medium", "high"},
		{"high", "critical"},
	}
	for _, b := range bands {
		lo := float64(severityBase(b.lower))
		hi := float64(severityBase(b.upper))
		// 最极端情况：异常分为 1.0，拿到满额加权。
		boosted := lo * mlBoostFromScore(1.0)
		if boosted >= hi {
			t.Fatalf("%s 经 ML 满额加权后达到 %.1f，够到了 %s 的基础分 %.1f —— ML 越界定罪了",
				b.lower, boosted, b.upper, hi)
		}
	}
}

// 低分不加权：IForest 的分数天然在 0.5 附近，不设下限会让所有主机都拿到加权，
// 等于没有区分度。
func TestLowScoresGetNoBoost(t *testing.T) {
	for _, s := range []float64{0.0, 0.3, 0.45, mlScoreFloor - 0.01} {
		if w := mlBoostFromScore(s); w != 1.0 {
			t.Fatalf("异常分 %.2f 不该加权，实际 %.4f", s, w)
		}
	}
}

// 加权随分数单调上升，且封顶。
func TestBoostIsMonotonicAndCapped(t *testing.T) {
	prev := 1.0
	for _, s := range []float64{0.6, 0.7, 0.8, 0.9, 1.0} {
		w := mlBoostFromScore(s)
		if w < prev {
			t.Fatalf("异常分 %.2f 的加权 %.4f 低于前一档 %.4f，应单调不降", s, w, prev)
		}
		if w > mlRankMaxBoost {
			t.Fatalf("异常分 %.2f 的加权 %.4f 超过上限 %.4f", s, w, mlRankMaxBoost)
		}
		prev = w
	}
	// 越界输入不能突破封顶。
	if w := mlBoostFromScore(99); w > mlRankMaxBoost {
		t.Fatalf("越界分数突破了封顶: %.4f", w)
	}
}

// 没有快照时加权为 1.0——ML 未启用不能影响既有排序。
func TestNoSnapshotMeansNoInfluence(t *testing.T) {
	g := &AlertGenerator{}
	if w := g.mlRankBoost("h1"); w != 1.0 {
		t.Fatalf("无快照时不该影响排序，实际加权 %.4f", w)
	}
}

// 快照里没有的主机不受影响。
func TestUnknownHostUnaffected(t *testing.T) {
	g := &AlertGenerator{}
	m := map[string]float64{"h1": 1.1}
	g.mlRankCache.Store(&m)
	if w := g.mlRankBoost("h-not-scored"); w != 1.0 {
		t.Fatalf("未评分主机不该被加权，实际 %.4f", w)
	}
	if w := g.mlRankBoost("h1"); w != 1.1 {
		t.Fatalf("已评分主机加权应为 1.1，实际 %.4f", w)
	}
}

// 风险分整体仍然封顶 100，ML 加权不能让它溢出。
func TestRiskScoreStillCappedWithMLBoost(t *testing.T) {
	g := &AlertGenerator{}
	m := map[string]float64{"h1": mlRankMaxBoost}
	g.mlRankCache.Store(&m)
	// assetWeight / correlationBoost 无快照时各返回 1.0，此处只验证封顶逻辑。
	a := &model.Alert{Severity: "critical", HostID: "h1"}
	if got := g.computeRiskScoreForExisting(a); got > 100 {
		t.Fatalf("风险分应封顶 100，实际 %d", got)
	}
}
