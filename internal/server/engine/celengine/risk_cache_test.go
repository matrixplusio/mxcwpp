package celengine

import "testing"

// TestWeightFromCriticality 锁定资产权重映射与原 assetWeight 语义一致。
func TestWeightFromCriticality(t *testing.T) {
	cases := map[string]float64{
		"critical": 1.3,
		"high":     1.15,
		"low":      0.8,
		"normal":   1.0,
		"":         1.0,
		"unknown":  1.0,
	}
	for in, want := range cases {
		if got := weightFromCriticality(in); got != want {
			t.Errorf("weightFromCriticality(%q)=%v, want %v", in, got, want)
		}
	}
}

// TestBoostFromCategoryCount 锁定关联加权阈值与原 correlationBoost 语义一致。
func TestBoostFromCategoryCount(t *testing.T) {
	cases := map[int64]float64{0: 1.0, 1: 1.0, 2: 1.2, 3: 1.5, 5: 1.5}
	for in, want := range cases {
		if got := boostFromCategoryCount(in); got != want {
			t.Errorf("boostFromCategoryCount(%d)=%v, want %v", in, got, want)
		}
	}
}

// TestAssetWeightCacheRead 校验热路径读原子快照：命中返回缓存值，未命中 / 空快照回退 1.0。
func TestAssetWeightCacheRead(t *testing.T) {
	g := &AlertGenerator{}
	// 空快照 → 默认 1.0（不 panic）
	if w := g.assetWeight("h1"); w != 1.0 {
		t.Fatalf("空快照 assetWeight=%v, want 1.0", w)
	}
	m := map[string]float64{"h1": 1.3}
	g.assetWeightCache.Store(&m)
	if w := g.assetWeight("h1"); w != 1.3 {
		t.Errorf("命中 assetWeight=%v, want 1.3", w)
	}
	if w := g.assetWeight("missing"); w != 1.0 {
		t.Errorf("未命中 assetWeight=%v, want 1.0", w)
	}
}

// TestCorrelationBoostCacheRead 校验关联加权热路径读快照：命中返回缓存值，未命中 / 空快照回退 1.0。
func TestCorrelationBoostCacheRead(t *testing.T) {
	g := &AlertGenerator{}
	if b := g.correlationBoost("h1"); b != 1.0 {
		t.Fatalf("空快照 correlationBoost=%v, want 1.0", b)
	}
	m := map[string]float64{"h1": 1.5}
	g.correlationBoostCache.Store(&m)
	if b := g.correlationBoost("h1"); b != 1.5 {
		t.Errorf("命中 correlationBoost=%v, want 1.5", b)
	}
	if b := g.correlationBoost("missing"); b != 1.0 {
		t.Errorf("未命中 correlationBoost=%v, want 1.0", b)
	}
}
