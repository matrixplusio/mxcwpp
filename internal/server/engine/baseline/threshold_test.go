package baseline

import "testing"

// TestPerMetricThreshold 校验 H1：计数/速率型指标用更高阈值倍率，同样 ~4σ 偏离下
// 计数型(net_connect_count, mult 1.7 → 5.1σ)不告警，比率型(dns_nx_ratio, mult 1.0 → 3σ)告警。
func TestPerMetricThreshold(t *testing.T) {
	eng := NewEngine(nil, nil)
	bl := eng.getOrCreate("h")
	bl.mu.Lock()
	bl.phase = PhaseActive
	bl.samples = 10000
	for i := range MetricCount {
		bl.mean[i] = 100
		bl.variance[i] = 100 // sd = 10
	}
	bl.mu.Unlock()

	var m [MetricCount]float64
	for i := range MetricCount {
		m[i] = 100 // 与基线一致 → 无偏离
	}
	m[MetricNetConnectCount] = 140 // +4σ，计数型阈值 3×1.7=5.1σ → 不越界
	m[MetricDNSNXRatio] = 140      // +4σ，比率型阈值 3×1.0=3σ → 越界

	res := eng.Ingest("h", m)
	if res == nil {
		t.Fatal("比率指标 4σ 偏离应产生告警")
	}
	got := map[string]bool{}
	for _, d := range res.Deviations {
		got[d.Metric] = true
	}
	if got[MetricNames[MetricNetConnectCount]] {
		t.Error("计数型 net_connect_count 在 4σ(<5.1σ 阈值) 不应告警")
	}
	if !got[MetricNames[MetricDNSNXRatio]] {
		t.Error("比率型 dns_nx_ratio 在 4σ(>3σ 阈值) 应告警")
	}
}
