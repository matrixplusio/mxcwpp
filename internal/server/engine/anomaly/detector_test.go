package anomaly

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestMetricSnapshot(t *testing.T) {
	metrics := []float64{
		1, 2, 3,
		4, 5, 6,
		7, 8, 9, 10,
		11, 12, 13,
	}
	snap := metricSnapshot(metrics)
	if len(snap) != featureCount {
		t.Fatalf("snapshot len = %d, want %d", len(snap), featureCount)
	}
	for i, name := range MetricNames {
		if snap[name] != metrics[i] {
			t.Errorf("snap[%q] = %v, want %v", name, snap[name], metrics[i])
		}
	}
}

func TestTopDeviations(t *testing.T) {
	t.Run("normal: pick top 3 by ratio descending", func(t *testing.T) {
		mean := []float64{
			10, 10, 10,
			10, 10, 10,
			10, 10, 10, 10,
			10, 10, 10,
		}
		// metrics: 第 2 个偏离 10x, 第 5 个偏离 5x, 第 7 个偏离 3x, 第 11 个偏离 0.5x（被过滤）
		metrics := []float64{
			10, 100, 10, // ratio 10
			10, 10, 50, // idx5 ratio 5
			10, 30, 10, 10, // idx7 ratio 3
			5, 10, 10, // idx10 ratio 0.5 — filter out
		}
		got := topDeviations(metrics, mean, 3)
		if len(got) != 3 {
			t.Fatalf("len=%d want 3", len(got))
		}
		want := []string{MetricNames[1], MetricNames[5], MetricNames[7]}
		for i, m := range got {
			if m.Name != want[i] {
				t.Errorf("[%d] name=%q want %q", i, m.Name, want[i])
			}
		}
		// Ratio 排序检查
		if got[0].Ratio < got[1].Ratio || got[1].Ratio < got[2].Ratio {
			t.Errorf("ratio not descending: %v", got)
		}
	})

	t.Run("zero mean entries skipped", func(t *testing.T) {
		mean := make([]float64, featureCount) // all 0
		metrics := make([]float64, featureCount)
		for i := range metrics {
			metrics[i] = float64(i)
		}
		got := topDeviations(metrics, mean, 5)
		if len(got) != 0 {
			t.Errorf("expected 0 elevations when mean is all-zero, got %d", len(got))
		}
	})

	t.Run("all ratios < 1 returns empty", func(t *testing.T) {
		mean := []float64{
			100, 100, 100,
			100, 100, 100,
			100, 100, 100, 100,
			100, 100, 100,
		}
		metrics := make([]float64, featureCount)
		for i := range metrics {
			metrics[i] = 50 // ratio 0.5
		}
		got := topDeviations(metrics, mean, 3)
		if len(got) != 0 {
			t.Errorf("expected 0 when all ratios < 1, got %d", len(got))
		}
	})

	t.Run("N larger than candidates", func(t *testing.T) {
		mean := []float64{
			10, 10, 10,
			10, 10, 10,
			10, 10, 10, 10,
			10, 10, 10,
		}
		metrics := []float64{
			30, 10, 10, // only 1 ratio > 1
			10, 10, 10,
			10, 10, 10, 10,
			10, 10, 10,
		}
		got := topDeviations(metrics, mean, 10)
		if len(got) != 1 {
			t.Errorf("expected 1 elevation, got %d", len(got))
		}
		if got[0].Name != MetricNames[0] {
			t.Errorf("name=%q want %q", got[0].Name, MetricNames[0])
		}
		if got[0].Ratio != 3.0 {
			t.Errorf("ratio=%v want 3.0", got[0].Ratio)
		}
		if got[0].Current != 30 || got[0].Baseline != 10 {
			t.Errorf("current=%v baseline=%v want 30,10", got[0].Current, got[0].Baseline)
		}
	})
}

// TestAnomalyTriggerContext_JSONRoundtrip 验证 trigger_context JSON 序列化/反序列化无损（GORM 自定义类型）。
func TestAnomalyTriggerContext_JSONRoundtrip(t *testing.T) {
	orig := model.AnomalyTriggerContext{
		ElevatedMetrics: []model.ElevatedMetric{
			{Name: "proc_exec_count", Current: 200, Baseline: 30, Ratio: 6.67},
		},
		MetricSnapshot:    map[string]float64{"proc_exec_count": 200, "net_unique_ip": 80},
		SuspiciousIPs:     []string{"1.2.3.4", "5.6.7.8"},
		SuspiciousDomains: []string{"c2.example.com"},
		SensitiveFiles:    []string{"/etc/shadow"},
		ProcessChain:      []string{"/usr/bin/curl", "/bin/bash"},
		ScannedPorts:      []string{"22", "445"},
		WindowStart:       "2026-06-04 16:00:00",
		WindowEnd:         "2026-06-04 16:05:00",
	}
	val, err := orig.Value()
	if err != nil {
		t.Fatalf("Value() failed: %v", err)
	}
	bytes, ok := val.([]byte)
	if !ok {
		t.Fatalf("Value() returned %T, want []byte", val)
	}

	var decoded model.AnomalyTriggerContext
	if err := decoded.Scan(bytes); err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	if len(decoded.ElevatedMetrics) != 1 || decoded.ElevatedMetrics[0].Name != "proc_exec_count" {
		t.Errorf("ElevatedMetrics not preserved: %+v", decoded.ElevatedMetrics)
	}
	if decoded.SuspiciousIPs[0] != "1.2.3.4" || decoded.SuspiciousIPs[1] != "5.6.7.8" {
		t.Errorf("SuspiciousIPs not preserved: %v", decoded.SuspiciousIPs)
	}
	if decoded.WindowStart != "2026-06-04 16:00:00" {
		t.Errorf("WindowStart=%q lost", decoded.WindowStart)
	}
	if decoded.MetricSnapshot["proc_exec_count"] != 200 {
		t.Errorf("MetricSnapshot value lost: %v", decoded.MetricSnapshot)
	}
}

// TestEnrichTriggerContext_NilChConn 验证 detector chConn=nil 时 enrichTriggerContext 不 panic、不写 IOC。
// 部署 ClickHouse 未启用时的降级路径。
func TestEnrichTriggerContext_NilChConn(t *testing.T) {
	d := &Detector{chConn: nil, logger: zap.NewNop()}
	trigger := &model.AnomalyTriggerContext{}
	now := time.Now()
	start := now.Add(-5 * time.Minute)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("enrichTriggerContext panicked with nil chConn: %v", r)
		}
	}()
	for _, p := range []string{"c2_beacon", "data_exfiltration", "privilege_escalation", "reconnaissance", "unknown_pattern"} {
		d.enrichTriggerContext(trigger, p, "host-1", start, now)
	}
	if len(trigger.SuspiciousIPs) != 0 || len(trigger.SuspiciousDomains) != 0 ||
		len(trigger.SensitiveFiles) != 0 || len(trigger.ProcessChain) != 0 ||
		len(trigger.ScannedPorts) != 0 {
		t.Errorf("expected no IOC enrichment when chConn nil, got %+v", trigger)
	}
}

// TestCorrelationPatternsCoverage 守护：每个 pattern.Indices 必须 ∈ [0, featureCount)。
// 防止后续编辑 MetricNames / 加 pattern 时引入越界 panic。
func TestCorrelationPatternsCoverage(t *testing.T) {
	for _, p := range correlationPatterns {
		for _, idx := range p.Indices {
			if idx < 0 || idx >= featureCount {
				t.Errorf("pattern %q has out-of-range index %d (featureCount=%d)", p.Name, idx, featureCount)
			}
		}
		if p.MinActive <= 0 || p.MinActive > len(p.Indices) {
			t.Errorf("pattern %q has invalid MinActive %d (Indices len=%d)", p.Name, p.MinActive, len(p.Indices))
		}
	}
}
