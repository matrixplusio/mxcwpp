package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gaugeValue 读取单个 Gauge/GaugeVec-child 的当前值（不引入 testutil 依赖）。
func gaugeValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return out.GetGauge().GetValue()
}

// TestSetAnomalyStatusOneHot 校验：配置/生效模式为 one-hot（命中项=1，其余=0），
// 且 schema/dns/trained 布尔与 sample/host 计数正确刷新。
func TestSetAnomalyStatusOneHot(t *testing.T) {
	// 配置 context、生效 shadow（模拟 schema 未就绪 fail-closed 降级）。
	SetAnomalyStatus("context", "shadow", false, false, true, 128, 7)

	// 配置模式 one-hot：仅 context=1。
	for _, m := range anomalyModes {
		want := 0.0
		if m == "context" {
			want = 1
		}
		if got := gaugeValue(t, AnomalyModeGauge.WithLabelValues(m)); got != want {
			t.Errorf("config mode gauge[%q]=%v, want %v", m, got, want)
		}
	}
	// 生效模式 one-hot：仅 shadow=1。
	for _, m := range anomalyModes {
		want := 0.0
		if m == "shadow" {
			want = 1
		}
		if got := gaugeValue(t, AnomalyEffectiveModeGauge.WithLabelValues(m)); got != want {
			t.Errorf("effective mode gauge[%q]=%v, want %v", m, got, want)
		}
	}

	if got := gaugeValue(t, AnomalySchemaReady); got != 0 {
		t.Errorf("schema_ready=%v, want 0", got)
	}
	if got := gaugeValue(t, AnomalyDNSFieldReady); got != 0 {
		t.Errorf("dns_field_ready=%v, want 0", got)
	}
	if got := gaugeValue(t, AnomalyIForestTrained); got != 1 {
		t.Errorf("iforest_trained=%v, want 1", got)
	}
	if got := gaugeValue(t, AnomalySampleCount); got != 128 {
		t.Errorf("sample_count=%v, want 128", got)
	}
	if got := gaugeValue(t, AnomalyHostCount); got != 7 {
		t.Errorf("host_count=%v, want 7", got)
	}

	// 再次刷新到 alert/alert + schema 就绪：旧的 one-hot 命中项必须清零（不残留 stale series）。
	SetAnomalyStatus("alert", "alert", true, false, true, 200, 9)
	if got := gaugeValue(t, AnomalyModeGauge.WithLabelValues("context")); got != 0 {
		t.Errorf("刷新后 config context 应清零，got %v", got)
	}
	if got := gaugeValue(t, AnomalyEffectiveModeGauge.WithLabelValues("shadow")); got != 0 {
		t.Errorf("刷新后 effective shadow 应清零，got %v", got)
	}
	if got := gaugeValue(t, AnomalyModeGauge.WithLabelValues("alert")); got != 1 {
		t.Errorf("刷新后 config alert 应=1，got %v", got)
	}
	if got := gaugeValue(t, AnomalySchemaReady); got != 1 {
		t.Errorf("schema_ready=%v, want 1", got)
	}
}
