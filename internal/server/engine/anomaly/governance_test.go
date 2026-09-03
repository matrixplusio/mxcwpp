package anomaly

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestCorrelationSeverity 校验证据分级：覆盖率+平均比值定档，且以 pattern 上限封顶。
func TestCorrelationSeverity(t *testing.T) {
	elev := func(ratios ...float64) []model.ElevatedMetric {
		out := make([]model.ElevatedMetric, len(ratios))
		for i, r := range ratios {
			out[i] = model.ElevatedMetric{Ratio: r}
		}
		return out
	}
	cases := []struct {
		name    string
		ceiling string
		elev    []model.ElevatedMetric
		total   int
		want    string
	}{
		{"全覆盖高比值→critical", "critical", elev(10, 12, 9, 8, 15), 5, "critical"},
		{"全覆盖高比值但上限high→封顶high", "high", elev(10, 12, 9, 8, 15), 5, "high"},
		{"高覆盖中比值→high", "critical", elev(6, 5, 7, 6), 5, "high"},
		{"低覆盖→medium", "critical", elev(20), 5, "medium"},
		{"空证据→low", "critical", nil, 5, "low"},
	}
	for _, c := range cases {
		if got := correlationSeverity(c.ceiling, c.elev, c.total); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// TestForestSeverity 校验 IForest 封顶 high，不单独判 critical。
func TestForestSeverity(t *testing.T) {
	if got := forestSeverity(0.99); got != "high" {
		t.Errorf("高分应封顶 high, got %q", got)
	}
	if got := forestSeverity(0.85); got != "high" {
		t.Errorf("0.85 应 high, got %q", got)
	}
	if got := forestSeverity(0.70); got != "medium" {
		t.Errorf("0.70 应 medium, got %q", got)
	}
}

// TestCapSeverity 校验严重度封顶。
func TestCapSeverity(t *testing.T) {
	if capSeverity("critical", "high") != "high" {
		t.Error("critical 应被 high 封顶")
	}
	if capSeverity("medium", "critical") != "medium" {
		t.Error("medium 低于上限应保持")
	}
}

// TestMetricFloor 校验绝对下限存在且计数类不为 0（防"除以极小基线"假阳性的关键）。
func TestMetricFloor(t *testing.T) {
	// net_connect_count(6) / dns_query_count(10) / proc_exec_count(0) 必须有有意义下限。
	if metricFloor[6] < 10 || metricFloor[10] < 10 || metricFloor[0] < 5 {
		t.Errorf("计数类指标下限过低: net_connect=%v dns_query=%v proc_exec=%v",
			metricFloor[6], metricFloor[10], metricFloor[0])
	}
	if len(metricFloor) != featureCount {
		t.Errorf("metricFloor 维度 %d 应等于 featureCount %d", len(metricFloor), featureCount)
	}
}

// TestIsInfraHostname 校验基础设施主机识别（这些是 correlation 误报大户）。
func TestIsInfraHostname(t *testing.T) {
	infra := []string{"web-cdn-01", "zookeeper-02", "bigdata-cdh-04", "prod-mysql-01"}
	for _, h := range infra {
		if !isInfraHostname(h) {
			t.Errorf("%q 应识别为基础设施主机", h)
		}
	}
	if isInfraHostname("app-server-01") {
		t.Error("业务主机不应识别为基础设施")
	}
}

// TestDowngradeForInfra 校验降级不消音（每级降一档，low 保持）。
func TestDowngradeForInfra(t *testing.T) {
	if downgradeForInfra("critical") != "high" || downgradeForInfra("high") != "medium" ||
		downgradeForInfra("medium") != "low" || downgradeForInfra("low") != "low" {
		t.Error("降级逻辑错误")
	}
}
