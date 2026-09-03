package baseline

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestNextTuningMult 校验反馈闭环调参决策（纯逻辑）。
func TestNextTuningMult(t *testing.T) {
	cases := []struct {
		name        string
		current     float64
		ignoredRate float64
		samples     int
		want        float64
	}{
		{"样本不足不动", 1.0, 0.95, 10, 1.0},
		{"高误报抬高", 1.0, 0.9, 100, 1.5},
		{"高误报封顶", 3.0, 0.9, 100, maxTuningMult}, // 3*1.5=4.5 → 封顶 4.0
		{"低误报缓降", 2.0, 0.1, 100, 1.6},
		{"低误报下限1", 1.0, 0.1, 100, 1.0},
		{"中间保持", 1.5, 0.5, 100, 1.5},
	}
	for _, c := range cases {
		if got := nextTuningMult(c.current, c.ignoredRate, c.samples); got != c.want {
			t.Errorf("%s: nextTuningMult(%v,%v,%d)=%v 期望 %v", c.name, c.current, c.ignoredRate, c.samples, got, c.want)
		}
	}
}

// TestReloadTuning 校验从 behavior_alerts ignored 率计算并落库 + 刷新内存快照，敏感指标豁免。
func TestReloadTuning(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&model.BehaviorAlert{}, &model.BDEMetricTuning{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	// net_connect_count：90 ignored + 10 resolved → rate 0.9(高) → 抬到 1.5。
	// file_sensitive_hits：全 ignored(敏感) → 豁免，保持 1.0。
	seed := func(metric, status string, n int) {
		for range n {
			if err := db.Create(&model.BehaviorAlert{HostID: "h", Metric: metric, Status: status}).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	seed("net_connect_count", "ignored", 90)
	seed("net_connect_count", "resolved", 10)
	seed("file_sensitive_hits", "ignored", 100)

	e := &Engine{db: db, logger: zap.NewNop()}
	e.reloadTuning()

	// 内存快照：net_connect_count 抬到 1.5，file_sensitive_hits 豁免=1.0。
	nci := metricIndexByName("net_connect_count")
	if got := e.tuningMult(nci); got != 1.5 {
		t.Errorf("net_connect_count 动态倍率=%v 期望 1.5", got)
	}
	if got := e.tuningMult(MetricFileSensitiveHits); got != 1.0 {
		t.Errorf("敏感指标应豁免=1.0, 得 %v", got)
	}

	// 落库校验。
	var row model.BDEMetricTuning
	if err := db.Where("metric = ?", "net_connect_count").First(&row).Error; err != nil {
		t.Fatalf("tuning 未落库: %v", err)
	}
	if row.ThresholdMult != 1.5 || row.Samples != 100 {
		t.Errorf("落库值 mult=%v samples=%d 期望 1.5/100", row.ThresholdMult, row.Samples)
	}
}
