package anomaly

import (
	"testing"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func seedThresholdFlag(t *testing.T, db *gorm.DB, value string) {
	t.Helper()
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS feature_flags (
		id INTEGER PRIMARY KEY AUTOINCREMENT, flag_key TEXT, value TEXT,
		description TEXT, created_at DATETIME, updated_at DATETIME)`).Error; err != nil {
		t.Fatalf("create flags: %v", err)
	}
	db.Exec(`DELETE FROM feature_flags WHERE flag_key = ?`, FlagAnomalyScoreThreshold)
	if value != "" {
		if err := db.Exec(`INSERT INTO feature_flags (flag_key, value) VALUES (?, ?)`,
			FlagAnomalyScoreThreshold, value).Error; err != nil {
			t.Fatalf("seed flag: %v", err)
		}
	}
}

// 未配置时用默认值。
func TestThresholdDefault(t *testing.T) {
	d := newStateDetector(newStateDB(t))
	if got := d.scoreThreshold(); got != defaultAnomalyThreshold {
		t.Fatalf("默认阈值应为 %.2f，实际 %.2f", defaultAnomalyThreshold, got)
	}
}

// 合法配置生效。
func TestThresholdConfigurable(t *testing.T) {
	db := newStateDB(t)
	d := newStateDetector(db)
	seedThresholdFlag(t, db, "0.8")
	d.LoadScoreThreshold(db)
	if got := d.scoreThreshold(); got != 0.8 {
		t.Fatalf("阈值应为 0.8，实际 %.2f", got)
	}
}

// 越界与非法配置一律回落默认值。
//
// 低于下限等于把大半样本判成异常（IForest 分数天然在 0.5 附近）；
// 高于上限实际等同关闭检测，但外表仍是"已启用"——要关就用 mode=off，
// 别用一个永远触发不了的阈值假装在跑。
func TestThresholdRejectsOutOfRangeAndGarbage(t *testing.T) {
	for _, bad := range []string{"0.1", "0.99", "1.5", "-1", "abc", ""} {
		db := newStateDB(t)
		d := newStateDetector(db)
		seedThresholdFlag(t, db, bad)
		d.LoadScoreThreshold(db)
		if got := d.scoreThreshold(); got != defaultAnomalyThreshold {
			t.Fatalf("配置 %q 应回落默认值，实际 %.2f", bad, got)
		}
	}
}

// 边界值本身是允许的。
func TestThresholdBoundariesAccepted(t *testing.T) {
	for _, v := range []float64{minAnomalyThreshold, maxAnomalyThreshold} {
		db := newStateDB(t)
		d := newStateDetector(db)
		seedThresholdFlag(t, db, formatFloat(v))
		d.LoadScoreThreshold(db)
		if got := d.scoreThreshold(); got != v {
			t.Fatalf("边界值 %.2f 应被接受，实际 %.2f", v, got)
		}
	}
}

func formatFloat(v float64) string {
	switch v {
	case 0.5:
		return "0.5"
	case 0.95:
		return "0.95"
	}
	return "0.65"
}

var _ = model.FeatureFlag{}
