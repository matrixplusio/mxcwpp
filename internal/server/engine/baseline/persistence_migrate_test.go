package baseline

import (
	"encoding/json"
	"math"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func seedBaselineRow(t *testing.T, db *gorm.DB, hostID, algo string, samples int, mean, m2 [MetricCount]float64) {
	t.Helper()
	mj, _ := json.Marshal(mean)
	m2j, _ := json.Marshal(m2)
	require := func(err error) {
		if err != nil {
			t.Fatalf("seed %s: %v", hostID, err)
		}
	}
	require(db.Create(&model.HostBaselineState{
		HostID: hostID, Phase: PhaseActive, Samples: samples,
		Algo: algo, MeanJSON: string(mj), M2JSON: string(m2j),
	}).Error)
}

// TestLoadFromDB_ConvertsLegacyWelfordM2 校验持久化迁移：
//   - 旧 Welford 行(algo="")：M2JSON 是 sum-of-squared-deviations，按 (samples-1) 换算成 variance。
//   - EWMA 行(algo="ewma")：M2JSON 直接是 variance。
func TestLoadFromDB_ConvertsLegacyWelfordM2(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.HostBaselineState{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	var mean [MetricCount]float64
	mean[0] = 10

	// 旧行：m2[0]=1000, samples=101 → variance=1000/100=10 → sd=sqrt(10)。
	var legacyM2 [MetricCount]float64
	legacyM2[0] = 1000
	seedBaselineRow(t, db, "legacy", "", 101, mean, legacyM2)

	// EWMA 行：m2[0]=10 已是 variance → sd=sqrt(10)。
	var ewmaVar [MetricCount]float64
	ewmaVar[0] = 10
	seedBaselineRow(t, db, "ewma", baselineAlgoEWMA, 500, mean, ewmaVar)

	eng := NewEngine(db, zap.NewNop()) // 触发 loadFromDB

	wantSd := math.Sqrt(10)
	for _, hostID := range []string{"legacy", "ewma"} {
		bl := eng.getOrCreate(hostID)
		if got := bl.Stddev(0); math.Abs(got-wantSd) > 1e-6 {
			t.Errorf("%s: Stddev(0)=%.6f, 期望 %.6f", hostID, got, wantSd)
		}
		if got := bl.Mean(0); got != 10 {
			t.Errorf("%s: Mean(0)=%.2f, 期望 10", hostID, got)
		}
	}
}
