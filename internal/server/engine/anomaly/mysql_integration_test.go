package anomaly

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 针对真实 MySQL 的集成验证。不设 PROBE_DSN 时自动跳过。
//
//	PROBE_DSN='user:pass@tcp(127.0.0.1:3306)/mxcwpp?charset=utf8mb4&parseTime=True&loc=Local' \
//	    go test ./internal/server/engine/anomaly/ -run MySQL
//
// 为什么值得单独维护一组：本包其余用例跑在 sqlite 上，而两者在分组语义、
// JSON 列、大字段与 upsert 上都有差异。本仓已经因此漏掉过真实缺陷——
// 单测全绿而真库上第一次调用就失败。模型 payload 是 500KB 级的 longtext，
// 恰恰是 sqlite 完全测不到的地方。
func mysqlDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("PROBE_DSN")
	if dsn == "" {
		t.Skip("未设置 PROBE_DSN，跳过 MySQL 集成验证")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("连接 MySQL 失败: %v", err)
	}
	return db
}

func cleanupMySQL(t *testing.T, db *gorm.DB) {
	t.Helper()
	db.Exec("DELETE FROM anomaly_model_versions WHERE model_name = ?", modelStateName)
	db.Exec("DELETE FROM anomaly_model_states WHERE model_name = ?", modelStateName)
	db.Exec("DELETE FROM host_anomaly_scores WHERE host_id LIKE 'itest-%'")
}

// 参照基线在真 MySQL 上落库并恢复（JSON 列往返）。
func TestReferenceBaselineRoundTripMySQL(t *testing.T) {
	db := mysqlDB(t)
	cleanupMySQL(t, db)
	t.Cleanup(func() { cleanupMySQL(t, db) })

	first := NewDetector(db, nil, zap.NewNop())
	first.reference = newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5))
	if first.reference == nil {
		t.Fatal("参照基线未建立")
	}
	first.SaveState()

	second := NewDetector(db, nil, zap.NewNop())
	second.LoadState()
	if !second.HasReference() {
		t.Fatal("未能从 MySQL 恢复参照基线：投毒防护会在每次重启后静默失效")
	}
	for i := range first.reference.mean {
		if second.reference.mean[i] != first.reference.mean[i] {
			t.Fatalf("第 %d 维均值恢复不符: %v vs %v",
				i, second.reference.mean[i], first.reference.mean[i])
		}
	}
}

// 模型版本落库、重启恢复、回滚，全程分数必须一致。
//
// payload 是 500KB 级的 longtext。字段类型、max_allowed_packet、字符集
// 任一处不对都会在这里暴露，而 sqlite 上永远不会。
func TestModelVersioningMySQL(t *testing.T) {
	db := mysqlDB(t)
	cleanupMySQL(t, db)
	t.Cleanup(func() { cleanupMySQL(t, db) })

	d := NewDetector(db, nil, zap.NewNop())
	d.forest.Train(makeWindow(512, 50, 8))
	sample := makeWindow(1, 50, 8)[0]
	v1Score := d.forest.Score(sample)
	d.saveModelVersion(512, 0.4)

	d.forest.Train(makeWindow(512, 400, 30))
	d.saveModelVersion(512, 2.1)
	v2Score := d.forest.Score(sample)

	// 重启应恢复生效版本 v2。
	restarted := NewDetector(db, nil, zap.NewNop())
	restarted.LoadActiveModel()
	if !restarted.forest.Trained() {
		t.Fatal("重启后未恢复模型：需等一个完整重训周期才能评分")
	}
	if got := restarted.forest.Score(sample); got != v2Score {
		t.Fatalf("重启应恢复 v2 分数 %.17g，实际 %.17g", v2Score, got)
	}

	// 回滚到 v1，分数必须真的换回去。
	if err := restarted.RollbackModel(1, "itest"); err != nil {
		t.Fatalf("回滚失败: %v", err)
	}
	if got := restarted.forest.Score(sample); got != v1Score {
		t.Fatalf("回滚后应为 v1 分数 %.17g，实际 %.17g", v1Score, got)
	}

	// 回滚后再重启仍应是 v1，否则回滚只是内存里的假象。
	again := NewDetector(db, nil, zap.NewNop())
	again.LoadActiveModel()
	if got := again.forest.Score(sample); got != v1Score {
		t.Fatalf("回滚后重启应保持 v1，实际 %.17g", got)
	}
}

// 异常分 upsert：同一主机重复落库必须更新而非新增。
//
// upsert 语义在 MySQL 与 sqlite 上不同；写错的话表会随时间无限膨胀，
// 而且排序会读到同一主机的多行旧分数。
func TestScoreUpsertMySQL(t *testing.T) {
	db := mysqlDB(t)
	cleanupMySQL(t, db)
	t.Cleanup(func() { cleanupMySQL(t, db) })

	r := newScoreRecorder(db, zap.NewNop())
	now := time.Now()
	r.record("itest-h1", 0.91, now)
	r.flush()
	r.record("itest-h1", 0.77, now.Add(time.Minute))
	r.flush()

	var n int64
	db.Model(&model.HostAnomalyScore{}).Where("host_id = ?", "itest-h1").Count(&n)
	if n != 1 {
		t.Fatalf("同一主机应只有 1 行（upsert），实际 %d 行", n)
	}
	var row model.HostAnomalyScore
	db.Where("host_id = ?", "itest-h1").First(&row)
	if row.Score != 0.77 {
		t.Fatalf("分数应更新为 0.77，实际 %v", row.Score)
	}
}
