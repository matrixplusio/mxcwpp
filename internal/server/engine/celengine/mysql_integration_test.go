package celengine

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ranking 跨进程通路的真实 MySQL 验证。不设 PROBE_DSN 时自动跳过。
//
// 异常检测跑在 consumer 进程，风险分算在 engine 进程，两端只靠
// host_anomaly_scores 表相连。任一端列名写错、时间字段解析不对，
// 结果都是"排序看起来启用了但不起作用"——两侧各自的单测都发现不了。
func rankingDB(t *testing.T) *gorm.DB {
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

func TestRankingCrossProcessMySQL(t *testing.T) {
	db := rankingDB(t)
	clean := func() { db.Exec("DELETE FROM host_anomaly_scores WHERE host_id LIKE 'itest-%'") }
	clean()
	t.Cleanup(clean)

	now := model.ToLocalTime(time.Now())
	rows := []model.HostAnomalyScore{
		{HostID: "itest-anomalous", Score: 0.95, ObservedAt: now},
		{HostID: "itest-normal", Score: 0.30, ObservedAt: now},
		// 过期分数：一台主机昨天异常不代表现在异常。
		{HostID: "itest-stale", Score: 0.95,
			ObservedAt: model.ToLocalTime(time.Now().Add(-24 * time.Hour))},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("写入异常分失败: %v", err)
		}
	}

	g := &AlertGenerator{db: db, log: zap.NewNop()}
	g.reloadMLRankCache()

	if w := g.mlRankBoost("itest-anomalous"); w <= 1.0 {
		t.Fatalf("异常主机应被加权，实际 %.4f —— 跨进程通路没打通", w)
	}
	if w := g.mlRankBoost("itest-normal"); w != 1.0 {
		t.Fatalf("低分主机不该加权，实际 %.4f", w)
	}
	if w := g.mlRankBoost("itest-stale"); w != 1.0 {
		t.Fatalf("过期分数不该参与排序，实际 %.4f", w)
	}

	// 加权改变排序，但绝不跨严重度带。
	empty := map[string]float64{}
	g.assetWeightCache.Store(&empty)
	g.correlationBoostCache.Store(&empty)

	hi := g.computeRiskScoreForExisting(&model.Alert{Severity: "high", HostID: "itest-anomalous"})
	lo := g.computeRiskScoreForExisting(&model.Alert{Severity: "high", HostID: "itest-normal"})
	if hi <= lo {
		t.Fatalf("异常主机上的同级告警应排在前面: %d vs %d", hi, lo)
	}
	if hi >= severityBase("critical") {
		t.Fatalf("high 告警经 ML 加权后达到 %d，够到了 critical 的基础分 %d —— 越界定罪",
			hi, severityBase("critical"))
	}
}
