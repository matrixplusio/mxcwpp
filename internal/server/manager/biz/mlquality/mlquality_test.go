package mlquality

import (
	"os"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	// 手写 DDL：模型的时间列带 MySQL 专有的 ON UPDATE CURRENT_TIMESTAMP。
	if err := db.Exec(`CREATE TABLE anomaly_alerts (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id TEXT, hostname TEXT, alert_type TEXT, pattern_name TEXT,
		severity TEXT, anomaly_score REAL, top_metric TEXT, top_value REAL,
		description TEXT, trigger_context TEXT, status TEXT DEFAULT 'open',
		resolved_by TEXT, hit_count INTEGER DEFAULT 1, last_seen_at DATETIME,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create anomaly_alerts: %v", err)
	}
	if err := db.Exec(`CREATE TABLE feature_flags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		flag_key TEXT, value TEXT, description TEXT,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create feature_flags: %v", err)
	}
	return db
}

// seedAlerts 写入指定模式与状态的异常告警。
func seedAlerts(t *testing.T, db *gorm.DB, pattern, status string, n int) {
	t.Helper()
	for range n {
		err := db.Exec(
			`INSERT INTO anomaly_alerts (host_id, alert_type, pattern_name, status, created_at)
			 VALUES ('h1', 'correlation', ?, ?, CURRENT_TIMESTAMP)`,
			pattern, status).Error
		if err != nil {
			t.Fatalf("insert alert: %v", err)
		}
	}
}

// 未研判的告警不能计入精确率。
//
// 异常检测最常见的状态就是一大堆没人看过的 open。把它们算成对或算成错
// 都会得出一个凭空捏造的数字。
func TestOpenAlertsExcludedFromPrecision(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	seedAlerts(t, db, "c2_beacon", "confirmed", 20)
	seedAlerts(t, db, "c2_beacon", "false_positive", 10)
	seedAlerts(t, db, "c2_beacon", "open", 3000)

	q, err := s.Measure()
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if q.Judged != 30 {
		t.Fatalf("已研判应为 30，实际 %d", q.Judged)
	}
	if q.Open != 3000 {
		t.Fatalf("未研判应为 3000，实际 %d", q.Open)
	}
	if q.Precision == nil {
		t.Fatal("30 条已研判样本应可算出精确率")
	}
	if got := *q.Precision; got < 0.66 || got > 0.67 {
		t.Fatalf("精确率应约为 0.667，实际 %.4f", got)
	}
}

// 样本不足时精确率是 nil（未知），不是 0。
func TestPrecisionUnknownWithFewSamples(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seedAlerts(t, db, "c2_beacon", "confirmed", 5)

	q, err := s.Measure()
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if q.Precision != nil {
		t.Fatalf("样本不足不该算出精确率，实际 %v", *q.Precision)
	}
}

// alert 档在 1.0 一律不开，无论数据多好看。
//
// 无监督异常检测给出的是"少见"而不是"恶意"。少见的东西每天都有一堆，
// 让它独立定罪的结果是值班不再看告警。
func TestAlertModeIsNeverAllowed(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	// 给一份完美数据，确认它依然被拒。
	seedAlerts(t, db, "c2_beacon", "confirmed", 500)

	d, err := s.EvaluateModeChange(anomaly.ModeContext, anomaly.ModeAlert)
	if err != nil {
		t.Fatalf("EvaluateModeChange: %v", err)
	}
	if d.Allowed {
		t.Fatal("1.0 不该允许 ML 进入 alert 档，即使精确率很高")
	}
	if !d.Blocking {
		t.Fatal("该拒绝应标记为硬性限制，而不是可以通过补数据解决的门槛")
	}
}

// 降档永远允许且不需要证据：出问题时必须能立刻把它按回去。
func TestDowngradeAlwaysAllowed(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seedAlerts(t, db, "c2_beacon", "false_positive", 999)

	for _, tc := range []struct{ from, to anomaly.Mode }{
		{anomaly.ModeContext, anomaly.ModeShadow},
		{anomaly.ModeContext, anomaly.ModeOff},
		{anomaly.ModeShadow, anomaly.ModeOff},
	} {
		d, err := s.EvaluateModeChange(tc.from, tc.to)
		if err != nil {
			t.Fatalf("EvaluateModeChange(%s→%s): %v", tc.from, tc.to, err)
		}
		if !d.Allowed {
			t.Fatalf("%s → %s 降档应无条件允许", tc.from, tc.to)
		}
	}
}

// 精确率不达标时不允许升到 context 档。
func TestLowPrecisionBlocksContext(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seedAlerts(t, db, "c2_beacon", "confirmed", 10)
	seedAlerts(t, db, "c2_beacon", "false_positive", 30)

	d, err := s.EvaluateModeChange(anomaly.ModeShadow, anomaly.ModeContext)
	if err != nil {
		t.Fatalf("EvaluateModeChange: %v", err)
	}
	if d.Allowed {
		t.Fatal("精确率 25% 不该允许升档")
	}
	if len(d.Reasons) == 0 {
		t.Fatal("拒绝必须给出原因")
	}
}

// 单个模式塌陷也要拦，即使总体精确率过关。
//
// 线上出现过一个模式独自贡献三千多条误报，而总体数字当时并不刺眼。
// 值班感受到的是那个模式在刷屏，不是平均值。
func TestCollapsedPatternBlocksPromotion(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	// 总体：90 对 / 30 错 = 75%，高于 70% 门槛。
	seedAlerts(t, db, "priv_esc", "confirmed", 90)
	// 但 c2_beacon 单独看：2 对 / 28 错 = 6.7%。
	seedAlerts(t, db, "c2_beacon", "confirmed", 2)
	seedAlerts(t, db, "c2_beacon", "false_positive", 28)

	q, err := s.Measure()
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if q.Precision == nil || *q.Precision < MinPrecisionForContext {
		t.Fatalf("前提失效：总体精确率应过关，实际 %v", q.Precision)
	}

	d, err := s.EvaluateModeChange(anomaly.ModeShadow, anomaly.ModeContext)
	if err != nil {
		t.Fatalf("EvaluateModeChange: %v", err)
	}
	if d.Allowed {
		t.Fatal("单个模式塌陷时不该升档，总体精确率掩盖了它")
	}
}

// 开关行不存在时必须报错，不能静默成功。
//
// UPDATE 影响 0 行不会报错。若就此返回成功，调用方以为档位已改，
// 而检测器仍然读到旧值。
func TestMissingFlagRowIsNotSilentSuccess(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	if _, err := s.ApplyModeChange(anomaly.ModeContext, anomaly.ModeShadow, "tester"); err == nil {
		t.Fatal("开关行不存在时必须报错，否则是静默成功")
	}
}

// 降档能真正写入，且写的是 LoadMode 读取的那一列。
func TestDowngradeWritesTheColumnLoadModeReads(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	if err := db.Exec(`INSERT INTO feature_flags (flag_key, value) VALUES (?, 'context')`,
		model.FlagAnomalyDetectorMode).Error; err != nil {
		t.Fatalf("seed flag: %v", err)
	}

	if _, err := s.ApplyModeChange(anomaly.ModeContext, anomaly.ModeShadow, "tester"); err != nil {
		t.Fatalf("降档应成功: %v", err)
	}
	var got string
	if err := db.Raw(`SELECT value FROM feature_flags WHERE flag_key = ?`,
		model.FlagAnomalyDetectorMode).Scan(&got).Error; err != nil {
		t.Fatalf("read flag: %v", err)
	}
	if got != string(anomaly.ModeShadow) {
		t.Fatalf("档位应写入 shadow，实际 %q", got)
	}
}

// 分组必须重复整个表达式，不能用 SELECT 里的别名。
//
// MySQL 默认开启 only_full_group_by，按别名分组会被判为 "alert_type 不在 GROUP BY 中"
// （Error 1055）直接拒绝；sqlite 却接受别名分组。也就是说这个 bug 在本包的其余用例里
// 永远不会暴露——本地起真 manager 打接口时才 500。
//
// 这里退而求其次做源码断言：跑一个 MySQL 实例代价太大，但至少能钉住"别名分组"不再出现。
func TestGroupByRepeatsExpressionNotAlias(t *testing.T) {
	src, err := os.ReadFile("mlquality.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body := string(src)

	idx := strings.Index(body, "func (s *Service) Measure()")
	if idx < 0 {
		t.Fatal("找不到 Measure")
	}
	fn := body[idx:]
	if end := strings.Index(fn, "\nfunc "); end > 0 {
		fn = fn[:end]
	}
	if strings.Contains(fn, `Group("pattern_name`) {
		t.Fatal("不得按别名 pattern_name 分组：MySQL only_full_group_by 会拒绝（Error 1055）")
	}
	if !strings.Contains(fn, "patternExpr") {
		t.Fatal("SELECT 与 GROUP BY 必须复用同一个表达式常量，避免两处写法漂移")
	}
}

// ranking 档的门槛必须高于 context 档。
//
// ranking 会改变分析师**先看到什么**。排错顺序的代价不是多看一条，而是把真实威胁
// 推到列表后面——在告警多到看不完的环境里，排在后面等于没被看到。
func TestRankingGateIsStricterThanContext(t *testing.T) {
	if MinPrecisionForRanking <= MinPrecisionForContext {
		t.Fatalf("ranking 精确率门槛 %.2f 应高于 context 的 %.2f",
			MinPrecisionForRanking, MinPrecisionForContext)
	}
	if MinSamplesForRanking <= MinSamplesForPromotion {
		t.Fatalf("ranking 样本门槛 %d 应高于 context 的 %d",
			MinSamplesForRanking, MinSamplesForPromotion)
	}
}

// 达到 context 门槛但不够 ranking 门槛时，只能升到 context。
func TestContextPassesButRankingBlocked(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	// 36 对 / 9 错 = 80% 精确率、45 条已研判：
	// 过 context（≥30 条 / ≥70%），但样本数不到 ranking 要求的 50 条。
	seedAlerts(t, db, "priv_esc", "confirmed", 36)
	seedAlerts(t, db, "priv_esc", "false_positive", 9)

	ctxD, err := s.EvaluateModeChange(anomaly.ModeShadow, anomaly.ModeContext)
	if err != nil {
		t.Fatalf("EvaluateModeChange(context): %v", err)
	}
	if !ctxD.Allowed {
		t.Fatalf("应允许升到 context，实际被拒: %v", ctxD.Reasons)
	}

	rankD, err := s.EvaluateModeChange(anomaly.ModeContext, anomaly.ModeRanking)
	if err != nil {
		t.Fatalf("EvaluateModeChange(ranking): %v", err)
	}
	if rankD.Allowed {
		t.Fatal("样本数不足 ranking 门槛时不该放行")
	}
}

// ranking 仍然低于 alert：从 ranking 升 alert 依旧硬拒。
func TestAlertStillBlockedFromRanking(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seedAlerts(t, db, "priv_esc", "confirmed", 500)

	d, err := s.EvaluateModeChange(anomaly.ModeRanking, anomaly.ModeAlert)
	if err != nil {
		t.Fatalf("EvaluateModeChange: %v", err)
	}
	if d.Allowed || !d.Blocking {
		t.Fatal("1.0 封顶在 ranking，从 ranking 升 alert 必须硬拒")
	}
}

// 从 ranking 降回 context / shadow 无条件允许。
func TestDowngradeFromRankingAlwaysAllowed(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seedAlerts(t, db, "c2_beacon", "false_positive", 999)

	for _, to := range []anomaly.Mode{anomaly.ModeContext, anomaly.ModeShadow, anomaly.ModeOff} {
		d, err := s.EvaluateModeChange(anomaly.ModeRanking, to)
		if err != nil {
			t.Fatalf("EvaluateModeChange(%s): %v", to, err)
		}
		if !d.Allowed {
			t.Fatalf("ranking → %s 降档应无条件允许", to)
		}
	}
}
