package detquality

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// testAlert 是 alerts 表的最小映射，只含本测试查询用到的列。
//
// 不能直接 AutoMigrate model.Alert：它的时间列带 MySQL 专有的
// ON UPDATE CURRENT_TIMESTAMP，sqlite 建表会报 near "ON": syntax error。
// 生产走 MySQL，这里只需要 id 与 rule_id 的对应关系。
type testAlert struct {
	ID     uint   `gorm:"primaryKey;autoIncrement"`
	RuleID string `gorm:"column:rule_id;index"`
	HostID string `gorm:"column:host_id"`
}

func (testAlert) TableName() string { return "alerts" }

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
	if err := db.AutoMigrate(&testAlert{}, &model.DetectionRule{}, &model.RuleShadowStat{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// incidents 同样手写 DDL：model.Incident.UpdatedAt 带 MySQL 专有的
	// ON UPDATE CURRENT_TIMESTAMP，sqlite 不认。casework 的测试出于同样原因也这么做。
	if err := db.Exec(`CREATE TABLE incidents (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		incident_id TEXT NOT NULL UNIQUE, host_id TEXT, hostname TEXT,
		status TEXT DEFAULT 'active', severity TEXT, risk_score REAL,
		tactics TEXT, tactic_count INTEGER, alert_ids TEXT, alert_count INTEGER,
		behavior_alert_count INTEGER, storyline_ids TEXT, title TEXT, summary TEXT,
		owner TEXT, assigned_at DATETIME, assigned_by TEXT,
		acked_at DATETIME, acked_by TEXT,
		ack_due_at DATETIME, resolve_due_at DATETIME,
		verdict TEXT, verdict_reason TEXT,
		escalated INTEGER DEFAULT 0, escalated_at DATETIME, escalated_to TEXT,
		close_reason TEXT,
		first_seen_at DATETIME, last_seen_at DATETIME,
		resolved_at DATETIME, resolved_by TEXT,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create incidents: %v", err)
	}
	return db
}

// seed 写入一条规则告警及其所属事件的研判结论。
func seed(t *testing.T, db *gorm.DB, ruleID string, verdicts []string) {
	t.Helper()
	seedAt(t, db, ruleID, verdicts, time.Now())
}

// seedAt 按指定发生时间写入样本，用于验证统计窗口。
//
// 显式写 created_at：LocalTime 不是 time.Time，GORM 不会自动回填，
// 生产上由 MySQL 列默认值 CURRENT_TIMESTAMP 补，sqlite 建表里没有这个默认值。
func seedAt(t *testing.T, db *gorm.DB, ruleID string, verdicts []string, at time.Time) {
	t.Helper()
	created := model.ToLocalTime(at)
	for i, v := range verdicts {
		a := testAlert{HostID: "h1", RuleID: ruleID}
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("create alert: %v", err)
		}
		inc := model.Incident{
			IncidentID: ruleID + "-inc" + itoa(uint(i)),
			HostID:     "h1",
			Severity:   "high",
			Verdict:    v,
			AlertIDs:   model.StringArray{itoa(a.ID)},
			CreatedAt:  created,
		}
		if err := db.Create(&inc).Error; err != nil {
			t.Fatalf("create incident: %v", err)
		}
	}
}

func itoa(v uint) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

// seedShadow 写入影子期观测量。
func seedShadow(t *testing.T, db *gorm.DB, ruleID string, hits int64, observedDays int) {
	t.Helper()
	stat := model.RuleShadowStat{
		RuleID:        ruleID,
		Hits:          hits,
		Hosts:         3,
		ObservedSince: model.ToLocalTime(time.Now().AddDate(0, 0, -observedDays)),
	}
	if err := db.Create(&stat).Error; err != nil {
		t.Fatalf("create shadow stat: %v", err)
	}
}

func rep(v string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// 精确率的分母必须是已研判样本，未研判的不能算进去。
//
// 这正是此前那个错误做法的核心问题：拿已关闭告警数当精确率，等于把
// "没人看所以批量关掉"算成检测准确——越是没人管的环境，看起来越准。
func TestPrecisionExcludesUndetermined(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	verdicts := append(rep(model.VerdictTruePositive, 18), rep(model.VerdictFalsePositive, 2)...)
	verdicts = append(verdicts, rep("", 500)...) // 500 条从没人看过
	seed(t, db, "cel-1", verdicts)

	q, err := s.RuleQuality("cel-1")
	if err != nil {
		t.Fatalf("RuleQuality: %v", err)
	}
	if q.Judged != 20 {
		t.Fatalf("已研判样本应为 20，实际 %d", q.Judged)
	}
	if q.Undetermined != 500 {
		t.Fatalf("未研判应为 500，实际 %d", q.Undetermined)
	}
	if q.Precision == nil {
		t.Fatal("20 条样本应可算出精确率")
	}
	if got := *q.Precision; got < 0.89 || got > 0.91 {
		t.Fatalf("精确率应为 0.90，实际 %.4f", got)
	}
}

// 样本不足时精确率必须是 nil（未知），不能是 0。
//
// 0 会被读成"精确率为零"，而实际含义是"不知道"——把缺失渲染成 0
// 与把请求失败显示成 0 是同一类错误。
func TestPrecisionUnknownWhenTooFewSamples(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seed(t, db, "cel-2", rep(model.VerdictTruePositive, 3))

	q, err := s.RuleQuality("cel-2")
	if err != nil {
		t.Fatalf("RuleQuality: %v", err)
	}
	if q.Precision != nil {
		t.Fatalf("3 条样本不该算出精确率，实际 %v", *q.Precision)
	}
}

// benign_true_positive 不是误报：检测确实命中了它要找的行为，只是该行为无害。
// 把它算成误报会让本来工作正常的规则被错误地调松甚至下线。
func TestBenignTruePositiveIsNotAnError(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seed(t, db, "cel-3", rep(model.VerdictBenignTruePositive, 20))

	q, err := s.RuleQuality("cel-3")
	if err != nil {
		t.Fatalf("RuleQuality: %v", err)
	}
	if q.Precision == nil || *q.Precision != 1.0 {
		t.Fatalf("全部为 benign_true_positive 时精确率应为 1.0，实际 %v", q.Precision)
	}
}

// 只统计属于该规则的事件，不能把同主机上别的规则的事件算进来。
func TestQualityIsScopedToRule(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seed(t, db, "cel-4", rep(model.VerdictTruePositive, 20))
	seed(t, db, "cel-5", rep(model.VerdictFalsePositive, 20)) // 同一主机，另一条规则

	q, err := s.RuleQuality("cel-4")
	if err != nil {
		t.Fatalf("RuleQuality: %v", err)
	}
	if q.FalsePositive != 0 {
		t.Fatalf("不该统计其他规则的误报，实际 %d", q.FalsePositive)
	}
	if q.TruePositive != 20 {
		t.Fatalf("真阳应为 20，实际 %d", q.TruePositive)
	}
}

// 精确率不达标时禁止晋级，并说明差在哪。
func TestPromotionBlockedByLowPrecision(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	verdicts := append(rep(model.VerdictTruePositive, 10), rep(model.VerdictFalsePositive, 10)...)
	seed(t, db, "cel-6", verdicts)

	// context 阶段才用精确率把关。
	rule := model.DetectionRule{Name: "noisy", Expression: "true", Severity: "high", Stage: model.RuleStageContext}
	rule.ID = 6
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	if _, err := s.PromoteRule(6, "tester"); err == nil {
		t.Fatal("精确率 50%% 的规则不该被允许晋级")
	}

	var after model.DetectionRule
	db.First(&after, 6)
	if after.Stage != model.RuleStageContext {
		t.Fatalf("晋级被拒后阶段不该变化，实际 %s", after.Stage)
	}
}

// 样本不足时同样禁止晋级：20 条里对 20 条才算数，3 条里对 3 条只说明它还没怎么响过。
func TestPromotionBlockedByTooFewSamples(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seed(t, db, "cel-7", rep(model.VerdictTruePositive, 5))

	rule := model.DetectionRule{Name: "young", Expression: "true", Severity: "high", Stage: model.RuleStageContext}
	rule.ID = 7
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	d, err := s.PromoteRule(7, "tester")
	if err == nil {
		t.Fatal("样本不足的规则不该被允许晋级")
	}
	if len(d.Reasons) == 0 {
		t.Fatal("拒绝晋级必须给出原因，否则运维只能反复点击试探")
	}
}

// 达标后可以晋级，且只升一级——不能从 shadow 直接跳到 alert。
func TestPromotionAdvancesOneStage(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)
	seed(t, db, "cel-8", rep(model.VerdictTruePositive, 20))

	rule := model.DetectionRule{Name: "good", Expression: "true", Severity: "high", Stage: model.RuleStageContext}
	rule.ID = 8
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	d, err := s.PromoteRule(8, "tester")
	if err != nil {
		t.Fatalf("达标规则应可晋级: %v", err)
	}
	if d.To != model.RuleStageAlert {
		t.Fatalf("context 应晋级到 alert，实际 %s", d.To)
	}
	var after model.DetectionRule
	db.First(&after, 8)
	if after.Stage != model.RuleStageAlert {
		t.Fatalf("阶段应已写入 alert，实际 %s", after.Stage)
	}
}

// draft → shadow 不需要数据：影子阶段本就是为了收集数据，
// 要求它先有数据是循环依赖，会让新规则永远卡在草稿。
func TestDraftPromotesWithoutData(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	rule := model.DetectionRule{Name: "new", Expression: "true", Severity: "high", Stage: model.RuleStageDraft}
	rule.ID = 9
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	if _, err := s.PromoteRule(9, "tester"); err != nil {
		t.Fatalf("草稿规则应能进入影子阶段: %v", err)
	}
}

// 降级不设门槛：噪声规则该能被立刻按下去，先停止打扰值班再慢慢查。
// 但必须写明原因，否则没人知道它为什么被关小了。
func TestDemoteRequiresReasonButNoEvidence(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	rule := model.DetectionRule{Name: "loud", Expression: "true", Severity: "high", Stage: model.RuleStageAlert}
	rule.ID = 10
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	if err := s.DemoteRule(10, model.RuleStageShadow, "", "tester"); err == nil {
		t.Fatal("降级必须写明原因")
	}
	if err := s.DemoteRule(10, model.RuleStageShadow, "凌晨误报 300 条", "tester"); err != nil {
		t.Fatalf("降级不该被数据门槛挡住: %v", err)
	}
	var after model.DetectionRule
	db.First(&after, 10)
	if after.Stage != model.RuleStageShadow {
		t.Fatalf("应已降级到 shadow，实际 %s", after.Stage)
	}
}

// 只有 alert 阶段才会独立告警；其余阶段命中也不该打扰到人。
func TestOnlyAlertStageInterruptsPeople(t *testing.T) {
	cases := map[string]bool{
		model.RuleStageDraft:   false,
		model.RuleStageShadow:  false,
		model.RuleStageContext: false,
		model.RuleStageAlert:   true,
		"":                     true, // 存量规则未回填时保持原有告警行为，不能静默失声
	}
	for stage, want := range cases {
		r := model.DetectionRule{Stage: stage}
		if got := r.AlertsIndependently(); got != want {
			t.Fatalf("阶段 %q 是否独立告警应为 %v，实际 %v", stage, want, got)
		}
	}
}

// 只统计近 QualityWindowDays 内的研判：一条规则半年前的表现不能证明它今天仍然准确，
// 环境、白名单、甚至规则本身都可能已经变过。
func TestQualityWindowExcludesStaleJudgements(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	old := time.Now().AddDate(0, 0, -(QualityWindowDays + 30))
	seedAt(t, db, "cel-11", rep(model.VerdictTruePositive, 20), old)

	q, err := s.RuleQuality("cel-11")
	if err != nil {
		t.Fatalf("RuleQuality: %v", err)
	}
	if q.Judged != 0 {
		t.Fatalf("窗口外的研判不该计入，实际 %d", q.Judged)
	}
	if q.Precision != nil {
		t.Fatal("窗口外样本不该撑出一个精确率")
	}
}

// shadow → context 看命中量而不是精确率。
//
// 影子规则不产生告警，也就不产生事件与研判结论。若这一跳也要求精确率，
// 影子规则永远凑不齐样本，会被永久卡死——晋级门槛必须是它够得着的那种证据。
func TestShadowPromotesOnVolumeNotPrecision(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	rule := model.DetectionRule{Name: "quiet", Expression: "true", Severity: "high", Stage: model.RuleStageShadow}
	rule.ID = 12
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	// 观察 14 天共 140 次命中（日均 10 次），且没有任何研判结论。
	seedShadow(t, db, "cel-12", 140, 14)

	d, err := s.PromoteRule(12, "tester")
	if err != nil {
		t.Fatalf("影子规则安静且观察充分时应可晋级: %v", err)
	}
	if d.To != model.RuleStageContext {
		t.Fatalf("shadow 应晋级到 context，实际 %s", d.To)
	}
}

// 噪声规则在影子阶段就该被拦住：日均命中过高的规则放开后不会让人更安全，
// 只会让人不再看告警。
func TestNoisyShadowRuleBlocked(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	rule := model.DetectionRule{Name: "flood", Expression: "true", Severity: "high", Stage: model.RuleStageShadow}
	rule.ID = 13
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	seedShadow(t, db, "cel-13", 100000, 10) // 日均一万次

	d, err := s.PromoteRule(13, "tester")
	if err == nil {
		t.Fatal("日均一万次命中的规则不该被放进关联链路")
	}
	if len(d.Reasons) == 0 {
		t.Fatal("必须说明为何被拦下")
	}
}

// 观察时长不足同样拦下：一天覆盖不到周末与月初结算这类周期性业务，
// 而它们恰恰是误报高发时段。
func TestShadowNeedsEnoughObservationTime(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	rule := model.DetectionRule{Name: "fresh", Expression: "true", Severity: "high", Stage: model.RuleStageShadow}
	rule.ID = 14
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	seedShadow(t, db, "cel-14", 5, 1) // 才观察一天

	if _, err := s.PromoteRule(14, "tester"); err == nil {
		t.Fatal("只观察一天的规则不该晋级")
	}
}

// 从没进过影子统计的规则不能晋级：没有观测记录不等于表现良好。
func TestShadowWithNoObservationBlocked(t *testing.T) {
	db := newTestDB(t)
	s := NewService(db, nil)

	rule := model.DetectionRule{Name: "ghost", Expression: "true", Severity: "high", Stage: model.RuleStageShadow}
	rule.ID = 15
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}

	if _, err := s.PromoteRule(15, "tester"); err == nil {
		t.Fatal("没有任何观测记录的规则不该晋级")
	}
}
