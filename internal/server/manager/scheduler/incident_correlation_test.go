package scheduler

import (
	"fmt"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"reflect"
	"testing"
	"time"
)

func TestOrderTactics_KillChainOrderDedup(t *testing.T) {
	// 乱序 + 重复 + 空 + 未知 → 去重、kill-chain 排序、未知置末
	in := []string{"TA0011", "", "TA0001", "TA0002", "TA0001", "TA9999"}
	got := orderTactics(in)
	want := []string{"TA0001", "TA0002", "TA0011", "TA9999"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderTactics=%v want %v", got, want)
	}
}

func TestIsIncidentWorthy(t *testing.T) {
	cases := []struct {
		alerts, tactics int
		want            bool
	}{
		{1, 2, true},  // 跨2战术
		{3, 1, true},  // 3告警
		{2, 1, false}, // 都不够
		{1, 1, false},
		{5, 0, true},
	}
	for _, c := range cases {
		if got := isIncidentWorthy(c.alerts, c.tactics, false); got != c.want {
			t.Errorf("isIncidentWorthy(a=%d,t=%d)=%v want %v", c.alerts, c.tactics, got, c.want)
		}
	}
}

func TestAggregateRisk_MultiTacticBoostAndCap(t *testing.T) {
	if r := aggregateRisk(50, 1, false); r != 50 {
		t.Errorf("单战术不 boost: %v want 50", r)
	}
	if r := aggregateRisk(50, 2, false); r != 60 { // 50*1.2
		t.Errorf("多战术 boost: %v want 60", r)
	}
	if r := aggregateRisk(90, 3, false); r != 100 { // 90*1.2=108 封顶 100
		t.Errorf("封顶: %v want 100", r)
	}
	if r := aggregateRisk(50, 1, true); r != 65 { // 50*1.3 攻击链 boost
		t.Errorf("攻击链 boost: %v want 65", r)
	}
}

func TestFilterHighPrevalence(t *testing.T) {
	alerts := []incidentAlert{
		{ID: 1, RuleID: "cel-25"}, // 高流行度端口规则 → 剔除
		{ID: 2, RuleID: "cel-256"},
		{ID: 3, RuleID: "cel-20"}, // 高流行度 → 剔除
		{ID: 4, RuleID: ""},       // 空 rule_id 不在噪声集 → 保留
	}
	highPrev := map[string]struct{}{"cel-25": {}, "cel-20": {}}

	got := filterHighPrevalence(alerts, highPrev)
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 4 {
		t.Fatalf("filterHighPrevalence=%v want [id2 id4]", got)
	}

	// 空噪声集：原样返回，不分配。
	if same := filterHighPrevalence(alerts, nil); len(same) != len(alerts) {
		t.Errorf("空噪声集应原样返回: len=%d want %d", len(same), len(alerts))
	}
}

func TestSummarizeIncident(t *testing.T) {
	alerts := []incidentAlert{
		{ID: 1, Severity: "medium", RiskScore: 40, ATTCKTactic: "TA0011"},
		{ID: 2, Severity: "critical", RiskScore: 90, ATTCKTactic: "TA0001"},
		{ID: 3, Severity: "high", RiskScore: 60, ATTCKTactic: "TA0001"}, // 重复战术
	}
	sev, risk, tactics, ids := summarizeIncident(alerts)
	if sev != "critical" {
		t.Errorf("maxSeverity=%s want critical", sev)
	}
	if risk != 90 {
		t.Errorf("maxRisk=%v want 90", risk)
	}
	if !reflect.DeepEqual(tactics, []string{"TA0001", "TA0011"}) {
		t.Errorf("tactics=%v want [TA0001 TA0011]", tactics)
	}
	if !reflect.DeepEqual(ids, []string{"1", "2", "3"}) {
		t.Errorf("ids=%v", ids)
	}
}

// 事件的研判上下文只取同主机、近窗内、被抑制的告警。
func TestSuppressedContextPicksOnlySuppressedInWindow(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,
		result_id TEXT, host_id TEXT, status TEXT, last_seen_at DATETIME)`).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	for _, r := range []struct {
		host, status string
		at           time.Time
	}{
		{"h1", "suppressed", now}, // 选中
		{"h1", "active", now},     // 不是被抑制的
		{"h1", "suppressed", old}, // 窗口外
		{"h2", "suppressed", now}, // 别的主机
	} {
		db.Exec(`INSERT INTO alerts (result_id, host_id, status, last_seen_at) VALUES (?, ?, ?, ?)`,
			r.host+r.status+r.at.String(), r.host, r.status, model.ToLocalTime(r.at))
	}

	got := suppressedContext(db, "h1", model.ToLocalTime(now.Add(-time.Hour)))
	if len(got) != 1 || got[0] != "1" {
		t.Fatalf("只应取到 id=1，实际 %v", got)
	}
}

// 事件挂的故事线：窗口内、带告警的才挂（已关闭的也算），窗口外的与没有告警的不挂；
// 按风险从高到低，最多 incidentStorylineLimit 条。
func TestWindowStorylineIDs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.Storyline{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	recent := model.LocalTime(now.Add(-5 * time.Hour))
	rows := []model.Storyline{
		{StoryID: "closed-in-window", HostID: "h1", Status: model.StorylineStatusClosed, AlertCount: 2, RiskScore: 90, LastSeenAt: recent},
		{StoryID: "no-alert", HostID: "h1", Status: model.StorylineStatusActive, AlertCount: 0, RiskScore: 99, LastSeenAt: recent},
		{StoryID: "active-old", HostID: "h1", Status: model.StorylineStatusActive, AlertCount: 5, RiskScore: 95, LastSeenAt: model.LocalTime(now.Add(-48 * time.Hour))},
		{StoryID: "other-host", HostID: "h2", Status: model.StorylineStatusActive, AlertCount: 5, RiskScore: 95, LastSeenAt: model.LocalTime(now)},
	}
	// 再放一批低风险的，数量超过上限
	for i := 0; i < incidentStorylineLimit+10; i++ {
		rows = append(rows, model.Storyline{StoryID: fmt.Sprintf("low-%03d", i), HostID: "h1",
			Status: model.StorylineStatusClosed, AlertCount: 1, RiskScore: 10, LastSeenAt: recent})
	}
	if err := db.CreateInBatches(rows, 50).Error; err != nil {
		t.Fatal(err)
	}

	got := windowStorylineIDs(db, "h1", model.ToLocalTime(now.Add(-incidentWindow)))
	if len(got) != incidentStorylineLimit {
		t.Fatalf("应截到上限 %d 条，得 %d", incidentStorylineLimit, len(got))
	}
	if got[0] != "closed-in-window" {
		t.Errorf("风险最高的应排第一，得 %s", got[0])
	}
	for _, id := range got {
		if id == "no-alert" || id == "active-old" || id == "other-host" {
			t.Errorf("不该挂上 %s", id)
		}
	}
}

// 窗口内故事线很少时照样只返回窗口内的那几条；很多时只从最近 incidentStorylineScan 条里挑。
// 两种情况读取量都有上限——按风险排序直接取前 N 条的写法在第一种情况下要读完该主机全部历史。
func TestWindowStorylineIDsBounded(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.Storyline{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cutoff := model.ToLocalTime(now.Add(-incidentWindow))

	// few：窗口内只有 3 条，窗口外有大量高风险历史
	var rows []model.Storyline
	for i := 0; i < 3; i++ {
		rows = append(rows, model.Storyline{StoryID: fmt.Sprintf("few-in-%d", i), HostID: "few", AlertCount: 1, RiskScore: 20,
			LastSeenAt: model.LocalTime(now.Add(-time.Duration(i+1) * time.Hour))})
	}
	for i := 0; i < 200; i++ {
		rows = append(rows, model.Storyline{StoryID: fmt.Sprintf("few-old-%d", i), HostID: "few", AlertCount: 9, RiskScore: 100,
			LastSeenAt: model.LocalTime(now.Add(-72 * time.Hour))})
	}
	// many：窗口内条数超过扫描上限；最近的那批里放一条高风险的，更早的那批里也放一条
	for i := 0; i < incidentStorylineScan+100; i++ {
		risk := 10.0
		id := fmt.Sprintf("many-%04d", i)
		if i == 5 {
			risk, id = 100, "many-recent-high"
		}
		if i == incidentStorylineScan+50 {
			risk, id = 100, "many-beyond-scan-high"
		}
		rows = append(rows, model.Storyline{StoryID: id, HostID: "many", AlertCount: 1, RiskScore: risk,
			LastSeenAt: model.LocalTime(now.Add(-time.Duration(i) * time.Second))})
	}
	if err := db.CreateInBatches(rows, 100).Error; err != nil {
		t.Fatal(err)
	}

	if got := windowStorylineIDs(db, "few", cutoff); len(got) != 3 {
		t.Errorf("few：应只返回窗口内的 3 条，得 %d: %v", len(got), got)
	}

	got := windowStorylineIDs(db, "many", cutoff)
	if len(got) != incidentStorylineLimit || got[0] != "many-recent-high" {
		t.Errorf("many：应返回 %d 条且风险最高的排第一，得 %d 条，首条 %v", incidentStorylineLimit, len(got), got[:1])
	}
	for _, id := range got {
		if id == "many-beyond-scan-high" {
			t.Error("many：超出扫描上限的更早记录不应被读到")
		}
	}
}

// 自动关闭的事件结论只从已研判的成员告警汇总；没人判过就留空，不替人下结论。
func TestRollupVerdict(t *testing.T) {
	tp, benign, fp := model.VerdictTruePositive, model.VerdictBenignTruePositive, model.VerdictFalsePositive
	cases := []struct {
		name     string
		verdicts []string
		members  int
		want     string
	}{
		{"有一条真实威胁", []string{fp, tp, ""}, 3, tp},
		{"良性与误报混合", []string{fp, benign}, 2, benign},
		{"全部误报", []string{fp, fp}, 2, fp},
		{"只判了一部分误报", []string{fp, ""}, 2, ""},
		{"没人判过", []string{"", ""}, 2, ""},
		{"成员告警已被清理", nil, 2, ""},
	}
	for _, c := range cases {
		got, reason := rollupVerdict(c.verdicts, c.members)
		if got != c.want {
			t.Errorf("%s：得 %q，期望 %q", c.name, got, c.want)
		}
		if (got == "") != (reason == "") {
			t.Errorf("%s：结论与依据应同时有或同时无", c.name)
		}
	}
}
