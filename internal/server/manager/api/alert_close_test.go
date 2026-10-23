package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupCloseDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE alerts (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT DEFAULT 'observe', would_action TEXT, action TEXT, action_result TEXT,
		attck_tactic TEXT, attck_technique TEXT, result_id TEXT UNIQUE NOT NULL,
		host_id TEXT, rule_id TEXT, policy_id TEXT, source TEXT DEFAULT '', severity TEXT,
		risk_score INTEGER DEFAULT 0, category TEXT, title TEXT, description TEXT,
		actual TEXT, expected TEXT, fix_suggestion TEXT, status TEXT DEFAULT 'active',
		first_seen_at DATETIME, last_seen_at DATETIME, hit_count INTEGER DEFAULT 1,
		last_notified_at DATETIME, notify_count INTEGER DEFAULT 0,
		resolved_at DATETIME, resolved_by TEXT, resolve_reason TEXT,
		verdict TEXT, verdict_basis TEXT, group_key TEXT, recurrence_of INTEGER, suppression_id INTEGER,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

var seedSeq int

func seedAlert(t *testing.T, db *gorm.DB, status model.AlertStatus) uint {
	t.Helper()
	seedSeq++
	a := model.Alert{ResultID: fmt.Sprintf("r-%d", seedSeq), HostID: "h1", RuleID: "cel-1",
		Severity: "high", Title: "t", Status: status, HitCount: 1}
	if err := db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func closeRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := &AlertsHandler{db: db, logger: zap.NewNop()}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("username", "alice"); c.Next() })
	r.POST("/alerts/:id/resolve", h.ResolveAlert)
	r.POST("/alerts/:id/ignore", h.IgnoreAlert)
	r.POST("/alerts/batch/ignore", h.BatchIgnoreAlerts)
	return r
}

// post 返回响应体里的业务码：本项目接口一律 HTTP 200，成败看 body.code（0 为成功）。
func post(r *gin.Engine, path string, body any) int {
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		return -1
	}
	return resp.Code
}

// 关闭必须给出研判结论与原因——否则这次处置无从审计，规则质量也无从统计。
func TestCloseRequiresVerdictAndReason(t *testing.T) {
	db := setupCloseDB(t)
	r := closeRouter(db)
	id := seedAlert(t, db, model.AlertStatusActive)
	for _, body := range []map[string]string{
		{"reason": "看过了"},
		{"verdict": "maybe", "reason": "看过了"},
		{"verdict": "false_positive", "reason": "   "},
	} {
		if code := post(r, fmt.Sprintf("/alerts/%d/ignore", id), body); code == 0 {
			t.Errorf("%v 应被拒，实际 %d", body, code)
		}
	}
	var a model.Alert
	db.First(&a, id)
	if a.Status != model.AlertStatusActive {
		t.Fatalf("被拒的请求不应改动告警: %q", a.Status)
	}
}

func TestCloseRecordsVerdictReasonAndActor(t *testing.T) {
	db := setupCloseDB(t)
	r := closeRouter(db)
	id := seedAlert(t, db, model.AlertStatusActive)
	if code := post(r, fmt.Sprintf("/alerts/%d/ignore", id),
		map[string]string{"verdict": "false_positive", "reason": "内网资产测绘"}); code != 0 {
		t.Fatalf("合法请求应成功，实际 %d", code)
	}
	var a model.Alert
	db.First(&a, id)
	if a.Status != model.AlertStatusIgnored || a.Verdict != "false_positive" ||
		a.ResolveReason != "内网资产测绘" || a.ResolvedBy != "alice" || a.ResolvedAt == nil {
		t.Fatalf("处置记录不完整: %+v", a)
	}
}

// 关闭过的告警是定案记录，不能再被改写。
func TestClosedAlertCannotBeClosedAgain(t *testing.T) {
	db := setupCloseDB(t)
	r := closeRouter(db)
	id := seedAlert(t, db, model.AlertStatusResolved)
	if code := post(r, fmt.Sprintf("/alerts/%d/ignore", id),
		map[string]string{"verdict": "false_positive", "reason": "x"}); code == 0 {
		t.Fatalf("已关闭的告警不应再被关闭，实际 %d", code)
	}
}

// 批量操作只关闭仍开着的告警（含被抑制的），已关闭的跳过。
func TestBatchCloseOnlyTouchesOpenAlerts(t *testing.T) {
	db := setupCloseDB(t)
	r := closeRouter(db)
	active := seedAlert(t, db, model.AlertStatusActive)
	suppressed := seedAlert(t, db, model.AlertStatusSuppressed)
	resolved := seedAlert(t, db, model.AlertStatusResolved)
	if code := post(r, "/alerts/batch/ignore", map[string]any{
		"ids": []uint{active, suppressed, resolved}, "verdict": "benign_true_positive", "reason": "运维变更",
	}); code != 0 {
		t.Fatalf("批量关闭应成功，实际 %d", code)
	}
	var rows []model.Alert
	db.Order("id").Find(&rows)
	if rows[0].Status != model.AlertStatusIgnored || rows[1].Status != model.AlertStatusIgnored {
		t.Errorf("开着的告警应被关闭: %q %q", rows[0].Status, rows[1].Status)
	}
	if rows[2].Status != model.AlertStatusResolved || rows[2].Verdict != "" {
		t.Errorf("已关闭的告警不应被改写: %+v", rows[2])
	}
	if rows[0].VerdictBasis != model.VerdictBasisBatch || rows[1].VerdictBasis != model.VerdictBasisBatch {
		t.Errorf("批量关闭的结论应标为 batch: %q %q", rows[0].VerdictBasis, rows[1].VerdictBasis)
	}
}

// 单条关闭的结论标为逐条研判，计入规则准确率。
func TestSingleCloseIsIndividualVerdict(t *testing.T) {
	db := setupCloseDB(t)
	r := closeRouter(db)
	id := seedAlert(t, db, model.AlertStatusActive)
	if code := post(r, fmt.Sprintf("/alerts/%d/resolve", id),
		map[string]string{"verdict": "false_positive", "reason": "dnf 升级写入"}); code != 0 {
		t.Fatalf("合法请求应成功，实际 %d", code)
	}
	var a model.Alert
	db.First(&a, id)
	if a.VerdictBasis != model.VerdictBasisIndividual {
		t.Fatalf("单条关闭应标为 individual，实际 %q", a.VerdictBasis)
	}
}
