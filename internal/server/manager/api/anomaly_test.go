package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupAnomalyAPIDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AnomalyAlert{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

func setupAnomalyRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("username", "tester"); c.Next() })
	h := NewAnomalyHandler(db, zap.NewNop())
	r.GET("/anomalies", h.ListAnomalies)
	r.PUT("/anomalies/:id/resolve", h.ResolveAnomaly)
	return r
}

// TestListAnomaliesOrdering 校验列表按 last_seen_at DESC, id DESC 排序（最新复发在前，同刻按 id 倒序）。
func TestListAnomaliesOrdering(t *testing.T) {
	db := setupAnomalyAPIDB(t)
	r := setupAnomalyRouter(db)

	lt := func(s string) model.LocalTime {
		tm, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.Local)
		if err != nil {
			t.Fatalf("parse time: %v", err)
		}
		return model.LocalTime(tm)
	}
	// 插入顺序 id=1..4；last_seen：r1=T2, r2=T2, r3=T3, r4=T1。
	for _, a := range []model.AnomalyAlert{
		{HostID: "h1", AlertType: "correlation", Status: "open", LastSeenAt: lt("2026-01-02 00:00:00")},
		{HostID: "h2", AlertType: "correlation", Status: "open", LastSeenAt: lt("2026-01-02 00:00:00")},
		{HostID: "h3", AlertType: "correlation", Status: "open", LastSeenAt: lt("2026-01-03 00:00:00")},
		{HostID: "h4", AlertType: "correlation", Status: "open", LastSeenAt: lt("2026-01-01 00:00:00")},
	} {
		a := a
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/anomalies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Total int64 `json:"total"`
			Items []struct {
				ID uint `json:"id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("code=%d, want 0", resp.Code)
	}
	if resp.Data.Total != 4 {
		t.Fatalf("total=%d, want 4", resp.Data.Total)
	}
	// 期望顺序：id3(T3) > id2(T2) > id1(T2, id 倒序) > id4(T1)。
	want := []uint{3, 2, 1, 4}
	if len(resp.Data.Items) != len(want) {
		t.Fatalf("items len=%d, want %d", len(resp.Data.Items), len(want))
	}
	for i, id := range want {
		if resp.Data.Items[i].ID != id {
			t.Errorf("order[%d]=%d, want %d (full=%+v)", i, resp.Data.Items[i].ID, id, resp.Data.Items)
		}
	}
}

// TestResolveAnomalyNotFound 校验不存在的 id 返回 CodeNotFound（区别于 DB error）。
func TestResolveAnomalyNotFound(t *testing.T) {
	db := setupAnomalyAPIDB(t)
	r := setupAnomalyRouter(db)

	body, _ := json.Marshal(map[string]string{"status": "confirmed"})
	req := httptest.NewRequest(http.MethodPut, "/anomalies/999/resolve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := parseRespCode(w); got != float64(CodeNotFound) {
		t.Errorf("code=%v, want %v body=%s", got, CodeNotFound, w.Body.String())
	}
}

// TestResolveAnomalyReturnsLatest 校验更新后返回最新行（status/resolved_by 为更新后的值，非旧值）。
func TestResolveAnomalyReturnsLatest(t *testing.T) {
	db := setupAnomalyAPIDB(t)
	r := setupAnomalyRouter(db)

	alert := model.AnomalyAlert{HostID: "h1", AlertType: "correlation", Status: "open"}
	if err := db.Create(&alert).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"status": "false_positive"})
	req := httptest.NewRequest(http.MethodPut, "/anomalies/1/resolve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			ID         uint   `json:"id"`
			Status     string `json:"status"`
			ResolvedBy string `json:"resolved_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if resp.Code != 0 {
		t.Fatalf("code=%d, want 0", resp.Code)
	}
	if resp.Data.Status != "false_positive" {
		t.Errorf("返回 status=%q, want false_positive（应回读最新行）", resp.Data.Status)
	}
	if resp.Data.ResolvedBy != "tester" {
		t.Errorf("返回 resolved_by=%q, want tester", resp.Data.ResolvedBy)
	}

	// DB 落库校验。
	var reloaded model.AnomalyAlert
	if err := db.First(&reloaded, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Status != "false_positive" || reloaded.ResolvedBy != "tester" {
		t.Errorf("DB row status=%q resolved_by=%q, want false_positive/tester", reloaded.Status, reloaded.ResolvedBy)
	}
}
