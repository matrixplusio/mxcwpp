package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/common/tenant"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// bodyCode 解析统一响应 body 中的业务 code 字段（业务接口一律 HTTP 200）。
func bodyCode(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v body=%s", err, w.Body.String())
	}
	code, ok := resp["code"].(float64)
	if !ok {
		t.Fatalf("missing code field, body=%s", w.Body.String())
	}
	return int(code)
}

func setupAdminTenantTestDB(t *testing.T) (*gorm.DB, *AdminTenantsHandler) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// SQLite 不支持 MySQL 的 ON UPDATE CURRENT_TIMESTAMP，
	// 直接手写兼容 SQL（仅测试用）。
	if err := db.Exec(`CREATE TABLE tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'standalone',
		parent_id TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		default_mode TEXT NOT NULL DEFAULT 'observe',
		ml_enabled INTEGER DEFAULT 1,
		llm_enabled INTEGER DEFAULT 0,
		llm_provider TEXT,
		quota_agents INTEGER DEFAULT 100,
		quota_llm_usd REAL DEFAULT 100,
		quota_events_per_day INTEGER DEFAULT 1000000000,
		retention_alerts_days INTEGER DEFAULT 90,
		retention_events_days INTEGER DEFAULT 30,
		retention_audit_days INTEGER DEFAULT 180,
		isolation_strategy TEXT DEFAULT 'shared',
		isolated_db_dsn TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`).Error; err != nil {
		t.Fatalf("create tenants table: %v", err)
	}
	// 预置默认租户
	def := model.Tenant{
		ID:          model.DefaultTenantID,
		Name:        "Default",
		Type:        model.TenantTypeInternal,
		Status:      model.TenantStatusActive,
		DefaultMode: model.TenantModeObserve,
	}
	if err := db.Create(&def).Error; err != nil {
		t.Fatalf("seed default tenant: %v", err)
	}
	return db, NewAdminTenantsHandler(db, zap.NewNop())
}

func newAdminRouter(h *AdminTenantsHandler, asAdmin bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if asAdmin {
			tenant.SetIdentity(c, tenant.Identity{IsPlatformAdmin: true})
		} else {
			tenant.SetIdentity(c, tenant.Identity{ID: "t-normal"})
		}
		c.Next()
	})
	r.Use(tenant.AdminMiddleware())
	r.GET("/admin/tenants", h.ListTenants)
	r.GET("/admin/tenants/:id", h.GetTenant)
	r.POST("/admin/tenants", h.CreateTenant)
	r.POST("/admin/tenants/:id/suspend", h.SuspendTenant)
	r.POST("/admin/tenants/:id/resume", h.ResumeTenant)
	return r
}

func TestAdminTenants_ListAsPlatformAdmin(t *testing.T) {
	t.Parallel()
	_, h := setupAdminTenantTestDB(t)
	r := newAdminRouter(h, true)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := bodyCode(t, w); got != CodeOK {
		t.Fatalf("expected code %d, got %d body=%s", CodeOK, got, w.Body.String())
	}
}

func TestAdminTenants_NormalUserBlocked(t *testing.T) {
	t.Parallel()
	_, h := setupAdminTenantTestDB(t)
	r := newAdminRouter(h, false)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := bodyCode(t, w); got != CodeForbidden {
		t.Fatalf("expected code %d platform_admin_required, got %d body=%s", CodeForbidden, got, w.Body.String())
	}
}

func TestAdminTenants_CreateAndGet(t *testing.T) {
	t.Parallel()
	_, h := setupAdminTenantTestDB(t)
	r := newAdminRouter(h, true)

	body, _ := json.Marshal(map[string]any{
		"id":           "t-bank-a",
		"name":         "Bank A",
		"type":         "standalone",
		"quota_agents": 5000,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("create expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := bodyCode(t, w); got != CodeOK {
		t.Fatalf("create expected code %d, got %d body=%s", CodeOK, got, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/admin/tenants/t-bank-a", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("get expected 200, got %d body=%s", w2.Code, w2.Body.String())
	}
	if got := bodyCode(t, w2); got != CodeOK {
		t.Fatalf("get expected code %d, got %d body=%s", CodeOK, got, w2.Body.String())
	}
}

func TestAdminTenants_CreateDuplicateRejected(t *testing.T) {
	t.Parallel()
	_, h := setupAdminTenantTestDB(t)
	r := newAdminRouter(h, true)

	body, _ := json.Marshal(map[string]any{
		"id":   model.DefaultTenantID, // 已存在
		"name": "Dup",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := bodyCode(t, w); got != CodeInvalidParam {
		t.Fatalf("expected code %d duplicate, got %d body=%s", CodeInvalidParam, got, w.Body.String())
	}
}

func TestAdminTenants_CannotSuspendDefault(t *testing.T) {
	t.Parallel()
	_, h := setupAdminTenantTestDB(t)
	r := newAdminRouter(h, true)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/tenants/"+model.DefaultTenantID+"/suspend", http.NoBody)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := bodyCode(t, w); got != CodeInvalidParam {
		t.Fatalf("expected code %d, got %d body=%s", CodeInvalidParam, got, w.Body.String())
	}
}

func TestAdminTenants_SuspendAndResume(t *testing.T) {
	t.Parallel()
	db, h := setupAdminTenantTestDB(t)
	// 预置一个非默认租户
	other := model.Tenant{
		ID:          "t-other",
		Name:        "Other",
		Type:        model.TenantTypeStandalone,
		Status:      model.TenantStatusActive,
		DefaultMode: model.TenantModeObserve,
	}
	if err := db.Create(&other).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := newAdminRouter(h, true)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/tenants/t-other/suspend", http.NoBody)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("suspend expected 200, got %d", w.Code)
	}
	if got := bodyCode(t, w); got != CodeOK {
		t.Fatalf("suspend expected code %d, got %d body=%s", CodeOK, got, w.Body.String())
	}

	var t1 model.Tenant
	db.Where("id = ?", "t-other").First(&t1)
	if t1.Status != model.TenantStatusSuspended {
		t.Fatalf("expected suspended, got %s", t1.Status)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/admin/tenants/t-other/resume", http.NoBody)
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("resume expected 200, got %d", w2.Code)
	}
	if got := bodyCode(t, w2); got != CodeOK {
		t.Fatalf("resume expected code %d, got %d body=%s", CodeOK, got, w2.Body.String())
	}

	var t2 model.Tenant
	db.Where("id = ?", "t-other").First(&t2)
	if t2.Status != model.TenantStatusActive {
		t.Fatalf("expected active, got %s", t2.Status)
	}
}
