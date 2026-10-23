package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newEnforceRouter(t *testing.T, role string) *gin.Engine {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.RolePermission{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// analyst: 可看 + 可处置告警；auditor: 只可看（只读）。
	for _, rp := range []model.RolePermission{
		{RoleCode: "analyst", PermCode: "alerts:view"},
		{RoleCode: "analyst", PermCode: "alerts:respond"},
		{RoleCode: "auditor", PermCode: "alerts:view"},
	} {
		db.Create(&rp)
	}
	res := NewPermissionResolver(db, zap.NewNop())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("role", role); c.Next() })
	r.Use(res.EnforcePermissions())
	r.POST("/api/v1/alerts/:id/resolve", func(c *gin.Context) { Success(c, nil) })
	r.GET("/api/v1/alerts", func(c *gin.Context) { Success(c, nil) })
	return r
}

func roBodyCode(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v (%s)", err, w.Body.String())
	}
	return resp.Code
}

// TestEnforce_RespondNeedsRespondPerm 审计员（只 view，无 respond）不能处置告警。
func TestEnforce_RespondNeedsRespondPerm(t *testing.T) {
	r := newEnforceRouter(t, "auditor")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/alerts/1/resolve", nil))
	if got := roBodyCode(t, w); got != CodeForbidden {
		t.Errorf("auditor resolve: body code = %d, want %d (forbidden)", got, CodeForbidden)
	}
}

// TestEnforce_ViewAllowedForReadOnly 审计员有 alerts:view，可读告警列表。
func TestEnforce_ViewAllowedForReadOnly(t *testing.T) {
	r := newEnforceRouter(t, "auditor")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil))
	if got := roBodyCode(t, w); got != 0 {
		t.Errorf("auditor read alerts: body code = %d, want 0 (success)", got)
	}
}

// TestEnforce_RespondAllowedWithPerm 分析师有 alerts:respond，可处置告警。
func TestEnforce_RespondAllowedWithPerm(t *testing.T) {
	r := newEnforceRouter(t, "analyst")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/alerts/1/resolve", nil))
	if got := roBodyCode(t, w); got != 0 {
		t.Errorf("analyst resolve with perm: body code = %d, want 0 (success)", got)
	}
}
