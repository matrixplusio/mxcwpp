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
	// analyst（非只读）拥有 alerts 模块写权限
	db.Create(&model.RolePermission{RoleCode: "analyst", PermCode: "alerts"})
	res := NewPermissionResolver(db, zap.NewNop())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("role", role); c.Next() })
	r.Use(res.EnforceWritePermissions())
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

// TestEnforce_ReadOnlyRoleBlockedOnWrite 审计员（只读角色）写操作必须被拦截。
func TestEnforce_ReadOnlyRoleBlockedOnWrite(t *testing.T) {
	r := newEnforceRouter(t, "auditor")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/alerts/1/resolve", nil))
	if got := roBodyCode(t, w); got != CodeForbidden {
		t.Errorf("auditor write: body code = %d, want %d (forbidden)", got, CodeForbidden)
	}
}

// TestEnforce_ReadOnlyRoleAllowedOnRead 审计员读操作放行。
func TestEnforce_ReadOnlyRoleAllowedOnRead(t *testing.T) {
	r := newEnforceRouter(t, "auditor")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil))
	if got := roBodyCode(t, w); got != 0 {
		t.Errorf("auditor read: body code = %d, want 0 (success)", got)
	}
}

// TestEnforce_NonReadOnlyWithPermAllowed 分析师（有 alerts 权限、非只读）写操作放行。
func TestEnforce_NonReadOnlyWithPermAllowed(t *testing.T) {
	r := newEnforceRouter(t, "analyst")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/alerts/1/resolve", nil))
	if got := roBodyCode(t, w); got != 0 {
		t.Errorf("analyst write with perm: body code = %d, want 0 (success)", got)
	}
}
