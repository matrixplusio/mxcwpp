package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// denyRouter 构造一个仅装 EnforcePermissions 的路由，role 由前置中间件注入。
// 用一个真实未登记的路径验证 deny-by-default。
func denyRouter(role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	res := &PermissionResolver{
		logger: zap.NewNop(),
		loaded: true,
		cache: map[string]map[string]bool{
			"ops": {"operations": true},
		},
	}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if role != "" {
			c.Set("role", role)
		}
		c.Next()
	})
	r.Use(res.EnforcePermissions())
	r.GET("/api/v1/totally-unmapped-route", func(c *gin.Context) { Success(c, nil) })
	r.GET("/api/v1/hosts", func(c *gin.Context) { Success(c, nil) }) // assets:view
	return r
}

func get(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// TestDeny_UnmappedRouteDeniedForNonAdmin 未登记路由对非 admin fail-closed。
func TestDeny_UnmappedRouteDeniedForNonAdmin(t *testing.T) {
	w := get(denyRouter("ops"), "/api/v1/totally-unmapped-route")
	if got := roBodyCode(t, w); got != CodeForbidden {
		t.Fatalf("unmapped route for ops: body code = %d, want %d (forbidden)", got, CodeForbidden)
	}
}

// TestDeny_UnmappedRouteAllowedForAdmin admin 显式超管通路可达未登记路由。
func TestDeny_UnmappedRouteAllowedForAdmin(t *testing.T) {
	w := get(denyRouter("admin"), "/api/v1/totally-unmapped-route")
	if got := roBodyCode(t, w); got != 0 {
		t.Fatalf("unmapped route for admin: body code = %d, want 0 (success)", got)
	}
}

// TestDeny_MissingRoleDenied 缺 role（空/未注入）对已登记路由也拒绝。
func TestDeny_MissingRoleDenied(t *testing.T) {
	w := get(denyRouter(""), "/api/v1/hosts")
	if got := roBodyCode(t, w); got != CodeForbidden {
		t.Fatalf("missing role on mapped route: body code = %d, want %d (forbidden)", got, CodeForbidden)
	}
}

// TestDeny_MappedRouteWithoutPermDenied ops 无 assets:view，读 /hosts 被拒。
func TestDeny_MappedRouteWithoutPermDenied(t *testing.T) {
	w := get(denyRouter("ops"), "/api/v1/hosts")
	if got := roBodyCode(t, w); got != CodeForbidden {
		t.Fatalf("ops without assets:view: body code = %d, want %d (forbidden)", got, CodeForbidden)
	}
}
