package tenant

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFromContext_Empty(t *testing.T) {
	t.Parallel()
	id := FromContext(context.Background())
	if !id.IsZero() {
		t.Fatalf("expected zero Identity, got %+v", id)
	}
	if id.ID != "" {
		t.Fatalf("expected empty ID, got %q", id.ID)
	}
}

func TestFromContext_RoundTrip(t *testing.T) {
	t.Parallel()
	want := Identity{ID: "t-bank-a", Type: "standalone"}
	ctx := WithContext(context.Background(), want)
	got := FromContext(ctx)
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}

func TestIdentity_IsZero(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   Identity
		want bool
	}{
		{"empty", Identity{}, true},
		{"id only", Identity{ID: "t-x"}, false},
		{"platform admin only", Identity{IsPlatformAdmin: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.in.IsZero() != tc.want {
				t.Fatalf("IsZero(%+v): want %v", tc.in, tc.want)
			}
		})
	}
}

func TestMiddleware_BlocksMissingTenant(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Middleware())
	r.GET("/x", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(w, req)

	// 统一响应：缺租户 → HTTP 200 + body code 40100。
	if w.Code != 200 {
		t.Fatalf("expected 200 unified response, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "40100") {
		t.Fatalf("expected code 40100 missing_tenant in body, got %s", w.Body.String())
	}
}

func TestMiddleware_AllowsTenantIdentity(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{ID: "t-bank-a"})
		c.Next()
	})
	r.Use(Middleware())
	r.GET("/x", func(c *gin.Context) {
		// 业务 handler 能拿到 Identity
		id := GetIdentity(c)
		if id.ID != "t-bank-a" {
			t.Fatalf("expected t-bank-a, got %q", id.ID)
		}
		// request context 也应可见
		if FromContext(c.Request.Context()).ID != "t-bank-a" {
			t.Fatalf("request context missing identity")
		}
		c.Status(204)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMiddleware_BlocksPlatformAdminFromBusinessPath(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// 平台超管但没有当前 tenant_id（未通过 HeaderOverride / 切换器选定 tenant）
		SetIdentity(c, Identity{IsPlatformAdmin: true})
		c.Next()
	})
	r.Use(Middleware())
	r.GET("/x", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(w, req)

	// 统一响应：平台超管无当前租户 → HTTP 200 + body code 40100（成功也是 200，故必须校验 code）。
	if w.Code != 200 || !strings.Contains(w.Body.String(), "40100") {
		t.Fatalf("expected 200 + code 40100 missing_tenant for platform admin without X-Tenant-ID, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestAdminMiddleware_AllowsPlatformAdmin(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{IsPlatformAdmin: true})
		c.Next()
	})
	r.Use(AdminMiddleware())
	r.GET("/x", func(c *gin.Context) { c.Status(204) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestAdminMiddleware_BlocksNormalUser(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{ID: "t-bank-a"})
		c.Next()
	})
	r.Use(AdminMiddleware())
	r.GET("/x", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(w, req)

	// 统一响应：非超管访问 admin → HTTP 200 + body code 40300（成功也是 200，故必须校验 code）。
	if w.Code != 200 || !strings.Contains(w.Body.String(), "40300") {
		t.Fatalf("expected 200 + code 40300 platform_admin_required, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHeaderOverride_PlatformAdminSwitchesTenant(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{IsPlatformAdmin: true})
		c.Next()
	})
	r.Use(HeaderOverride())
	r.Use(Middleware())
	r.GET("/x", func(c *gin.Context) {
		id := GetIdentity(c)
		if id.ID != "t-bank-a" || !id.IsPlatformAdmin {
			t.Fatalf("expected t-bank-a + admin, got %+v", id)
		}
		c.Status(204)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Tenant-ID", "t-bank-a")
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHeaderOverride_NormalUserCannotSpoof(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		SetIdentity(c, Identity{ID: "t-bank-a"})
		c.Next()
	})
	r.Use(HeaderOverride())
	r.GET("/x", func(c *gin.Context) { c.Status(200) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Tenant-ID", "t-bank-b") // 假冒别的租户
	r.ServeHTTP(w, req)

	// 统一响应：普通用户冒充别的租户 → HTTP 200 + body code 40300。
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "40300") {
		t.Fatalf("expected code 40300 cross_tenant_denied in body, got %s", w.Body.String())
	}
}

func TestErrConstants(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrMissingTenant, ErrMissingTenant) {
		t.Fatalf("ErrMissingTenant should be identifiable")
	}
	if ErrCrossTenantDenied == nil {
		t.Fatalf("ErrCrossTenantDenied should be non-nil")
	}
}
