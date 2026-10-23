package internalauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// newProtected 构造一个仅 Middleware 保护的测试路由。
func newProtected(secret string) *gin.Engine {
	r := gin.New()
	r.Use(Middleware(secret))
	r.GET("/x", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return r
}

func TestMiddleware_ValidSecretPasses(t *testing.T) {
	r := newProtected("s3cr3t-value-1234")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderName, "s3cr3t-value-1234")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid secret: code = %d, want 200", w.Code)
	}
}

func TestMiddleware_WrongSecretRejected(t *testing.T) {
	r := newProtected("s3cr3t-value-1234")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderName, "wrong")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: code = %d, want 401", w.Code)
	}
}

func TestMiddleware_MissingSecretRejected(t *testing.T) {
	r := newProtected("s3cr3t-value-1234")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing secret: code = %d, want 401", w.Code)
	}
}

// TestMiddleware_EmptySecretRejectsAll 空 secret 时不得退化为放行：
// 任何请求（含空头）都必须 401，杜绝 fail-open。
func TestMiddleware_EmptySecretRejectsAll(t *testing.T) {
	r := newProtected("")
	// 缺头
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty secret + no header: code = %d, want 401", w.Code)
	}
	// 送空头（== 配置值）也不得放行
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderName, "")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty secret + empty header: code = %d, want 401", w.Code)
	}
}

// alertmanager 的 webhook 只会带标准 Authorization 头，不能加自定义头；
// 不认 Bearer 时它投递到内部告警接口全部 401，告警发不出去。
func TestMiddleware_BearerSecretPasses(t *testing.T) {
	r := newProtected("s3cr3t-value-1234")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t-value-1234")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bearer secret: code = %d, want 200", w.Code)
	}
}

func TestMiddleware_BearerWrongOrMalformedRejected(t *testing.T) {
	r := newProtected("s3cr3t-value-1234")
	for _, v := range []string{"Bearer wrong", "s3cr3t-value-1234", "Basic s3cr3t-value-1234", "Bearer ", "Bearer"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", v)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: code = %d, want 401", v, w.Code)
		}
	}
}

// 空 secret 时 Bearer 也不得放行。
func TestMiddleware_EmptySecretRejectsBearer(t *testing.T) {
	r := newProtected("")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer ")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty secret + empty bearer: code = %d, want 401", w.Code)
	}
}

// TestMiddlewareAny_NoValidSecretFailsClosed 一把有效的都没有时拒绝一切，空凭据也不能通过。
func TestMiddlewareAny_NoValidSecretFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", MiddlewareAny("", ""), func(c *gin.Context) { c.Status(http.StatusOK) })
	for _, sec := range []string{"", "anything"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if sec != "" {
			req.Header.Set(HeaderName, sec)
		}
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("secret=%q 应 401，实际 %d", sec, w.Code)
		}
	}
}

// TestAllowCIDRs_RejectsBadEntry 写错的网段要在启动时报出来，不能悄悄变成「不限制」。
func TestAllowCIDRs_RejectsBadEntry(t *testing.T) {
	if _, err := AllowCIDRs([]string{"10.0.0.0/24", "not-an-ip"}); err == nil {
		t.Fatal("非法网段应返回错误")
	}
	// 全是空项不能等同于「没配」：那是写了白名单却不生效
	if _, err := AllowCIDRs([]string{""}); err == nil {
		t.Fatal("空项应返回错误")
	}
	if _, err := AllowCIDRs([]string{"10.0.0.5", "::1"}); err != nil {
		t.Fatalf("单个 IP 应被接受: %v", err)
	}
}
