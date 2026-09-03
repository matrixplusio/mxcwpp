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
