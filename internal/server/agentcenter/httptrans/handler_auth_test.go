package httptrans

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/internalauth"
)

const testSecret = "ac-mgmt-secret-abcdef123456"

func newACRouter(secret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	// transfer 传 nil：受保护路由的 401 在 handler 前中止；/health 不触碰 transfer。
	h := NewHandler(nil, zap.NewNop())
	r := gin.New()
	h.RegisterRoutes(r.Group("/"), secret)
	return r
}

func do(r *gin.Engine, method, path, secret, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set(internalauth.HeaderName, secret)
	}
	r.ServeHTTP(w, req)
	return w
}

// protectedRoutes 是所有必须强制内部认证的管理接口。
var protectedRoutes = []struct{ method, path string }{
	{http.MethodPost, "/command"},
	{http.MethodPost, "/command/batch"},
	{http.MethodPost, "/dependency/install"},
	{http.MethodGet, "/conn/stat"},
	{http.MethodGet, "/conn/list"},
}

func TestAC_ProtectedRoutesRejectMissingSecret(t *testing.T) {
	r := newACRouter(testSecret)
	for _, rt := range protectedRoutes {
		w := do(r, rt.method, rt.path, "", "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s no secret: code = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func TestAC_ProtectedRoutesRejectWrongSecret(t *testing.T) {
	r := newACRouter(testSecret)
	for _, rt := range protectedRoutes {
		w := do(r, rt.method, rt.path, "wrong-secret", "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s wrong secret: code = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

// TestAC_CommandPassesAuthWithSecret 正确凭据通过认证：到达 handler 后因空 body
// 绑定失败返回 400（证明已越过 401 认证层）。
func TestAC_CommandPassesAuthWithSecret(t *testing.T) {
	r := newACRouter(testSecret)
	w := do(r, http.MethodPost, "/command", testSecret, `{}`)
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("valid secret should pass auth, got 401")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (bind fail after auth), got %d", w.Code)
	}
}

// TestAC_EmptySecretFailClosed 空 secret 配置下管理接口一律 401，绝不裸奔。
func TestAC_EmptySecretFailClosed(t *testing.T) {
	r := newACRouter("")
	w := do(r, http.MethodPost, "/command", "", `{}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty secret must fail-closed, got %d", w.Code)
	}
}

// TestAC_HealthAnonymousMinimal /health 匿名可达，仅暴露最小 liveness，
// 不泄漏在线 Agent 数/明细。
func TestAC_HealthAnonymousMinimal(t *testing.T) {
	r := newACRouter(testSecret)
	w := do(r, http.MethodGet, "/health", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("/health should be anonymous 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "online") {
		t.Errorf("/health must not leak online agent info: %s", w.Body.String())
	}
}
