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

const (
	testSecret      = "ac-mgmt-secret-abcdef123456"
	testAdminSecret = "ac-admin-secret-zyxwvu987654"
)

func newACRouter(secret string) *gin.Engine {
	return newACRouterWith(RouteAuth{InternalSecrets: []string{secret}, AdminSecret: testAdminSecret})
}

func newACRouterWith(auth RouteAuth) *gin.Engine {
	gin.SetMode(gin.TestMode)
	// transfer 传 nil：受保护路由的 401 在 handler 前中止；/health 不触碰 transfer。
	h := NewHandler(nil, zap.NewNop())
	r := gin.New()
	if err := h.RegisterRoutes(r.Group("/"), auth); err != nil {
		panic(err)
	}
	return r
}

// adminRoutes 只认 ac_admin_secret 的接口：能下发完整命令或断开全部连接。
var adminRoutes = []struct{ method, path string }{
	{http.MethodPost, "/command/raw"},
	{http.MethodGet, "/admin/drain"},
	{http.MethodPost, "/admin/drain"},
	{http.MethodPost, "/admin/undrain"},
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
	{http.MethodPost, "/command/raw"},
	{http.MethodPost, "/plugins/resend"},
	{http.MethodGet, "/admin/drain"},
	{http.MethodPost, "/admin/drain"},
	{http.MethodPost, "/admin/undrain"},
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

// TestAC_AdminRoutesRejectInternalSecret 持有 internal_secret 不等于能调管理动作。
//
// 这两把此前是同一把：internal_secret 又被写进监控组件的配置文件，读得到那个文件的人
// 就能经 /command/raw 给任意 Agent 下发升级命令。拆开后各管各的。
func TestAC_AdminRoutesRejectInternalSecret(t *testing.T) {
	r := newACRouter(testSecret)
	for _, rt := range adminRoutes {
		if w := do(r, rt.method, rt.path, testSecret, `{}`); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s 带 internal_secret 应 401，实际 %d", rt.method, rt.path, w.Code)
		}
	}
	// 反过来，admin 密钥也调不了 Manager 的接口
	if w := do(r, http.MethodPost, "/command", testAdminSecret, `{}`); w.Code != http.StatusUnauthorized {
		t.Errorf("/command 带 ac_admin_secret 应 401，实际 %d", w.Code)
	}
}

// TestAC_AdminRoutesFailClosedWithoutAdminSecret 没配 ac_admin_secret 时管理动作一律拒绝，
// 不退回接受 internal_secret。
func TestAC_AdminRoutesFailClosedWithoutAdminSecret(t *testing.T) {
	r := newACRouterWith(RouteAuth{InternalSecrets: []string{testSecret}})
	for _, rt := range adminRoutes {
		for _, sec := range []string{"", testSecret} {
			if w := do(r, rt.method, rt.path, sec, `{}`); w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s 未配 admin 密钥应 401，实际 %d", rt.method, rt.path, w.Code)
			}
		}
	}
}

// TestAC_PreviousInternalSecretAcceptedDuringRotation 轮换期新旧两把都认，旧的留空即失效。
func TestAC_PreviousInternalSecretAcceptedDuringRotation(t *testing.T) {
	const old = "ac-mgmt-secret-old-000000000000"
	r := newACRouterWith(RouteAuth{InternalSecrets: []string{testSecret, old}, AdminSecret: testAdminSecret})
	for _, sec := range []string{testSecret, old} {
		if w := do(r, http.MethodPost, "/command", sec, `{}`); w.Code != http.StatusBadRequest {
			t.Errorf("轮换期密钥应通过认证（400 绑定失败），实际 %d", w.Code)
		}
	}
	r = newACRouterWith(RouteAuth{InternalSecrets: []string{testSecret, ""}, AdminSecret: testAdminSecret})
	if w := do(r, http.MethodPost, "/command", "", `{}`); w.Code != http.StatusUnauthorized {
		t.Errorf("旧密钥留空不能让空凭据通过，实际 %d", w.Code)
	}
}

// TestAC_AllowCIDRsBlocksOtherSources 来源不在白名单内，密钥正确也进不来；探活接口不受限。
func TestAC_AllowCIDRsBlocksOtherSources(t *testing.T) {
	r := newACRouterWith(RouteAuth{InternalSecrets: []string{testSecret}, AdminSecret: testAdminSecret,
		AllowCIDRs: []string{"10.0.0.0/24", "127.0.0.1"}})
	send := func(remote, path, secret string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(internalauth.HeaderName, secret)
		// 伪造的转发头不该影响判断
		req.Header.Set("X-Forwarded-For", "10.0.0.5")
		req.RemoteAddr = remote
		r.ServeHTTP(w, req)
		return w.Code
	}
	if c := send("203.0.113.9:5555", "/command", testSecret); c != http.StatusForbidden {
		t.Errorf("白名单外来源应 403，实际 %d", c)
	}
	if c := send("203.0.113.9:5555", "/admin/drain", testAdminSecret); c != http.StatusForbidden {
		t.Errorf("白名单外来源调管理动作应 403，实际 %d", c)
	}
	if c := send("10.0.0.7:5555", "/command", testSecret); c != http.StatusBadRequest {
		t.Errorf("白名单内来源应通过（400 绑定失败），实际 %d", c)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	func() {
		defer func() { _ = recover() }() // transfer 为 nil，/ready 会解引用；能走到 handler 即说明没被白名单挡
		r.ServeHTTP(w, req)
	}()
	if w.Code == http.StatusForbidden {
		t.Error("/ready 不应受来源白名单限制")
	}
}
