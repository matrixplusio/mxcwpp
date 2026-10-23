package router

import (
	"encoding/json"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/matrixplusio/mxcwpp/internal/server/common/internalauth"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/api"
)

const gatingSecret = "gating-internal-secret-0123456789abcd"

func gatingReq(engine *gin.Engine, method, path, secret, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set(internalauth.HeaderName, secret)
	}
	engine.ServeHTTP(w, req)
	return w
}

func gatingBodyCode(w *httptest.ResponseRecorder) int {
	var resp struct {
		Code int `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Code
}

// materializePath 把 Gin 的 :param / *path 占位符物化为安全测试值，
// 使请求能命中真实路由；因中间件应在 handler 前拦截，不会触达依赖 DB 的 handler。
func materializePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		switch {
		case strings.HasPrefix(s, ":"):
			parts[i] = "1"
		case strings.HasPrefix(s, "*"):
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}

// TestGating_EveryProtectedRouteGated 遍历真实注册的每一条 internal / authenticated-perm /
// authenticated-basic / admin 路由，发无凭据请求，逐条断言在 handler 前被相应机制拦截：
//   - internal            → HTTP 401（internalauth 中间件）
//   - authenticated-perm  → body code = 40101（JWT AuthMiddleware）
//   - admin               → body code = 40101（JWT AuthMiddleware，先于 AdminMiddleware）
//   - authenticated-basic → body code ∈ {40100, 40101}（AuthMiddleware 或 /auth/me handler 自鉴权）
//
// 若某条路由意外注册在 Auth group 之外而匿名可达，其响应码不符会立即失败并打印 method/path/class。
func TestGating_EveryProtectedRouteGated(t *testing.T) {
	eng := buildTestEngineWithSecret(t, gatingSecret)

	checked := map[string]int{}
	for _, ri := range eng.Routes() {
		class := api.RouteCategory(ri.Method, ri.Path)
		path := materializePath(ri.Path)
		w := gatingReq(eng, ri.Method, path, "", "")
		code := gatingBodyCode(w)

		switch class {
		case api.RouteClassInternal:
			if w.Code != http.StatusUnauthorized {
				t.Errorf("[internal] %s %s 匿名可达: HTTP %d, 期望 401", ri.Method, ri.Path, w.Code)
			}
		case api.RouteClassPerm, api.RouteClassAdmin:
			if code != api.CodeTokenExpired {
				t.Errorf("[%s] %s %s 未被 JWT 拦截: body code %d (HTTP %d), 期望 %d",
					class, ri.Method, ri.Path, code, w.Code, api.CodeTokenExpired)
			}
		case api.RouteClassBasic:
			if code != api.CodeTokenExpired && code != api.CodeUnauthorized {
				t.Errorf("[basic] %s %s 未被鉴权拦截: body code %d (HTTP %d), 期望 40100/40101",
					ri.Method, ri.Path, code, w.Code)
			}
		default:
			continue // public 不在此全量执行（仅由 manifest 精确登记）
		}
		checked[class]++
	}

	// 确保确实覆盖到了各受保护类，避免“0 条也算通过”。
	for _, class := range []string{api.RouteClassInternal, api.RouteClassPerm, api.RouteClassBasic, api.RouteClassAdmin} {
		if checked[class] == 0 {
			t.Errorf("未覆盖任何 %s 路由（分类或引擎构建异常）", class)
		}
	}
	t.Logf("已逐条验证门禁: internal=%d perm=%d basic=%d admin=%d",
		checked[api.RouteClassInternal], checked[api.RouteClassPerm],
		checked[api.RouteClassBasic], checked[api.RouteClassAdmin])
}

// TestGating_PublicRepresentativeReachable 最小 public 代表：无凭据可达、不被认证层拦截。
func TestGating_PublicRepresentativeReachable(t *testing.T) {
	eng := buildTestEngineWithSecret(t, gatingSecret)
	w := gatingReq(eng, http.MethodGet, "/api/v1/health", "", "")
	if code := gatingBodyCode(w); code == api.CodeTokenExpired || code == api.CodeUnauthorized {
		t.Errorf("public /api/v1/health 被认证层拦截: body code = %d", code)
	}
}

// TestGating_InternalRoutesAlwaysProtected 内部路由始终强制内部认证：
// 空 secret fail-closed、缺/错凭据 401、正确凭据越过认证到达 handler（不依赖 DB）。
func TestGating_InternalRoutesAlwaysProtected(t *testing.T) {
	secretEng := buildTestEngineWithSecret(t, gatingSecret)
	emptyEng := buildTestEngineWithSecret(t, "")

	internalRoutes := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/internal/ac/register"},
		{http.MethodPost, "/api/v1/internal/alerts/prometheus"},
	}
	for _, rt := range internalRoutes {
		if w := gatingReq(emptyEng, rt.method, rt.path, "", "{}"); w.Code != http.StatusUnauthorized {
			t.Errorf("empty-secret %s %s: code = %d, want 401 (fail-closed)", rt.method, rt.path, w.Code)
		}
		if w := gatingReq(secretEng, rt.method, rt.path, "", "{}"); w.Code != http.StatusUnauthorized {
			t.Errorf("no-cred %s %s: code = %d, want 401", rt.method, rt.path, w.Code)
		}
		if w := gatingReq(secretEng, rt.method, rt.path, "wrong-secret", "{}"); w.Code != http.StatusUnauthorized {
			t.Errorf("wrong-cred %s %s: code = %d, want 401", rt.method, rt.path, w.Code)
		}
		if w := gatingReq(secretEng, rt.method, rt.path, gatingSecret, "{}"); w.Code == http.StatusUnauthorized {
			t.Errorf("valid-cred %s %s: got 401, expected to pass internal auth", rt.method, rt.path)
		}
	}
}

// TestGating_AlertIngestSecretIsScoped 告警接收接口用自己的密钥：配了之后 internal_secret 进不来，
// 这把密钥也调不了 AC 注册接口。它会被写进监控组件的配置文件，只该有推告警这一项权限。
func TestGating_AlertIngestSecretIsScoped(t *testing.T) {
	const alertSecret = "alert-only-secret-0123456789abcdef"
	const prevSecret = "previous-internal-secret-0123456789"
	eng := buildTestEngineWithConfig(t, gatingSecret, func(c *config.Config) {
		c.Server.AlertIngestSecret = alertSecret
		c.Server.InternalSecretExtra = prevSecret
	})
	const alerts, register = "/api/v1/internal/alerts/prometheus", "/api/v1/internal/ac/register"

	if w := gatingReq(eng, http.MethodPost, alerts, gatingSecret, "{}"); w.Code != http.StatusUnauthorized {
		t.Errorf("配了专用密钥后，告警接口不应再接受 internal_secret，实际 %d", w.Code)
	}
	if w := gatingReq(eng, http.MethodPost, alerts, alertSecret, "{}"); w.Code == http.StatusUnauthorized {
		t.Error("告警接口应接受 alert_ingest_secret")
	}
	if w := gatingReq(eng, http.MethodPost, register, alertSecret, "{}"); w.Code != http.StatusUnauthorized {
		t.Errorf("AC 注册接口不应接受 alert_ingest_secret，实际 %d", w.Code)
	}
	// 轮换期：上一把 internal_secret 仍能通过 AC 注册接口，但进不了告警接口
	if w := gatingReq(eng, http.MethodPost, register, prevSecret, "{}"); w.Code == http.StatusUnauthorized {
		t.Error("轮换期 AC 注册接口应接受上一把 internal_secret")
	}
	if w := gatingReq(eng, http.MethodPost, alerts, prevSecret, "{}"); w.Code != http.StatusUnauthorized {
		t.Errorf("告警接口不应接受上一把 internal_secret，实际 %d", w.Code)
	}
}
