package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

var testSecret = []byte("test-jwt-secret-key-for-unit-tests")

func newTestAuthHandler() *AuthHandler {
	logger, _ := zap.NewDevelopment()
	return &AuthHandler{
		logger: logger,
		secret: testSecret,
	}
}

// generateValidToken 为测试生成一个有效的 JWT token
func generateValidToken(username, role string) string {
	now := time.Now()
	claims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testSecret)
	return tokenString
}

// generateExpiredToken 生成一个过期的 JWT token
func generateExpiredToken(username, role string) string {
	past := time.Now().Add(-48 * time.Hour)
	claims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(past.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(past),
			NotBefore: jwt.NewNumericDate(past),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testSecret)
	return tokenString
}

// --- extractBearerToken 测试 ---

func TestExtractBearerToken_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer my-token-123")

	token, err := extractBearerToken(c)
	require.NoError(t, err)
	assert.Equal(t, "my-token-123", token)
}

func TestExtractBearerToken_MissingHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	_, err := extractBearerToken(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing Authorization header")
}

func TestExtractBearerToken_WrongPrefix(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	_, err := extractBearerToken(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Authorization header format")
}

func TestExtractBearerToken_EmptyToken(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer ")

	_, err := extractBearerToken(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty token")
}

// --- parseToken 测试 ---

func TestParseToken_Valid(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateValidToken("admin", "admin")

	claims, err := h.parseToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Username)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, jwtIssuer, claims.Issuer)
}

func TestParseToken_Expired(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateExpiredToken("admin", "admin")

	_, err := h.parseToken(tokenString)
	assert.Error(t, err)
}

func TestParseToken_WrongSecret(t *testing.T) {
	// 用另一个密钥签名的 token
	now := time.Now()
	claims := Claims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("wrong-secret"))

	h := newTestAuthHandler()
	_, err := h.parseToken(tokenString)
	assert.Error(t, err)
}

func TestParseToken_WrongIssuer(t *testing.T) {
	now := time.Now()
	claims := Claims{
		Username: "admin",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testSecret)

	h := newTestAuthHandler()
	_, err := h.parseToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestParseToken_AlgorithmConfusion(t *testing.T) {
	// 尝试使用 none 算法（Algorithm Confusion Attack）
	h := newTestAuthHandler()
	_, err := h.parseToken("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0.")
	assert.Error(t, err)
}

// --- AuthMiddleware 测试 ---

func TestAuthMiddleware_ValidToken(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateValidToken("testuser", "user")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.GET("/protected", func(c *gin.Context) {
		username, _ := c.Get("username")
		role, _ := c.Get("role")
		c.JSON(200, gin.H{"username": username, "role": role})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "testuser", resp["username"])
	assert.Equal(t, "user", resp["role"])
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.GET("/protected", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.GET("/protected", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateExpiredToken("admin", "admin")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.GET("/protected", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- RoleMiddleware 测试 ---

func TestRoleMiddleware_AllowedRole(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateValidToken("admin", "admin")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.Use(RoleMiddleware("admin"))
	r.GET("/admin-only", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestRoleMiddleware_ForbiddenRole(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateValidToken("normaluser", "user")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.Use(RoleMiddleware("admin"))
	r.GET("/admin-only", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRoleMiddleware_MultipleAllowedRoles(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateValidToken("normaluser", "user")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(h.AuthMiddleware())
	r.Use(RoleMiddleware("admin", "user"))
	r.GET("/multi", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/multi", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestRoleMiddleware_NoRoleInContext(t *testing.T) {
	// RoleMiddleware 在没有 AuthMiddleware 的情况下使用
	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(RoleMiddleware("admin"))
	r.GET("/admin-only", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/admin-only", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- GetCurrentUser 测试 ---

func TestGetCurrentUser_Valid(t *testing.T) {
	h := newTestAuthHandler()
	tokenString := generateValidToken("testuser", "admin")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.GET("/auth/me", h.GetCurrentUser)

	req := httptest.NewRequest("GET", "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "testuser", data["username"])
	assert.Equal(t, "admin", data["role"])
}

func TestGetCurrentUser_NoAuth(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.GET("/auth/me", h.GetCurrentUser)

	req := httptest.NewRequest("GET", "/auth/me", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetCurrentUser_InvalidToken(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.GET("/auth/me", h.GetCurrentUser)

	req := httptest.NewRequest("GET", "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Logout 测试 ---

func TestLogout(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.POST("/auth/logout", h.Logout)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "登出成功", resp["message"])
}

// --- GetCaptcha 测试 ---

func TestGetCaptcha_Success(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.GET("/auth/captcha", h.GetCaptcha)

	req := httptest.NewRequest("GET", "/auth/captcha", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, data["captcha_id"])
	assert.NotEmpty(t, data["captcha_image"])
	// base64 图片应以 data:image 开头
	assert.Contains(t, data["captcha_image"].(string), "data:image")
}

// --- Login 验证码校验测试 ---

func TestLogin_WrongCaptcha(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.POST("/auth/login", h.Login)

	body, _ := json.Marshal(map[string]string{
		"username":     "admin",
		"password":     "password123",
		"captcha_id":   "non-existent-id",
		"captcha_code": "00000",
	})
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "验证码")
}

// --- Login 请求绑定测试（不需要数据库） ---

func TestLogin_MissingFields(t *testing.T) {
	h := newTestAuthHandler()

	tests := []struct {
		name string
		body interface{}
	}{
		{"缺少 username", map[string]string{"password": "123456", "captcha_id": "x", "captcha_code": "1"}},
		{"缺少 password", map[string]string{"username": "admin", "captcha_id": "x", "captcha_code": "1"}},
		{"缺少 captcha_id", map[string]string{"username": "admin", "password": "123456", "captcha_code": "1"}},
		{"缺少 captcha_code", map[string]string{"username": "admin", "password": "123456", "captcha_id": "x"}},
		{"空 body", map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)
			r.POST("/auth/login", h.Login)

			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	h := newTestAuthHandler()

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.POST("/auth/login", h.Login)

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
