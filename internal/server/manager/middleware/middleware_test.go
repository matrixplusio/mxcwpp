package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestLogger_SkipsHealthCheck(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	handler := Logger(logger)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	c.Request = httptest.NewRequest("GET", "/health", nil)
	r.ServeHTTP(w, c.Request)
	assert.Equal(t, 200, w.Code)
}

func TestLogger_LogsNormalRequest(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	handler := Logger(logger)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/api/v1/hosts", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": "ok"})
	})

	req := httptest.NewRequest("GET", "/api/v1/hosts?page=1", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
}

func TestCORS_AllowedOrigin(t *testing.T) {
	handler := CORS([]string{"https://example.com"})

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)

	assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Origin", w.Header().Get("Vary"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	handler := CORS([]string{"https://example.com"})

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	r.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_EmptyOrigins(t *testing.T) {
	handler := CORS(nil)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://any.com")
	r.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_OptionsPreflightReturns204(t *testing.T) {
	handler := CORS([]string{"https://example.com"})

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.OPTIONS("/test", func(c *gin.Context) {
		// 不应该到达这里
		t.Fatal("handler should not be called for OPTIONS")
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestInternalAuth_ValidSecret(t *testing.T) {
	handler := InternalAuth("my-secret-key")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/internal/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/internal/test", nil)
	req.Header.Set("X-Internal-Secret", "my-secret-key")
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestInternalAuth_InvalidSecret(t *testing.T) {
	handler := InternalAuth("my-secret-key")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/internal/test", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/internal/test", nil)
	req.Header.Set("X-Internal-Secret", "wrong-key")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInternalAuth_MissingSecret(t *testing.T) {
	handler := InternalAuth("my-secret-key")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(handler)
	r.GET("/internal/test", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/internal/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
