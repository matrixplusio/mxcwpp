package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestExtractResource(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantType string
		wantID   string
	}{
		{"标准资源路径", "/api/v1/hosts/abc123", "hosts", "abc123"},
		{"带 batch 操作", "/api/v1/alerts/batch/resolve", "alerts", ""},
		{"带 statistics 路径", "/api/v1/hosts/statistics", "hosts", ""},
		{"带 whitelist 路径", "/api/v1/alerts/whitelist", "alerts", ""},
		{"带 resolve 路径", "/api/v1/alerts/resolve", "alerts", ""},
		{"带 ignore 路径", "/api/v1/alerts/ignore", "alerts", ""},
		{"仅资源类型无 ID", "/api/v1/policies", "policies", ""},
		{"数字 ID", "/api/v1/tasks/42", "tasks", "42"},
		{"空路径", "", "", ""},
		{"无 api 前缀", "/health", "", "health"},
		// 新增：修复 extractResource 误提取的场景
		{"status-distribution", "/api/v1/hosts/status-distribution", "hosts", ""},
		{"export 路径", "/api/v1/policies/export", "policies", ""},
		{"import 路径", "/api/v1/policies/import", "policies", ""},
		{"run 操作", "/api/v1/tasks/run", "tasks", ""},
		{"cancel 操作", "/api/v1/tasks/cancel", "tasks", ""},
		{"approve 操作", "/api/v1/fim/approve", "fim", ""},
		{"batch-approve", "/api/v1/fim/batch-approve", "fim", ""},
		{"batch-confirm", "/api/v1/fim/batch-confirm", "fim", ""},
		{"host-monitor", "/api/v1/system/host-monitor", "system", ""},
		{"service-monitor", "/api/v1/system/service-monitor", "system", ""},
		{"task-report", "/api/v1/system/task-report", "system", ""},
		{"真正的资源 ID", "/api/v1/hosts/host-abc-123", "hosts", "host-abc-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotID := extractResource(tt.path)
			assert.Equal(t, tt.wantType, gotType)
			assert.Equal(t, tt.wantID, gotID)
		})
	}
}

func TestRedactSensitiveFields(t *testing.T) {
	data := map[string]any{
		"username": "admin",
		"password": "secret123",
		"nested": map[string]any{
			"token":  "abc",
			"value":  "keep",
			"Secret": "def",
		},
	}

	redactSensitiveFields(data)

	assert.Equal(t, "admin", data["username"])
	assert.Equal(t, "***", data["password"])

	nested := data["nested"].(map[string]any)
	assert.Equal(t, "***", nested["token"])
	assert.Equal(t, "keep", nested["value"])
	assert.Equal(t, "***", nested["Secret"])
}

func TestRedactSensitiveFieldsKubeconfig(t *testing.T) {
	data := map[string]any{
		"name":        "my-cluster",
		"kubeconfig":  "apiVersion: v1\nclusters:\n- cluster:\n    server: ...",
		"credentials": `{"type":"service_account"}`,
	}

	redactSensitiveFields(data)

	assert.Equal(t, "my-cluster", data["name"])
	assert.Equal(t, "***", data["kubeconfig"])
	assert.Equal(t, "***", data["credentials"])
}

// ===== captureRequestBody 功能测试 =====

func newGinContext(method, path, body string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c, w
}

func TestCaptureRequestBody_NormalJSON(t *testing.T) {
	body := `{"name":"test-policy","enabled":true}`
	c, _ := newGinContext("POST", "/api/v1/policies", body)

	result := captureRequestBody(c)

	// 应返回脱敏后的 JSON
	var parsed map[string]any
	err := json.Unmarshal([]byte(result), &parsed)
	assert.NoError(t, err)
	assert.Equal(t, "test-policy", parsed["name"])
	assert.Equal(t, true, parsed["enabled"])
}

func TestCaptureRequestBody_SensitiveFieldsRedacted(t *testing.T) {
	body := `{"username":"admin","password":"secret123","token":"jwt-abc"}`
	c, _ := newGinContext("POST", "/api/v1/auth/login", body)

	result := captureRequestBody(c)

	var parsed map[string]any
	err := json.Unmarshal([]byte(result), &parsed)
	assert.NoError(t, err)
	assert.Equal(t, "admin", parsed["username"])
	assert.Equal(t, "***", parsed["password"])
	assert.Equal(t, "***", parsed["token"])
}

func TestCaptureRequestBody_EmptyBody(t *testing.T) {
	c, _ := newGinContext("POST", "/api/v1/tasks/run", "")

	result := captureRequestBody(c)
	assert.Equal(t, "", result)
}

func TestCaptureRequestBody_NilBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/tasks/run", nil)
	req.Body = nil
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	result := captureRequestBody(c)
	assert.Equal(t, "", result)
}

func TestCaptureRequestBody_OversizedBodyTruncated(t *testing.T) {
	// 创建超过 4KB 的 JSON 请求体
	bigValue := strings.Repeat("x", maxAuditBodySize+100)
	body := `{"data":"` + bigValue + `"}`
	c, _ := newGinContext("POST", "/api/v1/policies", body)

	result := captureRequestBody(c)

	// 超大 body 截断后 JSON 解析会失败，应返回截断的原文
	assert.True(t, strings.HasSuffix(result, "...(truncated)"))
	// 截断后长度 = maxAuditBodySize + len("...(truncated)")
	assert.True(t, len(result) <= maxAuditBodySize+len("...(truncated)"))
}

func TestCaptureRequestBody_BodyRestoredForHandler(t *testing.T) {
	body := `{"name":"restored-test"}`
	c, _ := newGinContext("POST", "/api/v1/policies", body)

	// 调用 captureRequestBody 后 Body 应可再次读取
	captureRequestBody(c)

	// 模拟后续 handler 读取 body
	restoredBody, err := io.ReadAll(c.Request.Body)
	assert.NoError(t, err)
	assert.Equal(t, body, string(restoredBody))
}

func TestCaptureRequestBody_BatchIDsExtraction(t *testing.T) {
	body := `{"ids":["id-001","id-002","id-003"],"action":"delete"}`
	c, _ := newGinContext("POST", "/api/v1/policies/batch-delete", body)

	result := captureRequestBody(c)

	// 批量操作应只返回 ids 摘要
	var parsed map[string]any
	err := json.Unmarshal([]byte(result), &parsed)
	assert.NoError(t, err)
	ids, ok := parsed["ids"]
	assert.True(t, ok, "should contain ids field")
	idArr, ok := ids.([]any)
	assert.True(t, ok)
	assert.Equal(t, 3, len(idArr))
	// action 字段不应出现在摘要中
	_, hasAction := parsed["action"]
	assert.False(t, hasAction, "batch IDs extraction should only return ids")
}

func TestCaptureRequestBody_EmptyIDsArrayNotExtracted(t *testing.T) {
	body := `{"ids":[],"name":"test"}`
	c, _ := newGinContext("POST", "/api/v1/policies", body)

	result := captureRequestBody(c)

	// 空 ids 数组不应触发摘要提取，应返回完整 JSON
	var parsed map[string]any
	err := json.Unmarshal([]byte(result), &parsed)
	assert.NoError(t, err)
	assert.Equal(t, "test", parsed["name"])
}

func TestCaptureRequestBody_NonJSON(t *testing.T) {
	body := "plain text content"
	c, _ := newGinContext("POST", "/api/v1/upload", body)

	result := captureRequestBody(c)
	assert.Equal(t, "plain text content", result)
}

// ===== AuditLog 中间件集成测试 =====

func setupAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	err = db.Exec(`CREATE TABLE audit_logs (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		username      TEXT NOT NULL DEFAULT 'unknown',
		action        TEXT NOT NULL,
		resource_type TEXT NOT NULL DEFAULT 'unknown',
		resource_id   TEXT DEFAULT '',
		path          TEXT NOT NULL,
		ip            TEXT DEFAULT '',
		detail        TEXT DEFAULT '',
		status_code   INTEGER DEFAULT 200,
		created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
	)`).Error
	if err != nil {
		t.Fatalf("failed to create audit_logs table: %v", err)
	}
	return db
}

func TestAuditLog_PostRequestRecorded(t *testing.T) {
	db := setupAuditDB(t)
	nopLogger := zap.NewNop()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditLog(db, nopLogger))
	r.POST("/api/v1/policies", func(c *gin.Context) {
		c.Set("username", "admin")
		c.JSON(200, gin.H{"ok": true})
	})

	body := `{"name":"new-policy","enabled":true}`
	req := httptest.NewRequest("POST", "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var logs []model.AuditLog
	db.Find(&logs)
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "POST", logs[0].Action)
	assert.Equal(t, "/api/v1/policies", logs[0].Path)
	assert.Equal(t, "policies", logs[0].ResourceType)
	assert.Equal(t, 200, logs[0].StatusCode)
	assert.Contains(t, logs[0].Detail, "new-policy")
}

func TestAuditLog_GetRequestNotRecorded(t *testing.T) {
	db := setupAuditDB(t)
	nopLogger := zap.NewNop()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditLog(db, nopLogger))
	r.GET("/api/v1/hosts", func(c *gin.Context) {
		c.JSON(200, gin.H{"hosts": []string{}})
	})

	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var count int64
	db.Model(&model.AuditLog{}).Count(&count)
	assert.Equal(t, int64(0), count, "GET requests should not be audited")
}

func TestAuditLog_DeleteRequestRecorded(t *testing.T) {
	db := setupAuditDB(t)
	nopLogger := zap.NewNop()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditLog(db, nopLogger))
	r.DELETE("/api/v1/policies/:policy_id", func(c *gin.Context) {
		c.Set("username", "admin")
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("DELETE", "/api/v1/policies/pol-123", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var logs []model.AuditLog
	db.Find(&logs)
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "DELETE", logs[0].Action)
	assert.Equal(t, "policies", logs[0].ResourceType)
	assert.Equal(t, "pol-123", logs[0].ResourceID)
	// DELETE 不捕获 body
	assert.Equal(t, "", logs[0].Detail)
}

func TestAuditLog_SensitiveFieldsRedactedInDetail(t *testing.T) {
	db := setupAuditDB(t)
	nopLogger := zap.NewNop()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditLog(db, nopLogger))
	r.POST("/api/v1/auth/login", func(c *gin.Context) {
		c.JSON(200, gin.H{"token": "xxx"})
	})

	body := `{"username":"admin","password":"my-secret-pass"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var logs []model.AuditLog
	db.Find(&logs)
	assert.Equal(t, 1, len(logs))
	assert.Contains(t, logs[0].Detail, "admin")
	assert.NotContains(t, logs[0].Detail, "my-secret-pass")
	assert.Contains(t, logs[0].Detail, "***")
}

func TestAuditLog_UnknownUserFallback(t *testing.T) {
	db := setupAuditDB(t)
	nopLogger := zap.NewNop()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditLog(db, nopLogger))
	r.POST("/api/v1/policies", func(c *gin.Context) {
		// 不设置 username
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("POST", "/api/v1/policies", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var logs []model.AuditLog
	db.Find(&logs)
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "unknown", logs[0].Username)
}

func TestAuditLog_PutRequestWithBody(t *testing.T) {
	db := setupAuditDB(t)
	nopLogger := zap.NewNop()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuditLog(db, nopLogger))
	r.PUT("/api/v1/policies/:policy_id", func(c *gin.Context) {
		c.Set("username", "admin")
		// 验证 body 被恢复：后续 handler 可以读取
		bodyBytes, err := io.ReadAll(c.Request.Body)
		assert.NoError(t, err)
		assert.True(t, len(bodyBytes) > 0, "body should be available to handler")
		c.JSON(200, gin.H{"ok": true})
	})

	body := `{"name":"updated-policy","enabled":false}`
	req := httptest.NewRequest("PUT", "/api/v1/policies/pol-456", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var logs []model.AuditLog
	db.Find(&logs)
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "PUT", logs[0].Action)
	assert.Contains(t, logs[0].Detail, "updated-policy")
}
