// Package middleware 提供 HTTP 中间件
package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// 审计请求体最大捕获大小（4KB，超出截断）
const maxAuditBodySize = 4096

// 请求体最大读取大小（1MB），超出部分不读取也不恢复
const maxBodyReadSize = 1 << 20

// 不应作为 resourceID 的路径段（非资源操作的固定路由段）
var nonResourceSegments = map[string]bool{
	"batch":               true,
	"statistics":          true,
	"whitelist":           true,
	"resolve":             true,
	"ignore":              true,
	"status-distribution": true,
	"export":              true,
	"import":              true,
	"run":                 true,
	"cancel":              true,
	"confirm":             true,
	"approve":             true,
	"reject":              true,
	"download":            true,
	"upload":              true,
	"host-status":         true,
	"host-monitor":        true,
	"service-monitor":     true,
	"service-alert":       true,
	"task-report":         true,
	"batch-approve":       true,
	"batch-confirm":       true,
	"batch-delete":        true,
}

// 需要从请求体中脱敏的字段名
var sensitiveFields = map[string]bool{
	"password":     true,
	"new_password": true,
	"old_password": true,
	"secret":       true,
	"token":        true,
	"kubeconfig":   true,
	"credentials":  true,
}

// AuditLog 审计日志中间件，记录 POST/PUT/DELETE 操作
func AuditLog(db *gorm.DB, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		// 只记录写操作
		if method != "POST" && method != "PUT" && method != "DELETE" {
			c.Next()
			return
		}

		// 捕获请求体（POST/PUT 才读取）
		var detail string
		if method == "POST" || method == "PUT" {
			detail = captureRequestBody(c)
		}

		c.Next()

		// 从 context 获取当前用户（由 AuthMiddleware 注入）
		username, _ := c.Get("username")
		usernameStr, _ := username.(string)
		if usernameStr == "" {
			usernameStr = "unknown"
		}

		path := c.Request.URL.Path
		resourceType, resourceID := extractResource(path)

		log := &model.AuditLog{
			Username:     usernameStr,
			Action:       method,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Path:         path,
			IP:           c.ClientIP(),
			StatusCode:   c.Writer.Status(),
			Detail:       detail,
		}

		if err := db.Create(log).Error; err != nil {
			logger.Warn("记录审计日志失败", zap.Error(err))
		}
	}
}

// captureRequestBody 读取并返回脱敏后的请求体摘要
func captureRequestBody(c *gin.Context) string {
	if c.Request.Body == nil {
		return ""
	}

	// 跳过 multipart/form-data（文件上传）：
	// audit 用 LimitReader(1MB) 截断 body 后 restore，对大 multipart 会破坏 body 结构
	// → handler ParseMultipartForm 失败 → form 字段空。
	// audit 不记录 binary 上传内容（detail 列也存不下 binary），直接放行。
	if ct := c.Request.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/") {
		return "[multipart upload skipped]"
	}

	// 读取完整请求体并恢复，审计日志仅截断记录内容
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyReadSize))
	if err != nil {
		return ""
	}
	// 恢复完整 Body 以供后续 handler 使用
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 {
		return ""
	}

	// 截断标记
	truncated := len(body) > maxAuditBodySize
	if truncated {
		body = body[:maxAuditBodySize]
	}

	// 尝试 JSON 解析并脱敏
	var data map[string]any
	if json.Unmarshal(body, &data) == nil {
		redactSensitiveFields(data)
		// 对批量操作提取 IDs 摘要
		if ids, ok := data["ids"]; ok {
			if idArr, ok := ids.([]any); ok && len(idArr) > 0 {
				sanitized, _ := json.Marshal(map[string]any{"ids": idArr})
				return string(sanitized)
			}
		}
		sanitized, err := json.Marshal(data)
		if err == nil {
			result := string(sanitized)
			if truncated {
				result += "...(truncated)"
			}
			return result
		}
	}

	// 非 JSON 内容，返回截断的原文
	result := string(body)
	if truncated {
		result += "...(truncated)"
	}
	return result
}

// redactSensitiveFields 递归脱敏 JSON 中的敏感字段
func redactSensitiveFields(data map[string]any) {
	for key, val := range data {
		if sensitiveFields[strings.ToLower(key)] {
			data[key] = "***"
			continue
		}
		if nested, ok := val.(map[string]any); ok {
			redactSensitiveFields(nested)
		}
	}
}

// extractResource 从路径提取资源类型和资源 ID
// 例如 /api/v1/hosts/abc123 -> ("hosts", "abc123")
//
//	/api/v1/alerts/batch/resolve -> ("alerts", "")
//	/api/v1/hosts/status-distribution -> ("hosts", "")
func extractResource(path string) (resourceType, resourceID string) {
	// 去掉 /api/v1/ 前缀
	path = strings.TrimPrefix(path, "/api/v1/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) == 0 {
		return "unknown", ""
	}
	resourceType = parts[0]
	if len(parts) >= 2 {
		second := parts[1]
		if second != "" && !nonResourceSegments[second] {
			resourceID = second
		}
	}
	return resourceType, resourceID
}
