// Package middleware 提供 HTTP 中间件
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
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

// AuditLog 审计日志中间件，记录 POST/PUT/DELETE 操作。
//
// 路径按 feature_flag.data_source.audit_log 决定 MySQL or CH。
// chConn 为 nil 时强制走 MySQL；flag 启动时读一次缓存。
func AuditLog(db *gorm.DB, logger *zap.Logger) gin.HandlerFunc {
	return AuditLogWithCH(db, nil, logger)
}

// AuditLogWithCH 同 AuditLog 但允许注入 ClickHouse 写入路径。
func AuditLogWithCH(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) gin.HandlerFunc {
	target := readAuditTarget(db, logger)
	logger.Info("审计日志通道", zap.String("target", target), zap.Bool("ch_available", chConn != nil))
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

		if target == "ch" && chConn != nil {
			if err := writeAuditCH(chConn, log); err != nil {
				logger.Warn("审计日志 CH 写入失败，回落 MySQL", zap.Error(err))
				if err := db.Create(log).Error; err != nil {
					logger.Warn("审计日志 MySQL 写入失败", zap.Error(err))
				}
			}
			return
		}
		if err := db.Create(log).Error; err != nil {
			logger.Warn("记录审计日志失败", zap.Error(err))
		}
	}
}

// readAuditTarget 启动时读 feature_flag.data_source.audit_log。
// 不缓存运行时变化，需重启 manager 生效。
func readAuditTarget(db *gorm.DB, logger *zap.Logger) string {
	var f model.FeatureFlag
	if err := db.Where("flag_key = ?", model.FlagDataSourceAuditLog).First(&f).Error; err != nil {
		logger.Warn("audit_log feature flag 读取失败，使用 mysql 默认", zap.Error(err))
		return "mysql"
	}
	if f.Value != "ch" {
		return "mysql"
	}
	return "ch"
}

// writeAuditCH 把单条审计日志写到 CH mxsec.audit_log。
// CH 端 schema: timestamp / user_id / action / resource / detail / ip
// MySQL 模型字段更丰富，部分序列化压缩到 resource+detail 字段。
func writeAuditCH(conn chdriver.Conn, log *model.AuditLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	batch, err := conn.PrepareBatch(ctx,
		"INSERT INTO audit_log (timestamp, user_id, action, resource, detail, ip)")
	if err != nil {
		return err
	}
	// resource 字段拼 resource_type/resource_id + status_code 信息
	resource := log.ResourceType
	if log.ResourceID != "" {
		resource = resource + "/" + log.ResourceID
	}
	if log.Path != "" {
		resource = resource + " " + log.Path
	}
	// detail 拼 status_code 让 CH 端易查
	detail := log.Detail
	if log.StatusCode != 0 {
		if detail != "" {
			detail = detail + " | "
		}
		detail = detail + "status=" + intToStr(log.StatusCode)
	}
	ts := time.Time(log.CreatedAt)
	if ts.IsZero() {
		ts = time.Now()
	}
	if err := batch.Append(ts, log.Username, log.Action, resource, detail, log.IP); err != nil {
		return err
	}
	return batch.Send()
}

// intToStr 把 int 转字符串，避免引入 strconv 全文件 import。
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
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
