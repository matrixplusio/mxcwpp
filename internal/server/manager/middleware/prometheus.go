// Package middleware 提供 HTTP 中间件
package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxsec-platform/internal/server/metrics"
)

// Prometheus 返回一个 gin middleware，记录每次 HTTP 请求的：
//   - mxsec_http_requests_total{method, endpoint, status_code} 计数
//   - mxsec_http_request_duration_seconds{method, endpoint} 直方图（用于 p50/p95/p99）
//
// endpoint 用 c.FullPath()（路由模板，如 /api/v1/hosts/:host_id），避免高基数爆炸。
// 静态路径（/metrics、/health）跳过以减少噪声。
func Prometheus() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		// 跳过监控自身的路径
		path := c.FullPath()
		if path == "" || path == "/metrics" || path == "/health" {
			return
		}

		method := c.Request.Method
		status := strconv.Itoa(c.Writer.Status())
		duration := time.Since(start).Seconds()

		metrics.RecordHTTPRequest(method, path, status)
		metrics.RecordHTTPRequestDuration(method, path, duration)
	}
}
