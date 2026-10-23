// Package middleware — 安全响应头 (批4).
//
// 给所有 Manager HTTP 响应附加常见安全头, 缓解点击劫持 / MIME 嗅探 / 信息泄露.
// 默认关闭, 由 server.security.headers.enabled 灰度开启 (见 config.SecurityHeadersConfig).
package middleware

import "github.com/gin-gonic/gin"

// defaultCSP 默认内容安全策略: 仅同源, 禁止被嵌入 iframe.
// 前端 SPA 由独立 nginx 容器托管, Manager 主要出 API + /uploads 静态图, 同源策略足够.
const defaultCSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"

// hstsValue 一年 + 子域; 仅在 enableHSTS=true (全站 HTTPS) 时下发, 否则会锁死 http 访问.
const hstsValue = "max-age=31536000; includeSubDomains"

// SecurityHeaders 返回设置安全响应头的中间件.
//
//	enableHSTS — 是否下发 Strict-Transport-Security (仅全站 HTTPS 时开)
//	csp        — 自定义 CSP, 留空用 defaultCSP
func SecurityHeaders(enableHSTS bool, csp string) gin.HandlerFunc {
	if csp == "" {
		csp = defaultCSP
	}
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", csp)
		if enableHSTS {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		c.Next()
	}
}
