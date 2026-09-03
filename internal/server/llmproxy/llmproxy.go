// Package llmproxy 是 v2.0 多 LLM 厂商适配网关的实现。
//
// 本包目前是 PR3 引入的空骨架,后续 PR 将逐步加入:
//   - provider/  Provider interface + OpenAI / Anthropic / Gemini / DashScope / Ollama 实现
//   - router/    场景路由 (alert_explain / storyline_summary / nl2query / rule_draft)
//   - cache/     Redis 24h 缓存 (SHA256 入参)
//   - fallback/  主厂商失败黑名单 + 备用切换
//   - quota/     租户级月度 USD 上限 + token cap
//   - audit/     Kafka mxcwpp.llm.audit 审计
//
// 设计文档: docs/llmproxy-design.md
package llmproxy

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Version 是 LLMProxy 服务的语义化版本。
const Version = "0.1.0-skeleton"

// NewHTTPHandler 构造空骨架 HTTP handler。
//
// 后续 PR 将挂入: /complete (POST) / /stream (SSE) / /embed / /providers / /usage。
func NewHTTPHandler(logger *zap.Logger) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "llmproxy",
			"version": Version,
		})
	})

	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "# llmproxy metrics placeholder\n")
	})

	r.NoRoute(func(c *gin.Context) {
		payload, _ := json.Marshal(gin.H{
			"error":   "not implemented",
			"path":    c.Request.URL.Path,
			"hint":    "LLMProxy 服务 PR3 仅空骨架,业务接口在后续 PR 引入",
			"version": Version,
		})
		c.Data(http.StatusNotFound, "application/json", payload)
	})

	return r
}
