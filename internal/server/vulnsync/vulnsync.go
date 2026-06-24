// Package vulnsync 是 v2.0 漏洞情报融合服务的实现。
//
// 本包目前是 PR3 引入的空骨架,后续 PR 将逐步加入:
//   - sources/    NVD / OSV / RHSA / USN / Debian / Alpine / SUSE / CISA KEV / ExploitDB / CNNVD / EPSS + 信创 4 源
//   - merger/     PURL+NEVRA 双索引 + 3 级 confidence 仲裁
//   - publisher/  Kafka mxcwpp.vuln.advisory 生产者
//   - leader/     redsync Leader Election (避免重复抓取)
//
// 设计文档: docs/vulnsync-design.md
package vulnsync

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Version 是 VulnSync 服务的语义化版本。
const Version = "0.1.0-skeleton"

// NewHTTPHandler 构造 HTTP handler。
//
// trigger 为手动同步回调（一般绑定 Scheduler.TriggerNow），返回实际触发的 source 数；
// 为 nil 时 /sync 返回 503。Manager 的 advisory-sync API 经此端点触发 VulnSync 拉取。
func NewHTTPHandler(logger *zap.Logger, trigger func() int) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "vulnsync",
			"version": Version,
		})
	})

	// POST /sync 立即触发一轮全源 advisory 拉取（手动同步入口）。
	r.POST("/sync", func(c *gin.Context) {
		if trigger == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scheduler 未就绪"})
			return
		}
		n := trigger()
		c.JSON(http.StatusOK, gin.H{"status": "triggered", "sources": n})
	})

	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "# vulnsync metrics placeholder\n")
	})

	r.NoRoute(func(c *gin.Context) {
		payload, _ := json.Marshal(gin.H{
			"error":   "not implemented",
			"path":    c.Request.URL.Path,
			"hint":    "VulnSync 服务 PR3 仅空骨架,业务接口在后续 PR 引入",
			"version": Version,
		})
		c.Data(http.StatusNotFound, "application/json", payload)
	})

	return r
}
