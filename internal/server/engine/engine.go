// Package engine 是 v2.0 六微服务架构中检测引擎的实现。
//
// 本包目前是 PR3 引入的空骨架,后续 PR 将逐步搬入:
//   - rule/      CEL + Sigma + Falco + Tetragon 转换规则
//   - sequence/  Markov 转移 / n-gram 序列异常 / 端口扫描滑动窗口
//   - ml/        ONNX Runtime CPU 推理 (IForest / LightGBM / MiniLM)
//   - storyline/ 攻击链关联 + ATT&CK 战术映射
//   - kube/      K8s Audit Event 检测 (从 manager.biz.kube_detector 搬入)
//   - response/  observe/protect 模式下的响应动作
//
// 设计文档: docs/engine-design.md / docs/engine-detection-design.md
package engine

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Version 是 Engine 服务的语义化版本。
const Version = "0.1.0-skeleton"

// NewHTTPHandler 构造空骨架 HTTP handler,仅暴露 /health 与 /metrics 占位。
//
// 后续 PR 将在此挂入: /rules CRUD / /alerts query / /feedback 等。
func NewHTTPHandler(logger *zap.Logger) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "engine",
			"version": Version,
		})
	})

	// 暴露默认 registry：engine pipeline 指标(metrics.go MustRegister)+ Go runtime
	// (process_cpu_seconds_total / process_resident_memory_bytes / go_goroutines)。
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	r.NoRoute(func(c *gin.Context) {
		payload, _ := json.Marshal(gin.H{
			"error":   "not implemented",
			"path":    c.Request.URL.Path,
			"hint":    "Engine 服务 PR3 仅空骨架,业务接口在后续 PR 引入",
			"version": Version,
		})
		c.Data(http.StatusNotFound, "application/json", payload)
	})

	return r
}
