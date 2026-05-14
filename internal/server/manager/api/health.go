// Package api 提供 HTTP API 处理器
package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// BuildVersion 构建版本，通过 -ldflags "-X ...api.BuildVersion=x.x.x" 注入
var BuildVersion = "dev"

// HealthHandler 是健康检查 API 处理器
type HealthHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewHealthHandler 创建健康检查处理器
func NewHealthHandler(db *gorm.DB, logger *zap.Logger) *HealthHandler {
	return &HealthHandler{
		db:     db,
		logger: logger,
	}
}

// HealthResponse 健康检查响应
type HealthResponse struct {
	Status    string            `json:"status"`            // 总体状态: "ok" 或 "degraded"
	Timestamp string            `json:"timestamp"`         // 检查时间戳
	Checks    map[string]string `json:"checks"`            // 各项检查结果
	Version   string            `json:"version,omitempty"` // 版本信息（可选）
}

// Health 健康检查端点
// GET /health
func (h *HealthHandler) Health(c *gin.Context) {
	response := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().Format(model.TimeFormat),
		Checks:    make(map[string]string),
		Version:   BuildVersion,
	}

	// 检查数据库连接
	dbStatus := h.checkDatabase()
	response.Checks["database"] = dbStatus

	// 如果数据库不可用，整体状态设为 degraded
	if dbStatus != "ok" {
		response.Status = "degraded"
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code":    503,
			"message": "服务不可用",
			"data":    response,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    response,
	})
}

// checkDatabase 检查数据库连接状态
func (h *HealthHandler) checkDatabase() string {
	if h.db == nil {
		return "unavailable"
	}

	// 尝试执行一个简单的查询
	sqlDB, err := h.db.DB()
	if err != nil {
		h.logger.Warn("获取数据库实例失败", zap.Error(err))
		return "error"
	}

	// 执行 ping 操作（带超时）
	done := make(chan error, 1)
	go func() {
		done <- sqlDB.Ping()
	}()

	select {
	case err := <-done:
		if err != nil {
			h.logger.Warn("数据库连接检查失败", zap.Error(err))
			return "error"
		}
		return "ok"
	case <-time.After(2 * time.Second):
		h.logger.Warn("数据库连接检查超时")
		return "timeout"
	}
}
