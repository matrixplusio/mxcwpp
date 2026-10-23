// Package api 提供 HTTP API 处理器
package api

import (
	"context"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// BuildVersion 构建版本，通过 -ldflags "-X ...api.BuildVersion=x.x.x" 注入
var BuildVersion = "dev"

// HealthHandler 是健康检查 API 处理器
type HealthHandler struct {
	db          *gorm.DB
	chConn      chdriver.Conn // 可选，ClickHouse 连接（readiness 探测用）
	redisClient *redis.Client // 可选，Redis 客户端（readiness 探测用）
	logger      *zap.Logger
}

// NewHealthHandler 创建健康检查处理器。
// chConn / redisClient 为可选依赖，nil 时 readiness 探测跳过该项（不硬加拿不到的依赖）。
func NewHealthHandler(db *gorm.DB, chConn chdriver.Conn, redisClient *redis.Client, logger *zap.Logger) *HealthHandler {
	return &HealthHandler{
		db:          db,
		chConn:      chConn,
		redisClient: redisClient,
		logger:      logger,
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
		ServiceUnavailable(c, "服务不可用", response)
		return
	}

	SuccessWithMessage(c, "success", response)
}

// Readiness 就绪检查端点
// GET /health/ready
//
// 与 liveness(/health)区分：liveness 仅探硬依赖(DB)判定进程是否需重启；readiness 额外探可选
// 依赖(ClickHouse/Redis，仅在已配置时探)判定是否可承接流量。硬依赖(DB)不可用返回 503；可选依赖
// 不可用仅标记 degraded 仍返回 200(HTTP 层面可服务，降级运行)，避免健康检查因边缘依赖抖动而变脆。
func (h *HealthHandler) Readiness(c *gin.Context) {
	response := HealthResponse{
		Timestamp: time.Now().Format(model.TimeFormat),
		Checks:    make(map[string]string),
		Version:   BuildVersion,
	}

	response.Checks["database"] = h.checkDatabase()
	if h.chConn != nil {
		response.Checks["clickhouse"] = h.checkClickHouse()
	}
	if h.redisClient != nil {
		response.Checks["redis"] = h.checkRedis()
	}

	status, unavailable := evaluateReadiness(response.Checks)
	response.Status = status
	if unavailable {
		ServiceUnavailable(c, "服务不可用", response)
		return
	}
	SuccessWithMessage(c, "success", response)
}

// evaluateReadiness 依据各依赖检查结果聚合总体状态与是否应返回 503。
// 硬依赖(database)不可用 → (degraded, true=应 503)；可选依赖(clickhouse/redis)不可用 →
// (degraded, false=仍 200，降级但可服务)。纯函数，便于单测。
func evaluateReadiness(checks map[string]string) (status string, unavailable bool) {
	status = "ok"
	for name, s := range checks {
		if s == "ok" {
			continue
		}
		status = "degraded"
		if name == "database" {
			unavailable = true
		}
	}
	return status, unavailable
}

// Version GET /api/v1/system/version
// 返回 manager 构建版本（外部健康检查 / 监控轮询用）
func (h *HealthHandler) Version(c *gin.Context) {
	SuccessWithMessage(c, "success", gin.H{
		"version":   BuildVersion,
		"timestamp": time.Now().Format(model.TimeFormat),
		"component": "mxcwpp-manager",
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

// checkClickHouse 探测 ClickHouse 连接（带 2s 超时）。仅在 chConn 已配置时调用。
func (h *HealthHandler) checkClickHouse() string {
	if h.chConn == nil {
		return "unavailable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.chConn.Ping(ctx); err != nil {
		h.logger.Warn("ClickHouse 连接检查失败", zap.Error(err))
		return "error"
	}
	return "ok"
}

// checkRedis 探测 Redis 连接（带 2s 超时）。仅在 redisClient 已配置时调用。
func (h *HealthHandler) checkRedis() string {
	if h.redisClient == nil {
		return "unavailable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.redisClient.Ping(ctx).Err(); err != nil {
		h.logger.Warn("Redis 连接检查失败", zap.Error(err))
		return "error"
	}
	return "ok"
}
