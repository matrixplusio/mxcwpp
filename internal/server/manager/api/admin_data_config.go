// Package api 提供 HTTP API 处理器。
//
// admin_data_config.go 实现数据存储配置相关接口：
//   - GET    /api/v1/admin/feature-flags          列出 feature_flags
//   - PUT    /api/v1/admin/feature-flags/:key     更新 flag value
//   - GET    /api/v1/admin/retention-policies     列出 retention_policies
//   - PUT    /api/v1/admin/retention-policies/:ch_table  更新保留天数
//
// 修改 retention 时会立即下发 ALTER TABLE ... MODIFY TTL 到 CH。
package api

import (
	"context"
	"fmt"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// AdminDataConfigHandler 数据存储配置处理器。
type AdminDataConfigHandler struct {
	db     *gorm.DB
	chConn chdriver.Conn // 可为 nil
	logger *zap.Logger
}

// NewAdminDataConfigHandler 创建处理器
func NewAdminDataConfigHandler(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) *AdminDataConfigHandler {
	return &AdminDataConfigHandler{db: db, chConn: chConn, logger: logger}
}

// ListFeatureFlags 返回所有 feature_flags（按 key 字典序）。
func (h *AdminDataConfigHandler) ListFeatureFlags(c *gin.Context) {
	var items []model.FeatureFlag
	if err := h.db.Order("flag_key ASC").Find(&items).Error; err != nil {
		InternalError(c, "查询 feature flags 失败")
		return
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}

// UpdateFeatureFlagRequest 更新请求体。
type UpdateFeatureFlagRequest struct {
	Value string `json:"value" binding:"required"`
}

// UpdateFeatureFlag 更新 flag value。修改不立即生效，consumer / manager 需重启。
func (h *AdminDataConfigHandler) UpdateFeatureFlag(c *gin.Context) {
	key := c.Param("key")
	var req UpdateFeatureFlagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	var ff model.FeatureFlag
	if err := h.db.Where("flag_key = ?", key).First(&ff).Error; err != nil {
		NotFound(c, "feature flag 不存在")
		return
	}
	username := c.GetString("username")
	if username == "" {
		username = "admin"
	}
	if err := h.db.Model(&ff).Updates(map[string]any{
		"value":      req.Value,
		"updated_by": username,
	}).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}
	h.logger.Info("feature_flag 已更新",
		zap.String("key", key),
		zap.String("value", req.Value),
		zap.String("updated_by", username))
	Success(c, ff)
}

// ListRetentionPolicies 列出所有保留策略。
func (h *AdminDataConfigHandler) ListRetentionPolicies(c *gin.Context) {
	var items []model.RetentionPolicy
	if err := h.db.Order("ch_table ASC").Find(&items).Error; err != nil {
		InternalError(c, "查询 retention policies 失败")
		return
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}

// UpdateRetentionPolicyRequest 更新请求体。
type UpdateRetentionPolicyRequest struct {
	RetentionDays int `json:"retention_days" binding:"required,min=1,max=3650"`
}

// UpdateRetentionPolicy 修改保留天数，立即下发 CH ALTER TABLE MODIFY TTL。
// CH 端是元数据操作，秒级完成；旧数据下次 merge 时清理。
func (h *AdminDataConfigHandler) UpdateRetentionPolicy(c *gin.Context) {
	chTable := c.Param("ch_table")
	var req UpdateRetentionPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误（保留天数 1-3650）")
		return
	}
	var rp model.RetentionPolicy
	if err := h.db.Where("ch_table = ?", chTable).First(&rp).Error; err != nil {
		NotFound(c, "保留策略不存在")
		return
	}

	// 下发 ALTER TABLE 到 CH
	if h.chConn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ddl := fmt.Sprintf(
			"ALTER TABLE %s MODIFY TTL toDateTime(timestamp) + INTERVAL %d DAY",
			chTable, req.RetentionDays)
		if err := h.chConn.Exec(ctx, ddl); err != nil {
			h.logger.Error("CH ALTER TTL 失败",
				zap.String("table", chTable),
				zap.Int("days", req.RetentionDays),
				zap.Error(err))
			InternalError(c, fmt.Sprintf("CH ALTER TTL 失败: %s", err.Error()))
			return
		}
		h.logger.Info("CH TTL 已下发",
			zap.String("table", chTable),
			zap.Int("days", req.RetentionDays))
	}

	username := c.GetString("username")
	if username == "" {
		username = "admin"
	}
	if err := h.db.Model(&rp).Updates(map[string]any{
		"retention_days": req.RetentionDays,
		"updated_by":     username,
	}).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}
	h.logger.Info("retention_policy 已更新",
		zap.String("ch_table", chTable),
		zap.Int("days", req.RetentionDays),
		zap.String("updated_by", username))
	Success(c, rp)
}
