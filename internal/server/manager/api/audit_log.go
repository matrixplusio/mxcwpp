// Package api 提供 HTTP API 处理器
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AuditLogHandler 操作审计日志 API 处理器
type AuditLogHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAuditLogHandler 创建审计日志 API 处理器
func NewAuditLogHandler(db *gorm.DB, logger *zap.Logger) *AuditLogHandler {
	return &AuditLogHandler{db: db, logger: logger}
}

// ListAuditLogsRequest 查询审计日志列表请求
type ListAuditLogsRequest struct {
	Page         int    `form:"page" binding:"omitempty,min=1"`
	PageSize     int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Username     string `form:"username"`
	Action       string `form:"action"`        // POST/PUT/DELETE
	ResourceType string `form:"resource_type"` // hosts/policies 等
	StartTime    string `form:"start_time"`    // 2006-01-02 15:04:05
	EndTime      string `form:"end_time"`
}

// ListAuditLogs 获取审计日志列表
// GET /api/v1/audit-logs
func (h *AuditLogHandler) ListAuditLogs(c *gin.Context) {
	var req ListAuditLogsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}

	query := h.db.Model(&model.AuditLog{})

	if req.Username != "" {
		query = query.Where("username LIKE ?", "%"+req.Username+"%")
	}
	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}
	if req.ResourceType != "" {
		query = query.Where("resource_type = ?", req.ResourceType)
	}
	if req.StartTime != "" {
		query = query.Where("created_at >= ?", req.StartTime)
	}
	if req.EndTime != "" {
		query = query.Where("created_at <= ?", req.EndTime)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询审计日志总数失败", zap.Error(err))
		InternalError(c, "查询审计日志失败")
		return
	}

	var logs []model.AuditLog
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(req.PageSize).Find(&logs).Error; err != nil {
		h.logger.Error("查询审计日志失败", zap.Error(err))
		InternalError(c, "查询审计日志失败")
		return
	}

	Success(c, gin.H{
		"items":      logs,
		"total":      total,
		"page":       req.Page,
		"page_size":  req.PageSize,
		"total_page": (int(total) + req.PageSize - 1) / req.PageSize,
	})
}
