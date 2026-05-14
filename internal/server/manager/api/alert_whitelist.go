// Package api 提供 HTTP API 处理器
package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AlertWhitelistHandler 告警白名单 API 处理器
type AlertWhitelistHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAlertWhitelistHandler 创建告警白名单 API 处理器
func NewAlertWhitelistHandler(db *gorm.DB, logger *zap.Logger) *AlertWhitelistHandler {
	return &AlertWhitelistHandler{db: db, logger: logger}
}

// ListWhitelistRequest 查询白名单列表请求
type ListWhitelistRequest struct {
	Page     int    `form:"page" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Keyword  string `form:"keyword"`
}

// ListWhitelist 获取白名单列表
// GET /api/v1/alerts/whitelist
func (h *AlertWhitelistHandler) ListWhitelist(c *gin.Context) {
	var req ListWhitelistRequest
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

	query := h.db.Model(&model.AlertWhitelist{})
	if req.Keyword != "" {
		query = query.Where("name LIKE ? OR reason LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询白名单总数失败", zap.Error(err))
		InternalError(c, "查询白名单失败")
		return
	}

	var items []model.AlertWhitelist
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(req.PageSize).Find(&items).Error; err != nil {
		h.logger.Error("查询白名单列表失败", zap.Error(err))
		InternalError(c, "查询白名单失败")
		return
	}

	Success(c, gin.H{
		"items":      items,
		"total":      total,
		"page":       req.Page,
		"page_size":  req.PageSize,
		"total_page": (int(total) + req.PageSize - 1) / req.PageSize,
	})
}

// CreateWhitelistRequest 创建白名单请求
type CreateWhitelistRequest struct {
	Name     string `json:"name" binding:"required"`
	RuleID   string `json:"rule_id"`
	HostID   string `json:"host_id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// CreateWhitelist 创建白名单条目
// POST /api/v1/alerts/whitelist
func (h *AlertWhitelistHandler) CreateWhitelist(c *gin.Context) {
	var req CreateWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	item := &model.AlertWhitelist{
		Name:     req.Name,
		RuleID:   req.RuleID,
		HostID:   req.HostID,
		Category: req.Category,
		Severity: req.Severity,
		Reason:   req.Reason,
	}

	if err := h.db.Create(item).Error; err != nil {
		h.logger.Error("创建白名单失败", zap.Error(err))
		InternalError(c, "创建白名单失败")
		return
	}

	h.logger.Info("白名单已创建", zap.Uint("id", item.ID), zap.String("name", item.Name))
	Success(c, item)
}

// UpdateWhitelistRequest 更新白名单请求
type UpdateWhitelistRequest struct {
	Name     string `json:"name" binding:"required"`
	RuleID   string `json:"rule_id"`
	HostID   string `json:"host_id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// UpdateWhitelist 更新白名单条目
// PUT /api/v1/alerts/whitelist/:id
func (h *AlertWhitelistHandler) UpdateWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的白名单ID")
		return
	}

	var item model.AlertWhitelist
	if err := h.db.First(&item, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "白名单条目不存在")
			return
		}
		InternalError(c, "查询白名单失败")
		return
	}

	var req UpdateWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	item.Name = req.Name
	item.RuleID = req.RuleID
	item.HostID = req.HostID
	item.Category = req.Category
	item.Severity = req.Severity
	item.Reason = req.Reason

	if err := h.db.Save(&item).Error; err != nil {
		h.logger.Error("更新白名单失败", zap.Error(err))
		InternalError(c, "更新白名单失败")
		return
	}

	Success(c, item)
}

// DeleteWhitelist 删除白名单条目
// DELETE /api/v1/alerts/whitelist/:id
func (h *AlertWhitelistHandler) DeleteWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的白名单ID")
		return
	}

	result := h.db.Delete(&model.AlertWhitelist{}, id)
	if result.Error != nil {
		h.logger.Error("删除白名单失败", zap.Error(result.Error))
		InternalError(c, "删除白名单失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "白名单条目不存在")
		return
	}

	h.logger.Info("白名单已删除", zap.Uint64("id", id))
	SuccessWithMessage(c, "删除成功", nil)
}
