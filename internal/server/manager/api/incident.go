// Package api 提供 HTTP API 处理器
package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// IncidentHandler 安全事件 API 处理器（P2）
type IncidentHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewIncidentHandler 创建安全事件 API 处理器
func NewIncidentHandler(db *gorm.DB, logger *zap.Logger) *IncidentHandler {
	return &IncidentHandler{db: db, logger: logger}
}

// ListIncidentsRequest 查询事件列表请求
type ListIncidentsRequest struct {
	Page     int    `form:"page" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Status   string `form:"status"`
	HostID   string `form:"host_id"`
}

// ListIncidents 获取安全事件列表
// GET /api/v1/incidents
func (h *IncidentHandler) ListIncidents(c *gin.Context) {
	var req ListIncidentsRequest
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

	query := h.db.Model(&model.Incident{})
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.HostID != "" {
		query = query.Where("host_id = ?", req.HostID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询事件总数失败", zap.Error(err))
		InternalError(c, "查询事件失败")
		return
	}

	var items []model.Incident
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("risk_score DESC, last_seen_at DESC").
		Offset(offset).Limit(req.PageSize).Find(&items).Error; err != nil {
		h.logger.Error("查询事件列表失败", zap.Error(err))
		InternalError(c, "查询事件失败")
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

// GetIncident 获取事件详情(含成员告警)
// GET /api/v1/incidents/:id
func (h *IncidentHandler) GetIncident(c *gin.Context) {
	id := c.Param("id")
	var inc model.Incident
	if err := h.db.Where("incident_id = ?", id).First(&inc).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "事件不存在")
			return
		}
		InternalError(c, "查询事件失败")
		return
	}

	// 展开成员告警
	var alerts []model.Alert
	if len(inc.AlertIDs) > 0 {
		h.db.Where("id IN ?", []string(inc.AlertIDs)).Find(&alerts)
	}

	Success(c, gin.H{"incident": inc, "alerts": alerts})
}

// ResolveIncident 人工关闭事件
// POST /api/v1/incidents/:id/resolve
func (h *IncidentHandler) ResolveIncident(c *gin.Context) {
	id := c.Param("id")
	operator := c.GetString("username")
	if operator == "" {
		operator = "unknown"
	}
	now := model.ToLocalTime(time.Now())
	result := h.db.Model(&model.Incident{}).
		Where("incident_id = ? AND status <> ?", id, model.IncidentStatusResolved).
		Updates(map[string]any{
			"status":      model.IncidentStatusResolved,
			"resolved_at": now,
			"resolved_by": operator,
		})
	if result.Error != nil {
		InternalError(c, "关闭事件失败")
		return
	}
	if result.RowsAffected == 0 {
		BadRequest(c, "事件不存在或已关闭")
		return
	}
	SuccessWithMessage(c, "已关闭", nil)
}
