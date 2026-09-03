package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeAlarmHandler 容器告警 API Handler
type KubeAlarmHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewKubeAlarmHandler 创建容器告警 Handler
func NewKubeAlarmHandler(db *gorm.DB, logger *zap.Logger) *KubeAlarmHandler {
	return &KubeAlarmHandler{db: db, logger: logger}
}

// ListAlarms 告警列表（含统计）
func (h *KubeAlarmHandler) ListAlarms(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")
	clusterID := c.Query("cluster_id")
	severity := c.Query("severity")
	status := c.Query("status")

	query := h.db.Model(&model.KubeAlarm{})

	if search != "" {
		query = query.Where("title LIKE ? OR message LIKE ? OR target LIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	if clusterID != "" {
		query = query.Where("cluster_id = ?", clusterID)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询告警总数失败", zap.Error(err))
		InternalError(c, "查询告警列表失败")
		return
	}

	var alarms []model.KubeAlarm
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&alarms).Error; err != nil {
		h.logger.Error("查询告警列表失败", zap.Error(err))
		InternalError(c, "查询告警列表失败")
		return
	}

	// 统计各级别待处理告警数
	var critical, high, medium, low int64
	baseQuery := h.db.Model(&model.KubeAlarm{}).Where("status = ?", "pending")
	baseQuery.Where("severity = ?", "critical").Count(&critical)
	h.db.Model(&model.KubeAlarm{}).Where("status = ? AND severity = ?", "pending", "high").Count(&high)
	h.db.Model(&model.KubeAlarm{}).Where("status = ? AND severity = ?", "pending", "medium").Count(&medium)
	h.db.Model(&model.KubeAlarm{}).Where("status = ? AND severity = ?", "pending", "low").Count(&low)

	Success(c, gin.H{
		"items": alarms,
		"total": total,
		"stats": gin.H{
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
		},
	})
}

// ProcessAlarm 处理单个告警
func (h *KubeAlarmHandler) ProcessAlarm(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的告警 ID")
		return
	}

	now := model.LocalTime(time.Now())
	result := h.db.Model(&model.KubeAlarm{}).Where("id = ? AND status = ?", id, "pending").Updates(map[string]interface{}{
		"status":      model.KubeAlarmStatusProcessed,
		"resolved_at": now,
	})

	if result.Error != nil {
		h.logger.Error("处理告警失败", zap.Error(result.Error))
		InternalError(c, "处理告警失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "告警不存在或已处理")
		return
	}

	SuccessMessage(c, "告警已处理")
}

// BatchProcessAlarms 批量处理告警
func (h *KubeAlarmHandler) BatchProcessAlarms(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	now := model.LocalTime(time.Now())
	result := h.db.Model(&model.KubeAlarm{}).Where("id IN ? AND status = ?", req.IDs, "pending").Updates(map[string]interface{}{
		"status":      model.KubeAlarmStatusProcessed,
		"resolved_at": now,
	})

	if result.Error != nil {
		h.logger.Error("批量处理告警失败", zap.Error(result.Error))
		InternalError(c, "批量处理告警失败")
		return
	}

	Success(c, gin.H{"processed": result.RowsAffected})
}

// BatchIgnoreAlarms 批量忽略告警
func (h *KubeAlarmHandler) BatchIgnoreAlarms(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	now := model.LocalTime(time.Now())
	result := h.db.Model(&model.KubeAlarm{}).Where("id IN ? AND status = ?", req.IDs, "pending").Updates(map[string]interface{}{
		"status":      model.KubeAlarmStatusIgnored,
		"resolved_at": now,
	})

	if result.Error != nil {
		h.logger.Error("批量忽略告警失败", zap.Error(result.Error))
		InternalError(c, "批量忽略告警失败")
		return
	}

	Success(c, gin.H{"ignored": result.RowsAffected})
}
