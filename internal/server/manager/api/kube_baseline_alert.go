package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeBaselineAlertHandler 容器基线告警 API Handler
type KubeBaselineAlertHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewKubeBaselineAlertHandler 创建容器基线告警 Handler
func NewKubeBaselineAlertHandler(db *gorm.DB, logger *zap.Logger) *KubeBaselineAlertHandler {
	return &KubeBaselineAlertHandler{db: db, logger: logger}
}

// ListAlerts 基线告警列表
func (h *KubeBaselineAlertHandler) ListAlerts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	clusterID := c.Query("cluster_id")
	severity := c.Query("severity")
	status := c.Query("status")
	category := c.Query("category")
	search := c.Query("search")

	query := h.db.Model(&model.KubeBaselineAlert{})

	if clusterID != "" {
		query = query.Where("cluster_id = ?", clusterID)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if category != "" {
		query = query.Where("category = ?", category)
	}
	if search != "" {
		query = query.Where("check_name LIKE ? OR check_id LIKE ?", "%"+search+"%", "%"+search+"%")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询基线告警总数失败", zap.Error(err))
		InternalError(c, "查询基线告警列表失败")
		return
	}

	var alerts []model.KubeBaselineAlert
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("FIELD(severity, 'critical', 'high', 'medium', 'low'), last_seen_at DESC").Find(&alerts).Error; err != nil {
		h.logger.Error("查询基线告警列表失败", zap.Error(err))
		InternalError(c, "查询基线告警列表失败")
		return
	}

	// 统计各状态数
	var activeCount, resolvedCount, ignoredCount int64
	h.db.Model(&model.KubeBaselineAlert{}).Where("status = ?", "active").Count(&activeCount)
	h.db.Model(&model.KubeBaselineAlert{}).Where("status = ?", "resolved").Count(&resolvedCount)
	h.db.Model(&model.KubeBaselineAlert{}).Where("status = ?", "ignored").Count(&ignoredCount)

	Success(c, gin.H{
		"items": alerts,
		"total": total,
		"stats": gin.H{
			"active":   activeCount,
			"resolved": resolvedCount,
			"ignored":  ignoredCount,
		},
	})
}

// IgnoreAlert 忽略基线告警
func (h *KubeBaselineAlertHandler) IgnoreAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的告警 ID")
		return
	}

	now := model.LocalTime(time.Now())
	result := h.db.Model(&model.KubeBaselineAlert{}).Where("id = ? AND status = ?", id, "active").Updates(map[string]interface{}{
		"status":      model.KubeBaselineAlertStatusIgnored,
		"resolved_at": now,
	})

	if result.Error != nil {
		h.logger.Error("忽略基线告警失败", zap.Error(result.Error))
		InternalError(c, "忽略基线告警失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "告警不存在或已处理")
		return
	}

	SuccessMessage(c, "已忽略")
}

// BatchIgnoreAlerts 批量忽略基线告警
func (h *KubeBaselineAlertHandler) BatchIgnoreAlerts(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	now := model.LocalTime(time.Now())
	result := h.db.Model(&model.KubeBaselineAlert{}).Where("id IN ? AND status = ?", req.IDs, "active").Updates(map[string]interface{}{
		"status":      model.KubeBaselineAlertStatusIgnored,
		"resolved_at": now,
	})

	if result.Error != nil {
		h.logger.Error("批量忽略基线告警失败", zap.Error(result.Error))
		InternalError(c, "批量忽略基线告警失败")
		return
	}

	Success(c, gin.H{"ignored": result.RowsAffected})
}
