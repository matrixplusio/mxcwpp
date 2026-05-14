package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeEventHandler 容器安全事件 API Handler
type KubeEventHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewKubeEventHandler 创建容器安全事件 Handler
func NewKubeEventHandler(db *gorm.DB, logger *zap.Logger) *KubeEventHandler {
	return &KubeEventHandler{db: db, logger: logger}
}

// ListEvents 事件列表
func (h *KubeEventHandler) ListEvents(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")
	clusterID := c.Query("cluster_id")
	eventType := c.Query("event_type")

	query := h.db.Model(&model.KubeEvent{})

	if search != "" {
		query = query.Where("title LIKE ? OR message LIKE ? OR pod_name LIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	if clusterID != "" {
		query = query.Where("cluster_id = ?", clusterID)
	}
	if eventType != "" {
		query = query.Where("event_type = ?", eventType)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询事件总数失败", zap.Error(err))
		InternalError(c, "查询事件列表失败")
		return
	}

	var events []model.KubeEvent
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&events).Error; err != nil {
		h.logger.Error("查询事件列表失败", zap.Error(err))
		InternalError(c, "查询事件列表失败")
		return
	}

	SuccessPaginated(c, total, events)
}

// HandleEvent 处理单个事件
func (h *KubeEventHandler) HandleEvent(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的事件 ID")
		return
	}

	result := h.db.Model(&model.KubeEvent{}).Where("id = ? AND status = ?", id, "unhandled").Update("status", model.KubeEventStatusHandled)

	if result.Error != nil {
		h.logger.Error("处理事件失败", zap.Error(result.Error))
		InternalError(c, "处理事件失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "事件不存在或已处理")
		return
	}

	SuccessMessage(c, "事件已处理")
}
