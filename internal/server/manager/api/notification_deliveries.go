package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// DeliveryItem 一条投递记录，附带它所属事件的类型、主机与来源。
type DeliveryItem struct {
	ID             uint                 `json:"id"`
	CreatedAt      time.Time            `json:"created_at"`
	EventID        uint                 `json:"event_id"`
	NotificationID uint                 `json:"notification_id"`
	ChannelName    string               `json:"channel_name"`
	Category       model.NotifyCategory `json:"category"`
	Severity       string               `json:"severity"`
	Title          string               `json:"title"`
	Outcome        string               `json:"outcome"`
	Error          string               `json:"error"`
	Kind           string               `json:"kind"`
	Source         string               `json:"source"`
	HostID         string               `json:"host_id"`
	Hostname       string               `json:"hostname"`
	RefTable       string               `json:"ref_table"`
	RefID          string               `json:"ref_id"`
}

// ListNotificationDeliveries 通知投递记录：每条告警对每个渠道发没发、为什么没发。
// GET /api/v1/notification-deliveries?outcome=&category=&notification_id=&keyword=&page=&page_size=
func (h *NotificationsHandler) ListNotificationDeliveries(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}

	q := h.db.Table("notification_deliveries AS d").
		Joins("LEFT JOIN alert_notify_events AS e ON e.id = d.event_id")
	if v := c.Query("outcome"); v != "" {
		q = q.Where("d.outcome = ?", v)
	}
	if v := c.Query("category"); v != "" {
		q = q.Where("d.category = ?", v)
	}
	if v := c.Query("notification_id"); v != "" {
		q = q.Where("d.notification_id = ?", v)
	}
	if v := strings.TrimSpace(c.Query("keyword")); v != "" {
		like := "%" + v + "%"
		q = q.Where("d.title LIKE ? OR e.hostname LIKE ? OR e.host_id LIKE ?", like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.logger.Error("统计投递记录失败", zap.Error(err))
		InternalError(c, "查询投递记录失败")
		return
	}
	var items []DeliveryItem
	err := q.Select("d.id, d.created_at, d.event_id, d.notification_id, d.channel_name, d.category, d.severity, " +
		"d.title, d.outcome, d.error, e.kind, e.source, e.host_id, e.hostname, e.ref_table, e.ref_id").
		Order("d.id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Scan(&items).Error
	if err != nil {
		h.logger.Error("查询投递记录失败", zap.Error(err))
		InternalError(c, "查询投递记录失败")
		return
	}
	SuccessPaginated(c, total, items)
}
