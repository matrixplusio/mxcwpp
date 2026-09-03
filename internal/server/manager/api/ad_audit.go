// Package api — AD / LDAP 域控审计 HTTP handler (EDR-4).
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type ADAuditHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewADAuditHandler(db *gorm.DB, logger *zap.Logger) *ADAuditHandler {
	return &ADAuditHandler{db: db, logger: logger}
}

// ListEvents GET /api/v1/ad-audit/events.
func (h *ADAuditHandler) ListEvents(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	q := h.db.WithContext(c.Request.Context()).Model(&model.ADAuditEvent{}).Where("tenant_id = ?", tenantID)
	if v := c.Query("kind"); v != "" {
		q = q.Where("kind = ?", v)
	}
	if v := c.Query("username"); v != "" {
		q = q.Where("username = ?", v)
	}
	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip = ?", v)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.logger.Error("count ad-audit events failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	var rows []model.ADAuditEvent
	if err := q.Order("timestamp DESC").Limit(200).Find(&rows).Error; err != nil {
		h.logger.Error("list ad-audit events failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	Success(c, gin.H{"items": rows, "total": total})
}

// ListAlerts GET /api/v1/ad-audit/alerts.
func (h *ADAuditHandler) ListAlerts(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	q := h.db.WithContext(c.Request.Context()).Model(&model.ADAuditAlert{}).Where("tenant_id = ?", tenantID)
	if v := c.Query("rule_id"); v != "" {
		q = q.Where("rule_id = ?", v)
	}
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.logger.Error("count ad-audit alerts failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	var rows []model.ADAuditAlert
	if err := q.Order("detected_at DESC").Limit(200).Find(&rows).Error; err != nil {
		h.logger.Error("list ad-audit alerts failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	Success(c, gin.H{"items": rows, "total": total})
}

type topFailedUser struct {
	User  string `json:"user"`
	Count int    `json:"count"`
}

// Stats GET /api/v1/ad-audit/stats.
func (h *ADAuditHandler) Stats(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}
	ctx := c.Request.Context()

	var totalEvents24h, totalAlerts24h int64
	h.db.WithContext(ctx).Model(&model.ADAuditEvent{}).
		Where("tenant_id = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 1 DAY)", tenantID).
		Count(&totalEvents24h)
	h.db.WithContext(ctx).Model(&model.ADAuditAlert{}).
		Where("tenant_id = ? AND detected_at > DATE_SUB(NOW(), INTERVAL 1 DAY)", tenantID).
		Count(&totalAlerts24h)

	byKind := map[string]int64{}
	rows, err := h.db.WithContext(ctx).Model(&model.ADAuditEvent{}).
		Select("kind, COUNT(*) AS cnt").
		Where("tenant_id = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 1 DAY)", tenantID).
		Group("kind").Rows()
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var cnt int64
			if err := rows.Scan(&k, &cnt); err == nil {
				byKind[k] = cnt
			}
		}
	}

	var top []topFailedUser
	failRows, err := h.db.WithContext(ctx).Model(&model.ADAuditEvent{}).
		Select("username AS user, COUNT(*) AS cnt").
		Where("tenant_id = ? AND kind = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 1 DAY)", tenantID, "login_failure").
		Group("username").Order("cnt DESC").Limit(5).Rows()
	if err == nil {
		defer failRows.Close()
		for failRows.Next() {
			var u string
			var cnt int
			if err := failRows.Scan(&u, &cnt); err == nil && u != "" {
				top = append(top, topFailedUser{User: u, Count: cnt})
			}
		}
	}

	Success(c, gin.H{
		"total_events_24h": totalEvents24h,
		"total_alerts_24h": totalAlerts24h,
		"by_kind":          byKind,
		"top_failed_users": top,
	})
}
