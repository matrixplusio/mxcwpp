package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AnomalyHandler handles ML anomaly detection API requests.
type AnomalyHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAnomalyHandler creates a new anomaly detection handler.
func NewAnomalyHandler(db *gorm.DB, logger *zap.Logger) *AnomalyHandler {
	return &AnomalyHandler{db: db, logger: logger}
}

// ListAnomalies returns paginated ML anomaly alerts.
// GET /api/v1/anomalies?host_id=xxx&alert_type=isolation_forest&severity=critical&status=open&page=1&page_size=20
func (h *AnomalyHandler) ListAnomalies(c *gin.Context) {
	hostID := c.Query("host_id")
	alertType := c.Query("alert_type")
	severity := c.Query("severity")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	q := h.db.Model(&model.AnomalyAlert{})
	if hostID != "" {
		q = q.Where("host_id = ?", hostID)
	}
	if alertType != "" {
		q = q.Where("alert_type = ?", alertType)
	}
	if severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var total int64
	q.Count(&total)

	var alerts []model.AnomalyAlert
	if err := q.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&alerts).Error; err != nil {
		InternalError(c, "查询失败")
		return
	}

	Success(c, PaginatedData{Total: total, Items: alerts})
}

// GetAnomalyStats returns anomaly alert statistics.
// GET /api/v1/anomalies/stats
//
// 性能:原 5 query 串行 ~0.76s,合并 3 COUNT 为 1 个 conditional aggregate +
// 2 个 GROUP BY 并发,~50-100ms。
func (h *AnomalyHandler) GetAnomalyStats(c *gin.Context) {
	type aggRow struct {
		Total    int64
		OpenCnt  int64
		Critical int64
	}
	var agg aggRow

	type typeCount struct {
		AlertType string `json:"alert_type"`
		Count     int64  `json:"count"`
	}
	var byType, byPattern []typeCount

	g := new(errgroup.Group)

	// 3 COUNT 合并为 1 conditional aggregate query
	g.Go(func() error {
		return h.db.Model(&model.AnomalyAlert{}).
			Select(`COUNT(*) AS total,
			        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_cnt,
			        SUM(CASE WHEN severity = 'critical' AND status = 'open' THEN 1 ELSE 0 END) AS critical`).
			Scan(&agg).Error
	})

	// By alert type GROUP BY
	g.Go(func() error {
		return h.db.Model(&model.AnomalyAlert{}).
			Select("alert_type, count(*) as count").
			Where("status = ?", "open").
			Group("alert_type").
			Find(&byType).Error
	})

	// By pattern (correlation only)
	g.Go(func() error {
		return h.db.Model(&model.AnomalyAlert{}).
			Select("pattern_name as alert_type, count(*) as count").
			Where("status = ? AND alert_type = ?", "open", "correlation").
			Group("pattern_name").
			Find(&byPattern).Error
	})

	if err := g.Wait(); err != nil {
		h.logger.Warn("异常告警统计查询失败", zap.Error(err))
	}

	Success(c, gin.H{
		"total":      agg.Total,
		"open":       agg.OpenCnt,
		"critical":   agg.Critical,
		"by_type":    byType,
		"by_pattern": byPattern,
	})
}

type resolveAnomalyReq struct {
	Status string `json:"status" binding:"required"` // confirmed / false_positive
}

// ResolveAnomaly updates the status of an anomaly alert.
// PUT /api/v1/anomalies/:id/resolve
func (h *AnomalyHandler) ResolveAnomaly(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的 ID")
		return
	}

	var req resolveAnomalyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	if req.Status != "confirmed" && req.Status != "false_positive" {
		BadRequest(c, "状态必须是 confirmed 或 false_positive")
		return
	}

	var alert model.AnomalyAlert
	if err := h.db.First(&alert, id).Error; err != nil {
		NotFound(c, "异常告警不存在")
		return
	}

	username, _ := c.Get("username")
	h.db.Model(&alert).Updates(map[string]any{
		"status":      req.Status,
		"resolved_by": fmt.Sprintf("%v", username),
	})

	Success(c, alert)
}
