// Package api 提供 HTTP API 处理器
package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// AlertsHandler 告警管理 API 处理器
type AlertsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAlertsHandler 创建告警管理 API 处理器
func NewAlertsHandler(db *gorm.DB, logger *zap.Logger) *AlertsHandler {
	return &AlertsHandler{
		db:     db,
		logger: logger,
	}
}

// ListAlertsRequest 获取告警列表请求
type ListAlertsRequest struct {
	Page         int    `form:"page" binding:"omitempty,min=1"`
	PageSize     int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Status       string `form:"status"`   // active, resolved, ignored
	Severity     string `form:"severity"` // critical, high, medium, low
	HostID       string `form:"host_id"`
	RuleID       string `form:"rule_id"`
	Category     string `form:"category"`
	AlertType    string `form:"alert_type"`    // baseline, runtime, agent, vulnerability, fim, virus, kube
	Keyword      string `form:"keyword"`       // 搜索标题或描述
	ResultID     string `form:"result_id"`     // 根据 result_id 查询
	RuntimeType  string `form:"runtime_type"`  // vm, docker, k8s
	BusinessLine string `form:"business_line"` // 按业务线过滤
	MitreID      string `form:"mitre_id"`      // 按 MITRE ATT&CK ID 过滤
	StartTime    string `form:"start_time"`    // 时间范围起 (RFC3339)
	EndTime      string `form:"end_time"`      // 时间范围止 (RFC3339)
}

// ListAlerts 获取告警列表
// GET /api/v1/alerts
func (h *AlertsHandler) ListAlerts(c *gin.Context) {
	var req ListAlertsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 设置默认值
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}

	query := h.db.Model(&model.Alert{}).Preload("Host").Preload("Rule")

	// 过滤条件
	if req.Status != "" {
		// 支持多个状态，用逗号分隔
		statuses := strings.Split(req.Status, ",")
		if len(statuses) > 1 {
			query = query.Where("status IN ?", statuses)
		} else {
			query = query.Where("status = ?", req.Status)
		}
	}
	if req.Severity != "" {
		query = query.Where("severity = ?", req.Severity)
	}
	if req.HostID != "" {
		query = query.Where("host_id = ?", req.HostID)
	}
	if req.RuleID != "" {
		query = query.Where("rule_id = ?", req.RuleID)
	}
	if req.Category != "" {
		query = query.Where("category = ?", req.Category)
	}
	if req.AlertType != "" {
		query = query.Where("source = ?", req.AlertType)
	}
	if req.ResultID != "" {
		query = query.Where("result_id = ?", req.ResultID)
	}
	if req.Keyword != "" {
		query = query.Where("title LIKE ? OR description LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}
	// hosts JOIN：当 runtime_type 或 business_line 有值时合并为一次 JOIN
	if req.RuntimeType != "" || req.BusinessLine != "" {
		query = query.Joins("JOIN hosts ON hosts.host_id = alerts.host_id")
		if req.RuntimeType != "" {
			query = query.Where("hosts.runtime_type = ?", req.RuntimeType)
		}
		if req.BusinessLine != "" {
			query = query.Where("hosts.business_line = ?", req.BusinessLine)
		}
	}
	if req.MitreID != "" {
		query = query.Joins("JOIN detection_rules ON CONCAT('cel-', detection_rules.id) = alerts.rule_id").
			Where("detection_rules.mitre_id = ?", req.MitreID)
	}
	if req.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, req.StartTime); err == nil {
			query = query.Where("last_seen_at >= ?", t)
		}
	}
	if req.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, req.EndTime); err == nil {
			query = query.Where("last_seen_at <= ?", t)
		}
	}

	// 获取总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询告警总数失败", zap.Error(err))
		InternalError(c, "查询告警列表失败")
		return
	}

	// 获取列表
	var alerts []model.Alert
	offset := (req.Page - 1) * req.PageSize
	// P2-A 风险分级：高风险优先（risk_score DESC），同分按最近活跃
	if err := query.Order("risk_score DESC, last_seen_at DESC").Offset(offset).Limit(req.PageSize).Find(&alerts).Error; err != nil {
		h.logger.Error("查询告警列表失败", zap.Error(err))
		InternalError(c, "查询告警列表失败")
		return
	}

	Success(c, gin.H{
		"items":      alerts,
		"total":      total,
		"page":       req.Page,
		"page_size":  req.PageSize,
		"total_page": (int(total) + req.PageSize - 1) / req.PageSize,
	})
}

// GetAlert 获取告警详情
// GET /api/v1/alerts/:id
func (h *AlertsHandler) GetAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的告警ID")
		return
	}

	var alert model.Alert
	if err := h.db.Preload("Host").Preload("Rule").First(&alert, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "告警不存在")
			return
		}
		h.logger.Error("查询告警失败", zap.Error(err))
		InternalError(c, "查询告警失败")
		return
	}

	Success(c, alert)
}

// ResolveAlertRequest 解决告警请求
type ResolveAlertRequest struct {
	Reason string `json:"reason"` // 解决原因
}

// ResolveAlert 解决告警
// POST /api/v1/alerts/:id/resolve
func (h *AlertsHandler) ResolveAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的告警ID")
		return
	}

	var req ResolveAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	var alert model.Alert
	if err := h.db.First(&alert, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "告警不存在")
			return
		}
		h.logger.Error("查询告警失败", zap.Error(err))
		InternalError(c, "查询告警失败")
		return
	}

	now := model.Now()
	alert.Status = model.AlertStatusResolved
	alert.ResolvedAt = &now
	alert.ResolveReason = req.Reason
	// TODO: 从认证信息中获取用户名
	alert.ResolvedBy = "admin"

	if err := h.db.Save(&alert).Error; err != nil {
		h.logger.Error("更新告警失败", zap.Error(err))
		InternalError(c, "解决告警失败")
		return
	}

	SuccessWithMessage(c, "告警已解决", alert)
}

// IgnoreAlert 忽略告警
// POST /api/v1/alerts/:id/ignore
func (h *AlertsHandler) IgnoreAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的告警ID")
		return
	}

	var alert model.Alert
	if err := h.db.First(&alert, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "告警不存在")
			return
		}
		h.logger.Error("查询告警失败", zap.Error(err))
		InternalError(c, "查询告警失败")
		return
	}

	alert.Status = model.AlertStatusIgnored

	if err := h.db.Save(&alert).Error; err != nil {
		h.logger.Error("更新告警失败", zap.Error(err))
		InternalError(c, "忽略告警失败")
		return
	}

	SuccessWithMessage(c, "告警已忽略", alert)
}

// GetAlertStatistics 获取告警统计
// GET /api/v1/alerts/statistics
// 优化：2 条 GROUP BY 替代 8 条独立 COUNT
func (h *AlertsHandler) GetAlertStatistics(c *gin.Context) {
	var stats struct {
		Total    int64 `json:"total"`
		Active   int64 `json:"active"`
		Resolved int64 `json:"resolved"`
		Ignored  int64 `json:"ignored"`
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	}

	// 按状态聚合
	var statusRows []struct {
		Status string
		Cnt    int64
	}
	h.db.Model(&model.Alert{}).Select("status, COUNT(*) AS cnt").Group("status").Scan(&statusRows)
	for _, r := range statusRows {
		stats.Total += r.Cnt
		switch r.Status {
		case string(model.AlertStatusActive):
			stats.Active = r.Cnt
		case string(model.AlertStatusResolved):
			stats.Resolved = r.Cnt
		case string(model.AlertStatusIgnored):
			stats.Ignored = r.Cnt
		}
	}

	// 按严重级别聚合（只统计活跃告警）
	var severityRows []struct {
		Severity string
		Cnt      int64
	}
	h.db.Model(&model.Alert{}).
		Select("severity, COUNT(*) AS cnt").
		Where("status = ?", model.AlertStatusActive).
		Group("severity").
		Scan(&severityRows)
	for _, r := range severityRows {
		switch r.Severity {
		case "critical":
			stats.Critical = r.Cnt
		case "high":
			stats.High = r.Cnt
		case "medium":
			stats.Medium = r.Cnt
		case "low":
			stats.Low = r.Cnt
		}
	}

	Success(c, stats)
}

// BatchAlertRequest 批量操作请求
type BatchAlertRequest struct {
	IDs    []uint `json:"ids" binding:"required"`
	Reason string `json:"reason"`
}

// BatchResolveAlerts 批量解决告警
// POST /api/v1/alerts/batch/resolve
func (h *AlertsHandler) BatchResolveAlerts(c *gin.Context) {
	var req BatchAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if len(req.IDs) == 0 {
		BadRequest(c, "请选择要解决的告警")
		return
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":      model.AlertStatusResolved,
		"resolved_at": &now,
		"updated_at":  now,
	}
	if req.Reason != "" {
		updates["resolve_reason"] = req.Reason
	}

	result := h.db.Model(&model.Alert{}).
		Where("id IN ? AND status = ?", req.IDs, model.AlertStatusActive).
		Updates(updates)

	if result.Error != nil {
		h.logger.Error("批量解决告警失败", zap.Error(result.Error))
		InternalError(c, "批量解决告警失败")
		return
	}

	h.logger.Info("批量解决告警", zap.Int64("count", result.RowsAffected))
	SuccessWithMessage(c, fmt.Sprintf("成功解决 %d 个告警", result.RowsAffected), nil)
}

// BatchIgnoreAlerts 批量忽略告警
// POST /api/v1/alerts/batch/ignore
func (h *AlertsHandler) BatchIgnoreAlerts(c *gin.Context) {
	var req BatchAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if len(req.IDs) == 0 {
		BadRequest(c, "请选择要忽略的告警")
		return
	}

	now := time.Now()
	result := h.db.Model(&model.Alert{}).
		Where("id IN ? AND status = ?", req.IDs, model.AlertStatusActive).
		Updates(map[string]interface{}{
			"status":     model.AlertStatusIgnored,
			"updated_at": now,
		})

	if result.Error != nil {
		h.logger.Error("批量忽略告警失败", zap.Error(result.Error))
		InternalError(c, "批量忽略告警失败")
		return
	}

	h.logger.Info("批量忽略告警", zap.Int64("count", result.RowsAffected))
	SuccessWithMessage(c, fmt.Sprintf("成功忽略 %d 个告警", result.RowsAffected), nil)
}

// BatchDeleteAlerts 批量删除告警
// POST /api/v1/alerts/batch/delete
func (h *AlertsHandler) BatchDeleteAlerts(c *gin.Context) {
	var req BatchAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if len(req.IDs) == 0 {
		BadRequest(c, "请选择要删除的告警")
		return
	}

	result := h.db.Where("id IN ?", req.IDs).Delete(&model.Alert{})

	if result.Error != nil {
		h.logger.Error("批量删除告警失败", zap.Error(result.Error))
		InternalError(c, "批量删除告警失败")
		return
	}

	h.logger.Info("批量删除告警", zap.Int64("count", result.RowsAffected))
	SuccessWithMessage(c, fmt.Sprintf("成功删除 %d 个告警", result.RowsAffected), nil)
}
