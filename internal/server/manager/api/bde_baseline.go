package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// BDEBaselineHandler BDE 基线管理 API 处理器
type BDEBaselineHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewBDEBaselineHandler 创建 BDE 基线管理 API 处理器
func NewBDEBaselineHandler(db *gorm.DB, logger *zap.Logger) *BDEBaselineHandler {
	return &BDEBaselineHandler{db: db, logger: logger}
}

// ListBaselineStates 查看所有主机基线学习状态
func (h *BDEBaselineHandler) ListBaselineStates(c *gin.Context) {
	phase := c.Query("phase") // learning / active
	hostID := c.Query("host_id")

	var states []model.HostBaselineState
	query := h.db.Model(&model.HostBaselineState{})
	if phase != "" {
		query = query.Where("phase = ?", phase)
	}
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	query = query.Order("updated_at DESC")

	var total int64
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "查询基线状态失败")
		return
	}

	page, pageSize := parsePagination(c)
	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&states).Error; err != nil {
		InternalError(c, "查询基线状态失败")
		return
	}

	SuccessPaginated(c, total, states)
}

// GetBaselineStats 基线引擎统计概览
func (h *BDEBaselineHandler) GetBaselineStats(c *gin.Context) {
	var totalHosts int64
	var learningHosts int64
	var activeHosts int64

	h.db.Model(&model.HostBaselineState{}).Count(&totalHosts)
	h.db.Model(&model.HostBaselineState{}).Where("phase = ?", "learning").Count(&learningHosts)
	h.db.Model(&model.HostBaselineState{}).Where("phase = ?", "active").Count(&activeHosts)

	var alertCount int64
	h.db.Model(&model.BehaviorAlert{}).Where("status = ?", "open").Count(&alertCount)

	Success(c, gin.H{
		"total_hosts":    totalHosts,
		"learning_hosts": learningHosts,
		"active_hosts":   activeHosts,
		"open_alerts":    alertCount,
	})
}

// ListBehaviorAlerts 查看行为异常告警列表
func (h *BDEBaselineHandler) ListBehaviorAlerts(c *gin.Context) {
	hostID := c.Query("host_id")
	status := c.Query("status")
	metric := c.Query("metric")

	query := h.db.Model(&model.BehaviorAlert{})
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if metric != "" {
		query = query.Where("metric = ?", metric)
	}
	query = query.Order("created_at DESC")

	var total int64
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "查询行为告警失败")
		return
	}

	page, pageSize := parsePagination(c)
	var alerts []model.BehaviorAlert
	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&alerts).Error; err != nil {
		InternalError(c, "查询行为告警失败")
		return
	}

	SuccessPaginated(c, total, alerts)
}

// parsePagination extracts page and page_size from query params with defaults.
func parsePagination(c *gin.Context) (page, pageSize int) {
	page = 1
	pageSize = 20
	if v := c.Query("page"); v != "" {
		if p := parseIntParam(v); p > 0 {
			page = p
		}
	}
	if v := c.Query("page_size"); v != "" {
		if ps := parseIntParam(v); ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}
	return
}

func parseIntParam(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
