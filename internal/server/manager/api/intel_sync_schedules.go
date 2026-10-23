package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// IntelSyncSchedulesHandler 威胁情报同步计划 API 处理器
type IntelSyncSchedulesHandler struct {
	db        *gorm.DB
	logger    *zap.Logger
	scheduler *biz.IntelSyncScheduler
}

// NewIntelSyncSchedulesHandler 创建处理器
func NewIntelSyncSchedulesHandler(db *gorm.DB, logger *zap.Logger, scheduler *biz.IntelSyncScheduler) *IntelSyncSchedulesHandler {
	return &IntelSyncSchedulesHandler{db: db, logger: logger, scheduler: scheduler}
}

// ListSchedules 同步计划列表
func (h *IntelSyncSchedulesHandler) ListSchedules(c *gin.Context) {
	var schedules []model.IntelSyncSchedule
	if err := h.db.Order("created_at DESC").Find(&schedules).Error; err != nil {
		InternalError(c, "查询情报同步计划失败")
		return
	}
	Success(c, schedules)
}

// CreateSchedule 创建同步计划
func (h *IntelSyncSchedulesHandler) CreateSchedule(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		CronExpr string `json:"cronExpr" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误: "+err.Error())
		return
	}

	schedule := &model.IntelSyncSchedule{
		Name:      req.Name,
		CronExpr:  req.CronExpr,
		Enabled:   true,
		CreatedBy: c.GetString("username"),
	}

	if err := h.scheduler.AddSchedule(schedule); err != nil {
		BadRequest(c, "创建情报同步计划失败: "+err.Error())
		return
	}

	Success(c, schedule)
}

// UpdateSchedule 更新同步计划
func (h *IntelSyncSchedulesHandler) UpdateSchedule(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	var req map[string]any
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	if err := h.scheduler.UpdateSchedule(uint(id), req); err != nil {
		InternalError(c, "更新失败: "+err.Error())
		return
	}

	SuccessMessage(c, "更新成功")
}

// DeleteSchedule 删除同步计划
func (h *IntelSyncSchedulesHandler) DeleteSchedule(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	if err := h.scheduler.RemoveSchedule(uint(id)); err != nil {
		InternalError(c, "删除失败: "+err.Error())
		return
	}

	SuccessMessage(c, "删除成功")
}

// ToggleSchedule 启用/禁用同步计划
func (h *IntelSyncSchedulesHandler) ToggleSchedule(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	if err := h.scheduler.ToggleSchedule(uint(id)); err != nil {
		InternalError(c, "切换状态失败: "+err.Error())
		return
	}

	SuccessMessage(c, "操作成功")
}

// RunSchedule 立即运行一次同步
func (h *IntelSyncSchedulesHandler) RunSchedule(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	if err := h.scheduler.RunNow(uint(id)); err != nil {
		InternalError(c, "触发失败: "+err.Error())
		return
	}

	SuccessMessage(c, "已触发同步")
}

// ListExecutions 查询同步计划的执行历史
func (h *IntelSyncSchedulesHandler) ListExecutions(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	var total int64
	h.db.Model(&model.IntelSyncExecution{}).Where("schedule_id = ?", id).Count(&total)

	var records []model.IntelSyncExecution
	h.db.Where("schedule_id = ?", id).
		Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&records)

	Success(c, gin.H{
		"items": records,
		"total": total,
		"page":  page,
	})
}
