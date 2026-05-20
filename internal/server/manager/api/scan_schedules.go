package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ScanSchedulesHandler 扫描计划 API 处理器
type ScanSchedulesHandler struct {
	db        *gorm.DB
	logger    *zap.Logger
	scheduler *biz.ScanScheduler
}

// NewScanSchedulesHandler 创建处理器
func NewScanSchedulesHandler(db *gorm.DB, logger *zap.Logger, scheduler *biz.ScanScheduler) *ScanSchedulesHandler {
	return &ScanSchedulesHandler{db: db, logger: logger, scheduler: scheduler}
}

// ListSchedules 扫描计划列表
func (h *ScanSchedulesHandler) ListSchedules(c *gin.Context) {
	var schedules []model.ScanSchedule
	if err := h.db.Order("created_at DESC").Find(&schedules).Error; err != nil {
		InternalError(c, "查询扫描计划失败")
		return
	}
	Success(c, schedules)
}

// CreateSchedule 创建扫描计划
func (h *ScanSchedulesHandler) CreateSchedule(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		ScanType string `json:"scanType" binding:"required"`
		CronExpr string `json:"cronExpr" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误: "+err.Error())
		return
	}

	schedule := &model.ScanSchedule{
		Name:      req.Name,
		ScanType:  req.ScanType,
		CronExpr:  req.CronExpr,
		Enabled:   true,
		CreatedBy: c.GetString("username"),
	}

	if err := h.scheduler.AddSchedule(schedule); err != nil {
		BadRequest(c, "创建扫描计划失败: "+err.Error())
		return
	}

	Success(c, schedule)
}

// UpdateSchedule 更新扫描计划
func (h *ScanSchedulesHandler) UpdateSchedule(c *gin.Context) {
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

// DeleteSchedule 删除扫描计划
func (h *ScanSchedulesHandler) DeleteSchedule(c *gin.Context) {
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

// ToggleSchedule 启用/禁用扫描计划
func (h *ScanSchedulesHandler) ToggleSchedule(c *gin.Context) {
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

// ListExecutions 查询扫描计划的执行历史
func (h *ScanSchedulesHandler) ListExecutions(c *gin.Context) {
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
	h.db.Model(&model.ScanScheduleExecution{}).Where("schedule_id = ?", id).Count(&total)

	var records []model.ScanScheduleExecution
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

// GetExecution 查询单次执行详情（含新增漏洞、受影响主机）
func (h *ScanSchedulesHandler) GetExecution(c *gin.Context) {
	execID, _ := strconv.ParseUint(c.Param("execId"), 10, 64)
	if execID == 0 {
		BadRequest(c, "无效的执行 ID")
		return
	}

	var exec model.ScanScheduleExecution
	if err := h.db.First(&exec, execID).Error; err != nil {
		NotFound(c, "执行记录不存在")
		return
	}

	// 关联的扫描计划名称
	var schedule model.ScanSchedule
	h.db.Select("name").First(&schedule, exec.ScheduleID)

	// 查本次执行时间窗口内新增的漏洞
	vulnPage, _ := strconv.Atoi(c.DefaultQuery("vulnPage", "1"))
	vulnPageSize, _ := strconv.Atoi(c.DefaultQuery("vulnPageSize", "20"))
	if vulnPage < 1 {
		vulnPage = 1
	}
	if vulnPageSize < 1 || vulnPageSize > 100 {
		vulnPageSize = 20
	}

	finishedAt := exec.FinishedAt
	if finishedAt == nil {
		// 执行中 — 用当前时间作为窗口结束
		now := model.Now()
		finishedAt = &now
	}

	var vulnTotal int64
	h.db.Model(&model.Vulnerability{}).
		Where("created_at >= ? AND created_at <= ?", exec.StartedAt, *finishedAt).
		Count(&vulnTotal)

	var vulns []model.Vulnerability
	h.db.Where("created_at >= ? AND created_at <= ?", exec.StartedAt, *finishedAt).
		Order("cvss_score DESC").
		Offset((vulnPage - 1) * vulnPageSize).
		Limit(vulnPageSize).
		Find(&vulns)

	// 查本次执行时间窗口内新增的主机-漏洞关联（受影响主机）
	type affectedHost struct {
		HostID    string `json:"hostId"`
		Hostname  string `json:"hostname"`
		IP        string `json:"ip"`
		VulnCount int64  `json:"vulnCount"`
	}
	var hosts []affectedHost
	h.db.Model(&model.HostVulnerability{}).
		Select("host_id, hostname, ip, COUNT(*) as vuln_count").
		Where("created_at >= ? AND created_at <= ?", exec.StartedAt, *finishedAt).
		Group("host_id, hostname, ip").
		Order("vuln_count DESC").
		Limit(100).
		Find(&hosts)

	Success(c, gin.H{
		"execution":    exec,
		"scheduleName": schedule.Name,
		"vulns": gin.H{
			"items": vulns,
			"total": vulnTotal,
			"page":  vulnPage,
		},
		"affectedHosts": hosts,
	})
}
