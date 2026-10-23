package api

import (
	"errors"
	"regexp"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/scheduler"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ScheduledJobsHandler 后台定时任务的排期查看、修改与立即执行。
type ScheduledJobsHandler struct {
	logger *zap.Logger
}

// NewScheduledJobsHandler 构造 handler。
func NewScheduledJobsHandler(logger *zap.Logger) *ScheduledJobsHandler {
	return &ScheduledJobsHandler{logger: logger}
}

var scheduledJobKeyPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// runner 取全局调度器；未初始化（进程不是以 manager 身份完整启动）时回 503。
func (h *ScheduledJobsHandler) runner(c *gin.Context) *scheduler.JobRunner {
	r := scheduler.Jobs()
	if r == nil {
		ServiceUnavailable(c, "定时任务调度器未启动", nil)
	}
	return r
}

// List 返回全部任务的排期与最近一次执行情况。
//
// GET /api/v1/system-config/scheduled-jobs
func (h *ScheduledJobsHandler) List(c *gin.Context) {
	r := h.runner(c)
	if r == nil {
		return
	}
	items, err := r.List()
	if err != nil {
		h.logger.Error("查询定时任务失败", zap.Error(err))
		InternalError(c, "查询定时任务失败")
		return
	}
	Success(c, gin.H{"total": len(items), "items": items, "intervals": model.ScheduledJobIntervals})
}

// UpdateScheduledJobRequest 排期修改请求。三项都用指针：漏传不能被当成 0 点、或被当成停用。
type UpdateScheduledJobRequest struct {
	IntervalHours *int  `json:"intervalHours" binding:"required"`
	StartHour     *int  `json:"startHour" binding:"required"`
	Enabled       *bool `json:"enabled" binding:"required"`
}

// Update 修改一个任务的排期。
//
// PUT /api/v1/system-config/scheduled-jobs/:key
func (h *ScheduledJobsHandler) Update(c *gin.Context) {
	key := c.Param("key")
	if !scheduledJobKeyPattern.MatchString(key) {
		BadRequest(c, "无效的任务标识")
		return
	}
	var req UpdateScheduledJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "必须指定执行间隔、开始时刻与是否启用")
		return
	}
	r := h.runner(c)
	if r == nil {
		return
	}
	err := r.Update(key, scheduler.JobSchedule{
		IntervalHours: *req.IntervalHours, StartHour: *req.StartHour, Enabled: *req.Enabled,
	}, actorOf(c))
	switch {
	case errors.Is(err, scheduler.ErrJobNotFound):
		NotFound(c, "任务不存在")
	case err != nil:
		BadRequest(c, err.Error())
	default:
		Success(c, gin.H{"jobKey": key})
	}
}

// RunNow 立即执行一轮。
//
// POST /api/v1/system-config/scheduled-jobs/:key/run
func (h *ScheduledJobsHandler) RunNow(c *gin.Context) {
	key := c.Param("key")
	if !scheduledJobKeyPattern.MatchString(key) {
		BadRequest(c, "无效的任务标识")
		return
	}
	r := h.runner(c)
	if r == nil {
		return
	}
	err := r.RunNow(key, actorOf(c))
	switch {
	case errors.Is(err, scheduler.ErrJobNotFound):
		NotFound(c, "任务不存在")
	case errors.Is(err, scheduler.ErrJobRunning), errors.Is(err, scheduler.ErrJobExternal):
		Conflict(c, err.Error())
	case err != nil:
		h.logger.Error("立即执行定时任务失败", zap.String("job", key), zap.Error(err))
		InternalError(c, "执行失败")
	default:
		Success(c, gin.H{"jobKey": key})
	}
}
