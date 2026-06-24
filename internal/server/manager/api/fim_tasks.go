package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// FIMTasksHandler FIM 任务管理处理器
type FIMTasksHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewFIMTasksHandler 创建 FIM 任务处理器
func NewFIMTasksHandler(db *gorm.DB, logger *zap.Logger) *FIMTasksHandler {
	return &FIMTasksHandler{db: db, logger: logger}
}

// CreateFIMTaskRequest 创建 FIM 任务请求
type CreateFIMTaskRequest struct {
	PolicyID     string             `json:"policy_id" binding:"required"`
	TargetType   string             `json:"target_type"`
	TargetConfig model.TargetConfig `json:"target_config"`
}

// ListFIMTasks 获取 FIM 任务列表
func (h *FIMTasksHandler) ListFIMTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	query := h.db.Model(&model.FIMTask{})

	// 筛选条件
	if policyID := c.Query("policy_id"); policyID != "" {
		query = query.Where("policy_id = ?", policyID)
	}
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询 FIM 任务总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var tasks []model.FIMTask
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&tasks).Error; err != nil {
		h.logger.Error("查询 FIM 任务列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	SuccessPaginated(c, total, tasks)
}

// GetFIMTask 获取单个 FIM 任务详情
func (h *FIMTasksHandler) GetFIMTask(c *gin.Context) {
	taskID := c.Param("id")

	var task model.FIMTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询 FIM 任务失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 查询主机状态
	var hostStatuses []model.FIMTaskHostStatus
	h.db.Where("task_id = ?", taskID).Find(&hostStatuses)

	Success(c, gin.H{
		"task":          task,
		"host_statuses": hostStatuses,
	})
}

// CreateFIMTask 创建 FIM 任务
func (h *FIMTasksHandler) CreateFIMTask(c *gin.Context) {
	var req CreateFIMTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 验证策略存在
	var policy model.FIMPolicy
	if err := h.db.Where("policy_id = ?", req.PolicyID).First(&policy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			BadRequest(c, "策略不存在")
			return
		}
		h.logger.Error("查询 FIM 策略失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	targetType := req.TargetType
	targetConfig := req.TargetConfig
	if targetType == "" {
		targetType = policy.TargetType
		targetConfig = policy.TargetConfig
	}

	task := model.FIMTask{
		TaskID:       uuid.New().String(),
		PolicyID:     req.PolicyID,
		Status:       "pending",
		TargetType:   targetType,
		TargetConfig: targetConfig,
		CreatedAt:    model.Now(),
	}

	if err := h.db.Create(&task).Error; err != nil {
		h.logger.Error("创建 FIM 任务失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	Created(c, task)
}

// RunFIMTask 执行 FIM 任务（标记为 running，实际调度由 AgentCenter 处理）
func (h *FIMTasksHandler) RunFIMTask(c *gin.Context) {
	taskID := c.Param("id")

	var task model.FIMTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询 FIM 任务失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	if task.Status != "pending" {
		BadRequest(c, "任务当前状态不允许执行")
		return
	}

	now := model.Now()
	if err := h.db.Model(&task).Updates(map[string]any{
		"status":      "running",
		"executed_at": now,
	}).Error; err != nil {
		h.logger.Error("更新 FIM 任务状态失败", zap.Error(err))
		InternalError(c, "执行失败")
		return
	}

	task.Status = "running"
	task.ExecutedAt = &now
	Success(c, task)
}
