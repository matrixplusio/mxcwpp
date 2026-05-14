package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// FIMPoliciesHandler FIM 策略管理处理器
type FIMPoliciesHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewFIMPoliciesHandler 创建 FIM 策略处理器
func NewFIMPoliciesHandler(db *gorm.DB, logger *zap.Logger) *FIMPoliciesHandler {
	return &FIMPoliciesHandler{db: db, logger: logger}
}

// CreateFIMPolicyRequest 创建 FIM 策略请求
type CreateFIMPolicyRequest struct {
	Name                 string             `json:"name" binding:"required"`
	Description          string             `json:"description"`
	WatchPaths           model.WatchPaths   `json:"watch_paths" binding:"required"`
	ExcludePaths         model.StringArray  `json:"exclude_paths"`
	CheckIntervalHours   int                `json:"check_interval_hours"`
	TargetType           string             `json:"target_type"`
	TargetConfig         model.TargetConfig `json:"target_config"`
	EscalationTimeoutMin *int               `json:"escalation_timeout_min"`
	Enabled              *bool              `json:"enabled"`
}

// ListFIMPolicies 获取 FIM 策略列表
func (h *FIMPoliciesHandler) ListFIMPolicies(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	query := h.db.Model(&model.FIMPolicy{})

	// 筛选条件
	if name := c.Query("name"); name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	if enabledStr := c.Query("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		query = query.Where("enabled = ?", enabled)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询 FIM 策略总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var policies []model.FIMPolicy
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&policies).Error; err != nil {
		h.logger.Error("查询 FIM 策略列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	SuccessPaginated(c, total, policies)
}

// GetFIMPolicy 获取单个 FIM 策略
func (h *FIMPoliciesHandler) GetFIMPolicy(c *gin.Context) {
	policyID := c.Param("id")

	var policy model.FIMPolicy
	if err := h.db.Where("policy_id = ?", policyID).First(&policy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略不存在")
			return
		}
		h.logger.Error("查询 FIM 策略失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, policy)
}

// CreateFIMPolicy 创建 FIM 策略
func (h *FIMPoliciesHandler) CreateFIMPolicy(c *gin.Context) {
	var req CreateFIMPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if len(req.WatchPaths) == 0 {
		BadRequest(c, "监控路径不能为空")
		return
	}

	checkInterval := req.CheckIntervalHours
	if checkInterval <= 0 {
		checkInterval = 24
	}

	targetType := req.TargetType
	if targetType == "" {
		targetType = "all"
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	escalationTimeout := 1440
	if req.EscalationTimeoutMin != nil && *req.EscalationTimeoutMin > 0 {
		escalationTimeout = *req.EscalationTimeoutMin
	}

	policy := model.FIMPolicy{
		PolicyID:             uuid.New().String(),
		Name:                 req.Name,
		Description:          req.Description,
		WatchPaths:           req.WatchPaths,
		ExcludePaths:         req.ExcludePaths,
		CheckIntervalHours:   checkInterval,
		TargetType:           targetType,
		TargetConfig:         req.TargetConfig,
		EscalationTimeoutMin: escalationTimeout,
		Enabled:              enabled,
		CreatedAt:            model.Now(),
		UpdatedAt:            model.Now(),
	}

	if err := h.db.Create(&policy).Error; err != nil {
		h.logger.Error("创建 FIM 策略失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	Created(c, policy)
}

// UpdateFIMPolicy 更新 FIM 策略
func (h *FIMPoliciesHandler) UpdateFIMPolicy(c *gin.Context) {
	policyID := c.Param("id")

	var policy model.FIMPolicy
	if err := h.db.Where("policy_id = ?", policyID).First(&policy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略不存在")
			return
		}
		h.logger.Error("查询 FIM 策略失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var req CreateFIMPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	updates := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
		"updated_at":  model.Now(),
	}

	if len(req.WatchPaths) > 0 {
		updates["watch_paths"] = req.WatchPaths
	}
	if req.ExcludePaths != nil {
		updates["exclude_paths"] = req.ExcludePaths
	}
	if req.CheckIntervalHours > 0 {
		updates["check_interval_hours"] = req.CheckIntervalHours
	}
	if req.TargetType != "" {
		updates["target_type"] = req.TargetType
		updates["target_config"] = req.TargetConfig
	}
	if req.EscalationTimeoutMin != nil && *req.EscalationTimeoutMin > 0 {
		updates["escalation_timeout_min"] = *req.EscalationTimeoutMin
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if err := h.db.Model(&policy).Updates(updates).Error; err != nil {
		h.logger.Error("更新 FIM 策略失败", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	h.db.Where("policy_id = ?", policyID).First(&policy)
	Success(c, policy)
}

// DeleteFIMPolicy 删除 FIM 策略
func (h *FIMPoliciesHandler) DeleteFIMPolicy(c *gin.Context) {
	policyID := c.Param("id")

	result := h.db.Where("policy_id = ?", policyID).Delete(&model.FIMPolicy{})
	if result.Error != nil {
		h.logger.Error("删除 FIM 策略失败", zap.Error(result.Error))
		InternalError(c, "删除失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "策略不存在")
		return
	}

	Success(c, gin.H{"message": "删除成功"})
}
