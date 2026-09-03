// Package api 提供 HTTP API 处理器
package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PolicyGroupsHandler 是策略组管理 API 处理器
type PolicyGroupsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewPolicyGroupsHandler 创建策略组处理器
func NewPolicyGroupsHandler(db *gorm.DB, logger *zap.Logger) *PolicyGroupsHandler {
	return &PolicyGroupsHandler{
		db:     db,
		logger: logger,
	}
}

// ListPolicyGroups 获取策略组列表
// GET /api/v1/policy-groups
func (h *PolicyGroupsHandler) ListPolicyGroups(c *gin.Context) {
	var groups []model.PolicyGroup
	query := h.db.Model(&model.PolicyGroup{}).Order("sort_order ASC, created_at ASC")

	// 是否加载关联的策略
	if c.Query("with_policies") == "true" {
		query = query.Preload("Policies")
	}

	if err := query.Find(&groups).Error; err != nil {
		h.logger.Error("查询策略组列表失败", zap.Error(err))
		InternalError(c, "查询策略组列表失败")
		return
	}

	// 为每个策略组计算统计信息
	type GroupWithStats struct {
		model.PolicyGroup
		PolicyCount int     `json:"policy_count"`
		RuleCount   int     `json:"rule_count"`
		PassRate    float64 `json:"pass_rate"`
		HostCount   int     `json:"host_count"`
	}

	result := make([]GroupWithStats, len(groups))
	for i, group := range groups {
		result[i] = GroupWithStats{PolicyGroup: group}

		// 获取策略数量
		var policyCount int64
		h.db.Model(&model.Policy{}).Where("group_id = ?", group.ID).Count(&policyCount)
		result[i].PolicyCount = int(policyCount)

		// 获取规则数量
		var ruleCount int64
		h.db.Model(&model.Rule{}).
			Joins("JOIN policies ON rules.policy_id = policies.id").
			Where("policies.group_id = ?", group.ID).
			Count(&ruleCount)
		result[i].RuleCount = int(ruleCount)

		// 获取通过率和主机数（基于最近检查结果）
		var totalResults, passResults int64
		h.db.Model(&model.ScanResult{}).
			Joins("JOIN policies ON scan_results.policy_id = policies.id").
			Where("policies.group_id = ?", group.ID).
			Count(&totalResults)
		h.db.Model(&model.ScanResult{}).
			Joins("JOIN policies ON scan_results.policy_id = policies.id").
			Where("policies.group_id = ? AND scan_results.status = ?", group.ID, model.ResultStatusPass).
			Count(&passResults)

		if totalResults > 0 {
			result[i].PassRate = float64(passResults) / float64(totalResults) * 100
		}

		// 获取检查的主机数
		var hostCount int64
		h.db.Model(&model.ScanResult{}).
			Select("COUNT(DISTINCT host_id)").
			Joins("JOIN policies ON scan_results.policy_id = policies.id").
			Where("policies.group_id = ?", group.ID).
			Count(&hostCount)
		result[i].HostCount = int(hostCount)
	}

	SuccessPaginated(c, int64(len(result)), result)
}

// GetPolicyGroup 获取策略组详情
// GET /api/v1/policy-groups/:id
func (h *PolicyGroupsHandler) GetPolicyGroup(c *gin.Context) {
	id := c.Param("id")

	var group model.PolicyGroup
	query := h.db.Where("id = ?", id)

	// 是否加载关联的策略
	if c.Query("with_policies") == "true" {
		query = query.Preload("Policies").Preload("Policies.Rules")
	}

	if err := query.First(&group).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略组不存在")
			return
		}
		h.logger.Error("查询策略组失败", zap.Error(err))
		InternalError(c, "查询策略组失败")
		return
	}

	Success(c, group)
}

// CreatePolicyGroupRequest 创建策略组请求
type CreatePolicyGroupRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   int    `json:"sort_order"`
	Enabled     *bool  `json:"enabled"`
}

// CreatePolicyGroup 创建策略组
// POST /api/v1/policy-groups
func (h *PolicyGroupsHandler) CreatePolicyGroup(c *gin.Context) {
	var req CreatePolicyGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 生成 ID
	id := req.ID
	if id == "" {
		id = uuid.New().String()
	}

	// 检查 ID 是否已存在
	var count int64
	h.db.Model(&model.PolicyGroup{}).Where("id = ?", id).Count(&count)
	if count > 0 {
		Conflict(c, "策略组 ID 已存在")
		return
	}

	// 设置默认值
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	group := &model.PolicyGroup{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Icon:        req.Icon,
		Color:       req.Color,
		SortOrder:   req.SortOrder,
		Enabled:     enabled,
	}

	if err := h.db.Create(group).Error; err != nil {
		h.logger.Error("创建策略组失败", zap.Error(err))
		InternalError(c, "创建策略组失败")
		return
	}

	h.logger.Info("策略组已创建", zap.String("group_id", group.ID))

	Created(c, group)
}

// UpdatePolicyGroupRequest 更新策略组请求
type UpdatePolicyGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   *int   `json:"sort_order"`
	Enabled     *bool  `json:"enabled"`
}

// UpdatePolicyGroup 更新策略组
// PUT /api/v1/policy-groups/:id
func (h *PolicyGroupsHandler) UpdatePolicyGroup(c *gin.Context) {
	id := c.Param("id")

	var group model.PolicyGroup
	if err := h.db.Where("id = ?", id).First(&group).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略组不存在")
			return
		}
		h.logger.Error("查询策略组失败", zap.Error(err))
		InternalError(c, "查询策略组失败")
		return
	}

	var req UpdatePolicyGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 更新字段
	updates := make(map[string]interface{})
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Icon != "" {
		updates["icon"] = req.Icon
	}
	if req.Color != "" {
		updates["color"] = req.Color
	}
	if req.SortOrder != nil {
		updates["sort_order"] = *req.SortOrder
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	updates["updated_at"] = time.Now()

	if err := h.db.Model(&group).Updates(updates).Error; err != nil {
		h.logger.Error("更新策略组失败", zap.Error(err))
		InternalError(c, "更新策略组失败")
		return
	}

	// 重新查询更新后的数据
	h.db.Where("id = ?", id).First(&group)

	h.logger.Info("策略组已更新", zap.String("group_id", id))

	Success(c, group)
}

// DeletePolicyGroup 删除策略组
// DELETE /api/v1/policy-groups/:id
func (h *PolicyGroupsHandler) DeletePolicyGroup(c *gin.Context) {
	id := c.Param("id")

	var group model.PolicyGroup
	if err := h.db.Where("id = ?", id).First(&group).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略组不存在")
			return
		}
		h.logger.Error("查询策略组失败", zap.Error(err))
		InternalError(c, "查询策略组失败")
		return
	}

	// 检查是否有关联的策略
	var policyCount int64
	h.db.Model(&model.Policy{}).Where("group_id = ?", id).Count(&policyCount)
	if policyCount > 0 {
		Conflict(c, "策略组下存在策略，无法删除")
		return
	}

	if err := h.db.Delete(&group).Error; err != nil {
		h.logger.Error("删除策略组失败", zap.Error(err))
		InternalError(c, "删除策略组失败")
		return
	}

	h.logger.Info("策略组已删除", zap.String("group_id", id))

	SuccessMessage(c, "策略组已删除")
}

// GetPolicyGroupStatistics 获取策略组统计信息
// GET /api/v1/policy-groups/:id/statistics
func (h *PolicyGroupsHandler) GetPolicyGroupStatistics(c *gin.Context) {
	id := c.Param("id")

	var group model.PolicyGroup
	if err := h.db.Where("id = ?", id).First(&group).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略组不存在")
			return
		}
		h.logger.Error("查询策略组失败", zap.Error(err))
		InternalError(c, "查询策略组失败")
		return
	}

	// 获取策略列表
	var policies []model.Policy
	h.db.Where("group_id = ?", id).Find(&policies)

	// 获取规则数量
	var ruleCount int64
	h.db.Model(&model.Rule{}).
		Joins("JOIN policies ON rules.policy_id = policies.id").
		Where("policies.group_id = ?", id).
		Count(&ruleCount)

	// 获取检查结果统计
	var totalResults, passResults, failResults int64
	h.db.Model(&model.ScanResult{}).
		Joins("JOIN policies ON scan_results.policy_id = policies.id").
		Where("policies.group_id = ?", id).
		Count(&totalResults)
	h.db.Model(&model.ScanResult{}).
		Joins("JOIN policies ON scan_results.policy_id = policies.id").
		Where("policies.group_id = ? AND scan_results.status = ?", id, model.ResultStatusPass).
		Count(&passResults)
	h.db.Model(&model.ScanResult{}).
		Joins("JOIN policies ON scan_results.policy_id = policies.id").
		Where("policies.group_id = ? AND scan_results.status = ?", id, model.ResultStatusFail).
		Count(&failResults)

	// 计算通过率
	var passRate float64
	if totalResults > 0 {
		passRate = float64(passResults) / float64(totalResults) * 100
	}

	// 获取检查的主机数
	var hostCount int64
	h.db.Model(&model.ScanResult{}).
		Select("COUNT(DISTINCT host_id)").
		Joins("JOIN policies ON scan_results.policy_id = policies.id").
		Where("policies.group_id = ?", id).
		Count(&hostCount)

	// 获取最近检查时间
	var lastCheckTime *model.LocalTime
	var lastResult model.ScanResult
	if err := h.db.Model(&model.ScanResult{}).
		Joins("JOIN policies ON scan_results.policy_id = policies.id").
		Where("policies.group_id = ?", id).
		Order("checked_at DESC").
		First(&lastResult).Error; err == nil {
		lastCheckTime = &lastResult.CheckedAt
	}

	Success(c, gin.H{
		"group_id":        id,
		"policy_count":    len(policies),
		"rule_count":      ruleCount,
		"host_count":      hostCount,
		"pass_rate":       passRate,
		"pass_count":      passResults,
		"fail_count":      failResults,
		"risk_count":      failResults,
		"last_check_time": lastCheckTime,
	})
}
