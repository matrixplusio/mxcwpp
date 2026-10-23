package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RemediationPoliciesHandler 修复策略 API 处理器
type RemediationPoliciesHandler struct {
	db       *gorm.DB
	logger   *zap.Logger
	executor *biz.PolicyExecutor
}

// NewRemediationPoliciesHandler 创建处理器
func NewRemediationPoliciesHandler(db *gorm.DB, logger *zap.Logger, remExecutor *biz.RemediationExecutor) *RemediationPoliciesHandler {
	return &RemediationPoliciesHandler{
		db:       db,
		logger:   logger,
		executor: biz.NewPolicyExecutor(db, logger, remExecutor),
	}
}

// ListPolicies 策略列表
func (h *RemediationPoliciesHandler) ListPolicies(c *gin.Context) {
	var policies []model.RemediationPolicy
	if err := h.db.Order("created_at DESC").Find(&policies).Error; err != nil {
		InternalError(c, "查询修复策略失败")
		return
	}
	Success(c, policies)
}

// CreatePolicy 创建修复策略
func (h *RemediationPoliciesHandler) CreatePolicy(c *gin.Context) {
	var policy model.RemediationPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		BadRequest(c, "参数错误: "+err.Error())
		return
	}

	policy.CreatedBy = c.GetString("username")
	if err := h.db.Create(&policy).Error; err != nil {
		InternalError(c, "创建修复策略失败")
		return
	}

	Success(c, policy)
}

// GetPolicy 策略详情
func (h *RemediationPoliciesHandler) GetPolicy(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	var policy model.RemediationPolicy
	if err := h.db.First(&policy, id).Error; err != nil {
		NotFound(c, "修复策略不存在")
		return
	}

	Success(c, policy)
}

// UpdatePolicy 更新修复策略
func (h *RemediationPoliciesHandler) UpdatePolicy(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	var updates map[string]any
	if err := c.ShouldBindJSON(&updates); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	if err := h.db.Model(&model.RemediationPolicy{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}

	SuccessMessage(c, "更新成功")
}

// DeletePolicy 删除修复策略
func (h *RemediationPoliciesHandler) DeletePolicy(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	if err := h.db.Delete(&model.RemediationPolicy{}, id).Error; err != nil {
		InternalError(c, "删除失败")
		return
	}

	SuccessMessage(c, "删除成功")
}

// ExecutePolicy 执行修复策略
func (h *RemediationPoliciesHandler) ExecutePolicy(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	if err := h.executor.Execute(uint(id), c.GetString("username")); err != nil {
		InternalError(c, "执行策略失败: "+err.Error())
		return
	}

	SuccessMessage(c, "策略执行已启动")
}

// PreviewPolicy 预览策略影响范围
func (h *RemediationPoliciesHandler) PreviewPolicy(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	preview, err := h.executor.Preview(uint(id))
	if err != nil {
		InternalError(c, "预览失败: "+err.Error())
		return
	}

	Success(c, preview)
}

// ListExecutions 查询修复策略的执行历史
func (h *RemediationPoliciesHandler) ListExecutions(c *gin.Context) {
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
	h.db.Model(&model.RemediationPolicyExecution{}).Where("policy_id = ?", id).Count(&total)

	var records []model.RemediationPolicyExecution
	h.db.Where("policy_id = ?", id).
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
