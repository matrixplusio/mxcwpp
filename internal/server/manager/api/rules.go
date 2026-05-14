// Package api 提供 HTTP API 处理器
package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/service"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// RulesHandler 是规则管理 API 处理器
type RulesHandler struct {
	service *service.PolicyService
	db      *gorm.DB
	logger  *zap.Logger
}

// NewRulesHandler 创建规则处理器
func NewRulesHandler(db *gorm.DB, logger *zap.Logger) *RulesHandler {
	return &RulesHandler{
		service: service.NewPolicyService(db, logger),
		db:      db,
		logger:  logger,
	}
}

// ListRules 获取策略的规则列表
// GET /api/v1/policies/:policy_id/rules
func (h *RulesHandler) ListRules(c *gin.Context) {
	policyID := c.Param("policy_id")

	// 检查策略是否存在
	_, err := h.service.GetPolicy(policyID)
	if err != nil {
		if strings.Contains(err.Error(), "不存在") {
			NotFound(c, "策略不存在")
			return
		}
		h.logger.Error("查询策略失败", zap.Error(err))
		InternalError(c, "查询策略失败")
		return
	}

	rules, err := h.service.ListRules(policyID)
	if err != nil {
		h.logger.Error("查询规则列表失败", zap.Error(err))
		InternalError(c, "查询规则列表失败")
		return
	}

	SuccessPaginated(c, int64(len(rules)), rules)
}

// GetRule 获取规则详情
// GET /api/v1/rules/:rule_id
func (h *RulesHandler) GetRule(c *gin.Context) {
	ruleID := c.Param("rule_id")

	rule, err := h.service.GetRule(ruleID)
	if err != nil {
		if strings.Contains(err.Error(), "不存在") {
			NotFound(c, "规则不存在")
			return
		}
		h.logger.Error("查询规则失败", zap.Error(err))
		InternalError(c, "查询规则失败")
		return
	}

	Success(c, rule)
}

// CreateRuleRequest 创建规则请求
type CreateRuleRequest struct {
	RuleID      string            `json:"rule_id" binding:"required"`
	Category    string            `json:"category"`
	Title       string            `json:"title" binding:"required"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Enabled     *bool             `json:"enabled"` // 可选，默认为 true
	CheckConfig model.CheckConfig `json:"check_config"`
	FixConfig   model.FixConfig   `json:"fix_config"`
}

// CreateRule 创建规则
// POST /api/v1/policies/:policy_id/rules
func (h *RulesHandler) CreateRule(c *gin.Context) {
	policyID := c.Param("policy_id")

	// 检查策略是否存在
	_, err := h.service.GetPolicy(policyID)
	if err != nil {
		if strings.Contains(err.Error(), "不存在") {
			NotFound(c, "策略不存在")
			return
		}
		h.logger.Error("查询策略失败", zap.Error(err))
		InternalError(c, "查询策略失败")
		return
	}

	var req CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 检查规则 ID 是否已存在
	_, err = h.service.GetRule(req.RuleID)
	if err == nil {
		Conflict(c, "规则 ID 已存在")
		return
	}

	// 设置默认严重级别
	if req.Severity == "" {
		req.Severity = "medium"
	}

	// 设置默认启用状态
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &model.Rule{
		RuleID:      req.RuleID,
		PolicyID:    policyID,
		Category:    req.Category,
		Title:       req.Title,
		Description: req.Description,
		Severity:    req.Severity,
		Enabled:     enabled,
		CheckConfig: req.CheckConfig,
		FixConfig:   req.FixConfig,
	}

	if err := h.service.CreateRule(rule); err != nil {
		h.logger.Error("创建规则失败", zap.Error(err))
		InternalError(c, "创建规则失败")
		return
	}

	// 重新查询规则
	createdRule, _ := h.service.GetRule(req.RuleID)

	Created(c, createdRule)
}

// UpdateRuleRequest 更新规则请求
type UpdateRuleRequest struct {
	Category    string             `json:"category"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Severity    string             `json:"severity"`
	Enabled     *bool              `json:"enabled"` // 可选，更新启用状态
	CheckConfig *model.CheckConfig `json:"check_config"`
	FixConfig   *model.FixConfig   `json:"fix_config"`
}

// UpdateRule 更新规则
// PUT /api/v1/rules/:rule_id
func (h *RulesHandler) UpdateRule(c *gin.Context) {
	ruleID := c.Param("rule_id")

	// 检查规则是否存在
	rule, err := h.service.GetRule(ruleID)
	if err != nil {
		if strings.Contains(err.Error(), "不存在") {
			NotFound(c, "规则不存在")
			return
		}
		h.logger.Error("查询规则失败", zap.Error(err))
		InternalError(c, "查询规则失败")
		return
	}

	var req UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 更新字段
	if req.Category != "" {
		rule.Category = req.Category
	}
	if req.Title != "" {
		rule.Title = req.Title
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	if req.Severity != "" {
		rule.Severity = req.Severity
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.CheckConfig != nil {
		rule.CheckConfig = *req.CheckConfig
	}
	if req.FixConfig != nil {
		rule.FixConfig = *req.FixConfig
	}

	if err := h.service.UpdateRule(rule); err != nil {
		h.logger.Error("更新规则失败", zap.Error(err))
		InternalError(c, "更新规则失败")
		return
	}

	// 重新查询规则
	updatedRule, _ := h.service.GetRule(ruleID)

	Success(c, updatedRule)
}

// DeleteRule 删除规则
// DELETE /api/v1/rules/:rule_id
func (h *RulesHandler) DeleteRule(c *gin.Context) {
	ruleID := c.Param("rule_id")

	// 检查规则是否存在
	_, err := h.service.GetRule(ruleID)
	if err != nil {
		if strings.Contains(err.Error(), "不存在") {
			NotFound(c, "规则不存在")
			return
		}
		h.logger.Error("查询规则失败", zap.Error(err))
		InternalError(c, "查询规则失败")
		return
	}

	if err := h.service.DeleteRule(ruleID); err != nil {
		h.logger.Error("删除规则失败", zap.Error(err))
		InternalError(c, "删除规则失败")
		return
	}

	SuccessMessage(c, "规则已删除")
}
