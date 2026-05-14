package api

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeBaselineRulesHandler 容器基线规则管理 API Handler
type KubeBaselineRulesHandler struct {
	db         *gorm.DB
	logger     *zap.Logger
	checker    *biz.KubeBaselineChecker
	ruleEngine *biz.KubeRuleEngine
}

// NewKubeBaselineRulesHandler 创建基线规则管理 Handler
func NewKubeBaselineRulesHandler(db *gorm.DB, logger *zap.Logger, checker *biz.KubeBaselineChecker, ruleEngine *biz.KubeRuleEngine) *KubeBaselineRulesHandler {
	return &KubeBaselineRulesHandler{db: db, logger: logger, checker: checker, ruleEngine: ruleEngine}
}

// ListRules 基线规则列表
// GET /api/v1/kube/baseline-rules
func (h *KubeBaselineRulesHandler) ListRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.KubeBaselineRule{})

	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		pattern := "%" + keyword + "%"
		query = query.Where("check_id LIKE ? OR check_name LIKE ? OR description LIKE ?", pattern, pattern, pattern)
	}
	if category := c.Query("category"); category != "" {
		query = query.Where("category = ?", category)
	}
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if enabled := c.Query("enabled"); enabled != "" {
		query = query.Where("enabled = ?", enabled == "true")
	}
	if builtin := c.Query("builtin"); builtin != "" {
		query = query.Where("builtin = ?", builtin == "true")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询基线规则总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var rules []model.KubeBaselineRule
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("check_id ASC").Find(&rules).Error; err != nil {
		h.logger.Error("查询基线规则列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 获取已注册的检查函数 ID 列表
	registeredIDs := make(map[string]bool)
	for _, id := range h.checker.GetRegisteredCheckIDs() {
		registeredIDs[id] = true
	}

	type ruleWithMeta struct {
		model.KubeBaselineRule
		HasCheckFunc   bool `json:"hasCheckFunc"`
		HasCheckConfig bool `json:"hasCheckConfig"`
	}

	items := make([]ruleWithMeta, len(rules))
	for i, r := range rules {
		items[i] = ruleWithMeta{
			KubeBaselineRule: r,
			HasCheckFunc:     registeredIDs[r.CheckID],
			HasCheckConfig:   r.CheckConfig != nil,
		}
	}

	// 统计信息
	var totalRules, enabledCount, builtinCount int64
	h.db.Model(&model.KubeBaselineRule{}).Count(&totalRules)
	h.db.Model(&model.KubeBaselineRule{}).Where("enabled = ?", true).Count(&enabledCount)
	h.db.Model(&model.KubeBaselineRule{}).Where("builtin = ?", true).Count(&builtinCount)

	c.JSON(200, gin.H{
		"code": 0,
		"data": gin.H{
			"total": total,
			"items": items,
			"stats": gin.H{
				"totalRules": totalRules,
				"enabled":    enabledCount,
				"disabled":   totalRules - enabledCount,
				"builtin":    builtinCount,
			},
		},
	})
}

// GetRule 获取单条基线规则
// GET /api/v1/kube/baseline-rules/:id
func (h *KubeBaselineRulesHandler) GetRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.KubeBaselineRule
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "规则不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	Success(c, rule)
}

type createKubeBaselineRuleRequest struct {
	CheckID     string                 `json:"checkId" binding:"required"`
	CheckName   string                 `json:"checkName" binding:"required"`
	Category    string                 `json:"category" binding:"required"`
	Severity    string                 `json:"severity" binding:"required"`
	Description string                 `json:"description"`
	Remediation string                 `json:"remediation"`
	Benchmark   string                 `json:"benchmark"`
	CheckConfig *model.KubeCheckConfig `json:"checkConfig"`
}

// CreateRule 新增基线规则
// POST /api/v1/kube/baseline-rules
func (h *KubeBaselineRulesHandler) CreateRule(c *gin.Context) {
	var req createKubeBaselineRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	// 验证 CEL 表达式
	if req.CheckConfig != nil && req.CheckConfig.Expression != "" && h.ruleEngine != nil {
		if err := h.ruleEngine.CompileExpression(req.CheckConfig.Expression); err != nil {
			BadRequest(c, "CEL 表达式无效")
			return
		}
	}

	rule := &model.KubeBaselineRule{
		CheckID:     req.CheckID,
		CheckName:   req.CheckName,
		Category:    req.Category,
		Severity:    req.Severity,
		Description: req.Description,
		Remediation: req.Remediation,
		Benchmark:   req.Benchmark,
		CheckConfig: req.CheckConfig,
		Enabled:     true,
		Builtin:     false,
	}

	if err := h.db.Create(rule).Error; err != nil {
		if strings.Contains(err.Error(), "Duplicate") || strings.Contains(err.Error(), "UNIQUE") {
			BadRequest(c, "CheckID 已存在")
			return
		}
		h.logger.Error("创建基线规则失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	Created(c, rule)
}

type updateKubeBaselineRuleRequest struct {
	CheckName   *string                `json:"checkName"`
	Category    *string                `json:"category"`
	Severity    *string                `json:"severity"`
	Description *string                `json:"description"`
	Remediation *string                `json:"remediation"`
	Benchmark   *string                `json:"benchmark"`
	Enabled     *bool                  `json:"enabled"`
	CheckConfig *model.KubeCheckConfig `json:"checkConfig"`
}

// UpdateRule 编辑基线规则
// PUT /api/v1/kube/baseline-rules/:id
func (h *KubeBaselineRulesHandler) UpdateRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.KubeBaselineRule
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "规则不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	var req updateKubeBaselineRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	// 验证 CEL 表达式
	if req.CheckConfig != nil && req.CheckConfig.Expression != "" && h.ruleEngine != nil {
		if err := h.ruleEngine.CompileExpression(req.CheckConfig.Expression); err != nil {
			BadRequest(c, "CEL 表达式无效")
			return
		}
	}

	updates := map[string]any{}
	if req.CheckName != nil {
		updates["check_name"] = *req.CheckName
	}
	if req.Category != nil {
		updates["category"] = *req.Category
	}
	if req.Severity != nil {
		updates["severity"] = *req.Severity
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Remediation != nil {
		updates["remediation"] = *req.Remediation
	}
	if req.Benchmark != nil {
		updates["benchmark"] = *req.Benchmark
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.CheckConfig != nil {
		updates["check_config"] = req.CheckConfig
	}

	if len(updates) == 0 {
		BadRequest(c, "没有需要更新的字段")
		return
	}

	if err := h.db.Model(&rule).Updates(updates).Error; err != nil {
		h.logger.Error("更新基线规则失败", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	h.db.First(&rule, id)
	Success(c, rule)
}

// DeleteRule 删除基线规则
// DELETE /api/v1/kube/baseline-rules/:id
func (h *KubeBaselineRulesHandler) DeleteRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.KubeBaselineRule
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "规则不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	if rule.Builtin {
		BadRequest(c, "内置规则不允许删除")
		return
	}

	if err := h.db.Delete(&rule).Error; err != nil {
		h.logger.Error("删除基线规则失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	SuccessMessage(c, "规则已删除")
}

// ToggleRule 启用/禁用切换
// PUT /api/v1/kube/baseline-rules/:id/toggle
func (h *KubeBaselineRulesHandler) ToggleRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.KubeBaselineRule
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "规则不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	newEnabled := !rule.Enabled
	if err := h.db.Model(&rule).Update("enabled", newEnabled).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}

	status := "已启用"
	if !newEnabled {
		status = "已禁用"
	}
	SuccessMessage(c, "规则"+status)
}

// ValidateExpression 验证 CEL 表达式
// POST /api/v1/kube/baseline-rules/validate-expression
func (h *KubeBaselineRulesHandler) ValidateExpression(c *gin.Context) {
	var req struct {
		Expression string `json:"expression" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	if h.ruleEngine == nil {
		InternalError(c, "CEL 引擎未初始化")
		return
	}

	if err := h.ruleEngine.CompileExpression(req.Expression); err != nil {
		Success(c, gin.H{"valid": false, "error": err.Error()})
		return
	}
	Success(c, gin.H{"valid": true})
}

// GetExpressionTemplates 获取 CEL 表达式模板列表
// GET /api/v1/kube/baseline-rules/expression-templates
func (h *KubeBaselineRulesHandler) GetExpressionTemplates(c *gin.Context) {
	var templates []model.KubeExpressionTemplate
	if err := h.db.Order("id ASC").Find(&templates).Error; err != nil {
		h.logger.Error("查询表达式模板失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	Success(c, templates)
}

type createExpressionTemplateRequest struct {
	Name         string `json:"name" binding:"required"`
	Description  string `json:"description"`
	ResourceType string `json:"resourceType" binding:"required"`
	APIGroup     string `json:"apiGroup"`
	Namespace    string `json:"namespace"`
	Expression   string `json:"expression" binding:"required"`
	MatchPolicy  string `json:"matchPolicy"`
}

// CreateExpressionTemplate 新增表达式模板
// POST /api/v1/kube/baseline-rules/expression-templates
func (h *KubeBaselineRulesHandler) CreateExpressionTemplate(c *gin.Context) {
	var req createExpressionTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	// 验证 CEL 表达式
	if h.ruleEngine != nil {
		if err := h.ruleEngine.CompileExpression(req.Expression); err != nil {
			BadRequest(c, "CEL 表达式无效")
			return
		}
	}

	matchPolicy := req.MatchPolicy
	if matchPolicy == "" {
		matchPolicy = "any_match_fail"
	}

	tmpl := &model.KubeExpressionTemplate{
		Name:         req.Name,
		Description:  req.Description,
		ResourceType: req.ResourceType,
		APIGroup:     req.APIGroup,
		Namespace:    req.Namespace,
		Expression:   req.Expression,
		MatchPolicy:  matchPolicy,
		Builtin:      false,
	}

	if err := h.db.Create(tmpl).Error; err != nil {
		h.logger.Error("创建表达式模板失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	Created(c, tmpl)
}

type updateExpressionTemplateRequest struct {
	Name         *string `json:"name"`
	Description  *string `json:"description"`
	ResourceType *string `json:"resourceType"`
	APIGroup     *string `json:"apiGroup"`
	Namespace    *string `json:"namespace"`
	Expression   *string `json:"expression"`
	MatchPolicy  *string `json:"matchPolicy"`
}

// UpdateExpressionTemplate 编辑表达式模板
// PUT /api/v1/kube/baseline-rules/expression-templates/:id
func (h *KubeBaselineRulesHandler) UpdateExpressionTemplate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的模板 ID")
		return
	}

	var tmpl model.KubeExpressionTemplate
	if err := h.db.First(&tmpl, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "模板不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	var req updateExpressionTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	// 验证 CEL 表达式
	if req.Expression != nil && *req.Expression != "" && h.ruleEngine != nil {
		if err := h.ruleEngine.CompileExpression(*req.Expression); err != nil {
			BadRequest(c, "CEL 表达式无效")
			return
		}
	}

	updates := map[string]any{}
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.ResourceType != nil {
		updates["resource_type"] = *req.ResourceType
	}
	if req.APIGroup != nil {
		updates["api_group"] = *req.APIGroup
	}
	if req.Namespace != nil {
		updates["namespace"] = *req.Namespace
	}
	if req.Expression != nil {
		updates["expression"] = *req.Expression
	}
	if req.MatchPolicy != nil {
		updates["match_policy"] = *req.MatchPolicy
	}

	if len(updates) == 0 {
		BadRequest(c, "没有需要更新的字段")
		return
	}

	if err := h.db.Model(&tmpl).Updates(updates).Error; err != nil {
		h.logger.Error("更新表达式模板失败", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	h.db.First(&tmpl, id)
	Success(c, tmpl)
}

// DeleteExpressionTemplate 删除表达式模板
// DELETE /api/v1/kube/baseline-rules/expression-templates/:id
func (h *KubeBaselineRulesHandler) DeleteExpressionTemplate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的模板 ID")
		return
	}

	var tmpl model.KubeExpressionTemplate
	if err := h.db.First(&tmpl, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "模板不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	if err := h.db.Delete(&tmpl).Error; err != nil {
		h.logger.Error("删除表达式模板失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	SuccessMessage(c, "模板已删除")
}

// ExportRules 导出规则为 JSON
// GET /api/v1/kube/baseline-rules/export
func (h *KubeBaselineRulesHandler) ExportRules(c *gin.Context) {
	var rules []model.KubeBaselineRule
	if err := h.db.Order("check_id ASC").Find(&rules).Error; err != nil {
		h.logger.Error("导出基线规则失败", zap.Error(err))
		InternalError(c, "导出失败")
		return
	}

	type exportRule struct {
		CheckID     string                 `json:"checkId"`
		CheckName   string                 `json:"checkName"`
		Category    string                 `json:"category"`
		Severity    string                 `json:"severity"`
		Description string                 `json:"description"`
		Remediation string                 `json:"remediation"`
		Benchmark   string                 `json:"benchmark"`
		Enabled     bool                   `json:"enabled"`
		CheckConfig *model.KubeCheckConfig `json:"checkConfig,omitempty"`
	}

	exported := make([]exportRule, len(rules))
	for i, r := range rules {
		exported[i] = exportRule{
			CheckID:     r.CheckID,
			CheckName:   r.CheckName,
			Category:    r.Category,
			Severity:    r.Severity,
			Description: r.Description,
			Remediation: r.Remediation,
			Benchmark:   r.Benchmark,
			Enabled:     r.Enabled,
			CheckConfig: r.CheckConfig,
		}
	}

	data, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		InternalError(c, "序列化失败")
		return
	}

	c.Header("Content-Disposition", "attachment; filename=kube_baseline_rules.json")
	c.Data(200, "application/json", data)
}

// ImportRules 导入规则
// POST /api/v1/kube/baseline-rules/import
func (h *KubeBaselineRulesHandler) ImportRules(c *gin.Context) {
	mode := c.DefaultQuery("mode", "skip") // skip 或 update

	var imported []struct {
		CheckID     string                 `json:"checkId"`
		CheckName   string                 `json:"checkName"`
		Category    string                 `json:"category"`
		Severity    string                 `json:"severity"`
		Description string                 `json:"description"`
		Remediation string                 `json:"remediation"`
		Benchmark   string                 `json:"benchmark"`
		Enabled     *bool                  `json:"enabled"`
		CheckConfig *model.KubeCheckConfig `json:"checkConfig"`
	}

	if err := c.ShouldBindJSON(&imported); err != nil {
		BadRequest(c, "JSON 格式错误")
		return
	}

	if len(imported) == 0 {
		BadRequest(c, "导入数据为空")
		return
	}

	var created, updated, skipped int

	for _, item := range imported {
		if item.CheckID == "" || item.CheckName == "" {
			skipped++
			continue
		}

		var existing model.KubeBaselineRule
		err := h.db.Where("check_id = ?", item.CheckID).First(&existing).Error

		if err == gorm.ErrRecordNotFound {
			enabled := true
			if item.Enabled != nil {
				enabled = *item.Enabled
			}
			rule := model.KubeBaselineRule{
				CheckID:     item.CheckID,
				CheckName:   item.CheckName,
				Category:    item.Category,
				Severity:    item.Severity,
				Description: item.Description,
				Remediation: item.Remediation,
				Benchmark:   item.Benchmark,
				CheckConfig: item.CheckConfig,
				Enabled:     enabled,
				Builtin:     false,
			}
			if err := h.db.Create(&rule).Error; err != nil {
				h.logger.Error("导入规则创建失败", zap.String("check_id", item.CheckID), zap.Error(err))
				skipped++
				continue
			}
			created++
		} else if err == nil {
			if mode == "update" {
				updates := map[string]any{
					"check_name":  item.CheckName,
					"category":    item.Category,
					"severity":    item.Severity,
					"description": item.Description,
					"remediation": item.Remediation,
					"benchmark":   item.Benchmark,
				}
				if item.Enabled != nil {
					updates["enabled"] = *item.Enabled
				}
				if item.CheckConfig != nil {
					updates["check_config"] = item.CheckConfig
				}
				h.db.Model(&existing).Updates(updates)
				updated++
			} else {
				skipped++
			}
		} else {
			h.logger.Error("导入规则查询失败", zap.String("check_id", item.CheckID), zap.Error(err))
			skipped++
		}
	}

	Success(c, gin.H{
		"total":   len(imported),
		"created": created,
		"updated": updated,
		"skipped": skipped,
	})
}
