package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// DetectionRulesHandler 检测规则管理 API 处理器
type DetectionRulesHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewDetectionRulesHandler 创建检测规则处理器
func NewDetectionRulesHandler(db *gorm.DB, logger *zap.Logger) *DetectionRulesHandler {
	return &DetectionRulesHandler{db: db, logger: logger}
}

// ListRules 获取检测规则列表
// GET /api/v1/detection-rules
func (h *DetectionRulesHandler) ListRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.DetectionRule{})

	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		pattern := "%" + keyword + "%"
		query = query.Where("name LIKE ? OR description LIKE ? OR category LIKE ? OR mitre_id LIKE ?",
			pattern, pattern, pattern, pattern)
	}
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if category := c.Query("category"); category != "" {
		query = query.Where("category = ?", category)
	}
	if enabled := c.Query("enabled"); enabled != "" {
		query = query.Where("enabled = ?", enabled == "true")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询检测规则总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var rules []model.DetectionRule
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&rules).Error; err != nil {
		h.logger.Error("查询检测规则列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	SuccessPaginated(c, total, rules)
}

// GetRule 获取单条检测规则
// GET /api/v1/detection-rules/:id
func (h *DetectionRulesHandler) GetRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.DetectionRule
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

type createDetectionRuleRequest struct {
	Name        string   `json:"name" binding:"required"`
	Expression  string   `json:"expression" binding:"required"`
	Severity    string   `json:"severity" binding:"required"`
	MitreID     string   `json:"mitreId"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	DataTypes   []string `json:"dataTypes"`
	Enabled     *bool    `json:"enabled"`
}

// CreateRule 创建检测规则
// POST /api/v1/detection-rules
func (h *DetectionRulesHandler) CreateRule(c *gin.Context) {
	var req createDetectionRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &model.DetectionRule{
		Name:        req.Name,
		Expression:  req.Expression,
		Severity:    req.Severity,
		MitreID:     req.MitreID,
		Category:    req.Category,
		Description: req.Description,
		DataTypes:   model.StringArray(req.DataTypes),
		Enabled:     enabled,
	}

	if err := h.db.Create(rule).Error; err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			BadRequest(c, "规则名称已存在")
			return
		}
		h.logger.Error("创建检测规则失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	Created(c, rule)
}

// UpdateRule 更新检测规则
// PUT /api/v1/detection-rules/:id
func (h *DetectionRulesHandler) UpdateRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.DetectionRule
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "规则不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	var req createDetectionRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	updates := map[string]interface{}{
		"name":        req.Name,
		"expression":  req.Expression,
		"severity":    req.Severity,
		"mitre_id":    req.MitreID,
		"category":    req.Category,
		"description": req.Description,
		"data_types":  model.StringArray(req.DataTypes),
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	// 内置规则被用户编辑后标记 user_modified，防止版本升级时被覆盖
	if rule.Builtin {
		updates["user_modified"] = true
	}

	if err := h.db.Model(&rule).Updates(updates).Error; err != nil {
		h.logger.Error("更新检测规则失败", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	h.db.First(&rule, id)
	Success(c, rule)
}

// DeleteRule 删除检测规则（内置规则不可删除，只能禁用）
// DELETE /api/v1/detection-rules/:id
func (h *DetectionRulesHandler) DeleteRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.DetectionRule
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "规则不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}
	if rule.Builtin {
		BadRequest(c, "内置规则不可删除，请使用禁用功能")
		return
	}

	result := h.db.Delete(&model.DetectionRule{}, id)
	if result.Error != nil {
		h.logger.Error("删除检测规则失败", zap.Error(result.Error))
		InternalError(c, "删除失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "规则不存在")
		return
	}

	SuccessMessage(c, "规则已删除")
}

// ToggleRule 启用/禁用检测规则
// POST /api/v1/detection-rules/:id/toggle
func (h *DetectionRulesHandler) ToggleRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}

	var rule model.DetectionRule
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

// GetCategories 获取规则分类列表
// GET /api/v1/detection-rules/categories
func (h *DetectionRulesHandler) GetCategories(c *gin.Context) {
	var categories []string
	h.db.Model(&model.DetectionRule{}).Distinct("category").Where("category != ''").Pluck("category", &categories)
	Success(c, categories)
}

// GetMitreIDs 获取去重的 MITRE ATT&CK ID 列表
// GET /api/v1/detection-rules/mitre-ids
func (h *DetectionRulesHandler) GetMitreIDs(c *gin.Context) {
	var ids []string
	h.db.Model(&model.DetectionRule{}).
		Where("mitre_id != ''").
		Distinct("mitre_id").
		Order("mitre_id").
		Pluck("mitre_id", &ids)
	Success(c, ids)
}

// GetStatistics 获取规则统计
// GET /api/v1/detection-rules/statistics
func (h *DetectionRulesHandler) GetStatistics(c *gin.Context) {
	var total, enabled, disabled int64
	h.db.Model(&model.DetectionRule{}).Count(&total)
	h.db.Model(&model.DetectionRule{}).Where("enabled = ?", true).Count(&enabled)
	disabled = total - enabled

	var severityRows []struct {
		Severity string `gorm:"column:severity"`
		Count    int64  `gorm:"column:count"`
	}
	h.db.Model(&model.DetectionRule{}).Select("severity, COUNT(*) as count").Group("severity").Scan(&severityRows)

	severityMap := make(map[string]int64)
	for _, row := range severityRows {
		severityMap[row.Severity] = row.Count
	}

	Success(c, gin.H{
		"total":    total,
		"enabled":  enabled,
		"disabled": disabled,
		"severity": severityMap,
	})
}
