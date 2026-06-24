package api

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PolicyImportExportHandler 策略导入导出处理器
type PolicyImportExportHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewPolicyImportExportHandler 创建策略导入导出处理器
func NewPolicyImportExportHandler(db *gorm.DB, logger *zap.Logger) *PolicyImportExportHandler {
	return &PolicyImportExportHandler{
		db:     db,
		logger: logger,
	}
}

// PolicyExportFormat 策略导出格式（匹配 JSON 配置文件格式）
type PolicyExportFormat struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	OSFamily    []string           `json:"os_family"`
	OSVersion   string             `json:"os_version,omitempty"`
	Enabled     bool               `json:"enabled"`
	Rules       []RuleExportFormat `json:"rules"`
}

// RuleExportFormat 规则导出格式
type RuleExportFormat struct {
	RuleID      string                 `json:"rule_id"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Check       map[string]interface{} `json:"check"`
	Fix         map[string]interface{} `json:"fix"`
}

// ExportPolicy 导出单个策略
func (h *PolicyImportExportHandler) ExportPolicy(c *gin.Context) {
	policyID := c.Param("policy_id")

	var policy model.Policy
	if err := h.db.Preload("Rules").Where("id = ?", policyID).First(&policy).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "策略不存在")
			return
		}
		h.logger.Error("查询策略失败", zap.Error(err))
		InternalError(c, "查询策略失败")
		return
	}

	exportData := h.convertPolicyToExportFormat(&policy)
	Success(c, exportData)
}

// ExportAllPolicies 导出所有策略
func (h *PolicyImportExportHandler) ExportAllPolicies(c *gin.Context) {
	var policies []model.Policy
	if err := h.db.Preload("Rules").Find(&policies).Error; err != nil {
		h.logger.Error("查询策略失败", zap.Error(err))
		InternalError(c, "查询策略失败")
		return
	}

	var exportData []PolicyExportFormat
	for _, policy := range policies {
		exportData = append(exportData, h.convertPolicyToExportFormat(&policy))
	}

	Success(c, exportData)
}

// ImportPolicy 导入策略
func (h *PolicyImportExportHandler) ImportPolicy(c *gin.Context) {
	// 获取目标策略组 ID（必填）
	groupID := c.Query("group_id")
	if groupID == "" {
		groupID = c.PostForm("group_id")
	}
	if groupID == "" {
		BadRequest(c, "请指定目标策略组 ID (group_id)")
		return
	}

	// 验证策略组是否存在
	var group model.PolicyGroup
	if err := h.db.Where("id = ?", groupID).First(&group).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			BadRequest(c, "指定的策略组不存在")
			return
		}
		h.logger.Error("查询策略组失败", zap.Error(err))
		InternalError(c, "查询策略组失败")
		return
	}

	// 读取上传的文件
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		BadRequest(c, "请上传 JSON 文件")
		return
	}
	defer file.Close()

	// 读取文件内容
	data, err := io.ReadAll(file)
	if err != nil {
		h.logger.Error("读取文件失败", zap.Error(err))
		InternalError(c, "读取文件失败")
		return
	}

	// 尝试解析为单个策略或策略数组
	var policies []PolicyExportFormat

	// 先尝试解析为数组
	if err := json.Unmarshal(data, &policies); err != nil {
		// 如果失败，尝试解析为单个策略
		var singlePolicy PolicyExportFormat
		if err := json.Unmarshal(data, &singlePolicy); err != nil {
			BadRequest(c, "JSON 格式错误")
			return
		}
		policies = []PolicyExportFormat{singlePolicy}
	}

	// 获取导入模式
	mode := c.DefaultQuery("mode", "skip") // skip: 跳过已存在, update: 更新已存在, replace: 替换已存在

	// 导入策略
	imported := 0
	updated := 0
	skipped := 0
	errors := []string{}

	for _, policyData := range policies {
		// 检查策略是否已存在
		var existing model.Policy
		err := h.db.Where("id = ?", policyData.ID).First(&existing).Error

		if err == nil {
			// 策略已存在
			switch mode {
			case "skip":
				skipped++
				continue
			case "update", "replace":
				// 更新策略
				if err := h.updatePolicy(&existing, &policyData, groupID, mode == "replace"); err != nil {
					errors = append(errors, fmt.Sprintf("%s: %v", policyData.ID, err))
					continue
				}
				updated++
			default:
				errors = append(errors, fmt.Sprintf("%s: 未知的导入模式 %s", policyData.ID, mode))
				continue
			}
		} else if err == gorm.ErrRecordNotFound {
			// 策略不存在，创建新策略
			if err := h.createPolicy(&policyData, groupID); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", policyData.ID, err))
				continue
			}
			imported++
		} else {
			errors = append(errors, fmt.Sprintf("%s: %v", policyData.ID, err))
			continue
		}
	}

	result := gin.H{
		"imported": imported,
		"updated":  updated,
		"skipped":  skipped,
		"total":    len(policies),
	}

	if len(errors) > 0 {
		result["errors"] = errors
	}

	Success(c, result)
}

// convertPolicyToExportFormat 将策略转换为导出格式
func (h *PolicyImportExportHandler) convertPolicyToExportFormat(policy *model.Policy) PolicyExportFormat {
	export := PolicyExportFormat{
		ID:          policy.ID,
		Name:        policy.Name,
		Version:     policy.Version,
		Description: policy.Description,
		OSFamily:    policy.OSFamily,
		OSVersion:   policy.OSVersion,
		Enabled:     policy.Enabled,
		Rules:       []RuleExportFormat{},
	}

	for _, rule := range policy.Rules {
		ruleExport := RuleExportFormat{
			RuleID:      rule.RuleID,
			Category:    rule.Category,
			Title:       rule.Title,
			Description: rule.Description,
			Severity:    rule.Severity,
		}

		// 转换 CheckConfig
		checkBytes, _ := json.Marshal(rule.CheckConfig)
		_ = json.Unmarshal(checkBytes, &ruleExport.Check)

		// 转换 FixConfig
		fixBytes, _ := json.Marshal(rule.FixConfig)
		_ = json.Unmarshal(fixBytes, &ruleExport.Fix)

		export.Rules = append(export.Rules, ruleExport)
	}

	return export
}

// createPolicy 创建新策略
func (h *PolicyImportExportHandler) createPolicy(data *PolicyExportFormat, groupID string) error {
	return h.db.Transaction(func(tx *gorm.DB) error {
		// 创建策略
		policy := model.Policy{
			ID:          data.ID,
			Name:        data.Name,
			Version:     data.Version,
			Description: data.Description,
			OSFamily:    data.OSFamily,
			OSVersion:   data.OSVersion,
			Enabled:     data.Enabled,
			GroupID:     groupID,
		}

		if err := tx.Create(&policy).Error; err != nil {
			return fmt.Errorf("创建策略失败: %w", err)
		}

		// 创建规则
		for _, ruleData := range data.Rules {
			rule := model.Rule{
				RuleID:      ruleData.RuleID,
				PolicyID:    data.ID,
				Category:    ruleData.Category,
				Title:       ruleData.Title,
				Description: ruleData.Description,
				Severity:    ruleData.Severity,
				Enabled:     true,
			}

			// 转换 CheckConfig
			checkBytes, _ := json.Marshal(ruleData.Check)
			_ = json.Unmarshal(checkBytes, &rule.CheckConfig)

			// 转换 FixConfig
			fixBytes, _ := json.Marshal(ruleData.Fix)
			_ = json.Unmarshal(fixBytes, &rule.FixConfig)

			if err := tx.Create(&rule).Error; err != nil {
				return fmt.Errorf("创建规则 %s 失败: %w", ruleData.RuleID, err)
			}
		}

		return nil
	})
}

// updatePolicy 更新策略
func (h *PolicyImportExportHandler) updatePolicy(existing *model.Policy, data *PolicyExportFormat, groupID string, replace bool) error {
	return h.db.Transaction(func(tx *gorm.DB) error {
		// 更新策略基本信息
		updates := map[string]interface{}{
			"name":        data.Name,
			"version":     data.Version,
			"description": data.Description,
			"os_family":   model.StringArray(data.OSFamily), // 转换为 StringArray 类型
			"os_version":  data.OSVersion,
			"enabled":     data.Enabled,
			"group_id":    groupID,
		}

		if err := tx.Model(existing).Updates(updates).Error; err != nil {
			return fmt.Errorf("更新策略失败: %w", err)
		}

		if replace {
			// 替换模式：删除所有旧规则
			if err := tx.Where("policy_id = ?", existing.ID).Delete(&model.Rule{}).Error; err != nil {
				return fmt.Errorf("删除旧规则失败: %w", err)
			}

			// 创建新规则
			for _, ruleData := range data.Rules {
				rule := model.Rule{
					RuleID:      ruleData.RuleID,
					PolicyID:    existing.ID,
					Category:    ruleData.Category,
					Title:       ruleData.Title,
					Description: ruleData.Description,
					Severity:    ruleData.Severity,
					Enabled:     true,
				}

				checkBytes, _ := json.Marshal(ruleData.Check)
				_ = json.Unmarshal(checkBytes, &rule.CheckConfig)

				fixBytes, _ := json.Marshal(ruleData.Fix)
				_ = json.Unmarshal(fixBytes, &rule.FixConfig)

				if err := tx.Create(&rule).Error; err != nil {
					return fmt.Errorf("创建规则 %s 失败: %w", ruleData.RuleID, err)
				}
			}
		} else {
			// P2-8: 一次性预取所有现存规则, 避免 N+1
			ruleIDs := make([]string, 0, len(data.Rules))
			for _, rd := range data.Rules {
				ruleIDs = append(ruleIDs, rd.RuleID)
			}
			var existRules []model.Rule
			_ = tx.Where("policy_id = ? AND rule_id IN ?", existing.ID, ruleIDs).Find(&existRules).Error
			existMap := make(map[string]*model.Rule, len(existRules))
			for i := range existRules {
				existMap[existRules[i].RuleID] = &existRules[i]
			}

			// 更新模式：更新或创建规则
			for _, ruleData := range data.Rules {
				var existingRule model.Rule
				var err error
				if existPtr, found := existMap[ruleData.RuleID]; found {
					existingRule = *existPtr
				} else {
					err = gorm.ErrRecordNotFound
				}

				if err == gorm.ErrRecordNotFound {
					// 规则不存在，创建新规则
					rule := model.Rule{
						RuleID:      ruleData.RuleID,
						PolicyID:    existing.ID,
						Category:    ruleData.Category,
						Title:       ruleData.Title,
						Description: ruleData.Description,
						Severity:    ruleData.Severity,
						Enabled:     true,
					}

					checkBytes, _ := json.Marshal(ruleData.Check)
					_ = json.Unmarshal(checkBytes, &rule.CheckConfig)

					fixBytes, _ := json.Marshal(ruleData.Fix)
					_ = json.Unmarshal(fixBytes, &rule.FixConfig)

					if err := tx.Create(&rule).Error; err != nil {
						return fmt.Errorf("创建规则 %s 失败: %w", ruleData.RuleID, err)
					}
				} else if err == nil {
					// 规则已存在，更新
					var checkConfig model.CheckConfig
					var fixConfig model.FixConfig

					checkBytes, _ := json.Marshal(ruleData.Check)
					_ = json.Unmarshal(checkBytes, &checkConfig)

					fixBytes, _ := json.Marshal(ruleData.Fix)
					_ = json.Unmarshal(fixBytes, &fixConfig)

					ruleUpdates := map[string]interface{}{
						"category":     ruleData.Category,
						"title":        ruleData.Title,
						"description":  ruleData.Description,
						"severity":     ruleData.Severity,
						"check_config": checkConfig,
						"fix_config":   fixConfig,
					}

					if err := tx.Model(&existingRule).Updates(ruleUpdates).Error; err != nil {
						return fmt.Errorf("更新规则 %s 失败: %w", ruleData.RuleID, err)
					}
				} else {
					return fmt.Errorf("查询规则 %s 失败: %w", ruleData.RuleID, err)
				}
			}
		}

		return nil
	})
}

// RegisterPolicyImportExportRoutes 注册策略导入导出路由
func RegisterPolicyImportExportRoutes(r *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := NewPolicyImportExportHandler(db, logger)

	// 导出路由
	r.GET("/policies/export", handler.ExportAllPolicies)
	r.GET("/policies/:policy_id/export", handler.ExportPolicy)

	// 导入路由
	r.POST("/policies/import", handler.ImportPolicy)
}
