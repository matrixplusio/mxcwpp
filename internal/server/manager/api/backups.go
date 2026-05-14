package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// BackupsHandler 配置备份 API 处理器
type BackupsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewBackupsHandler 创建备份处理器
func NewBackupsHandler(db *gorm.DB, logger *zap.Logger) *BackupsHandler {
	return &BackupsHandler{db: db, logger: logger}
}

// backupScopeLabels scope 到中文名的映射
var backupScopeLabels = map[string]string{
	"policies":       "策略配置",
	"users":          "用户数据",
	"notifications":  "通知配置",
	"settings":       "系统设置",
	"business_lines": "业务线",
	"fim_policies":   "FIM 策略",
}

// validScopes 允许的 scope 值
var validScopes = map[string]bool{
	"policies": true, "users": true, "notifications": true,
	"settings": true, "business_lines": true, "fim_policies": true,
}

// backupData 备份文件结构
type backupData struct {
	Version   string                 `json:"version"`
	CreatedAt string                 `json:"created_at"`
	Scope     []string               `json:"scope"`
	Data      map[string]interface{} `json:"data"`
}

// ListBackups 获取备份列表
// GET /api/v1/system/backups
func (h *BackupsHandler) ListBackups(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	var total int64
	query := h.db.Model(&model.ConfigBackup{})
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询备份总数失败", zap.Error(err))
		InternalError(c, "查询备份列表失败")
		return
	}

	var backups []model.ConfigBackup
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&backups).Error; err != nil {
		h.logger.Error("查询备份列表失败", zap.Error(err))
		InternalError(c, "查询备份列表失败")
		return
	}

	type backupItem struct {
		model.ConfigBackup
		ScopeText string `json:"scopeText"`
		Size      string `json:"size"`
		CreatedAt string `json:"createdAt"`
	}

	items := make([]backupItem, 0, len(backups))
	for _, b := range backups {
		labels := make([]string, 0, len(b.Scope))
		for _, s := range b.Scope {
			if label, ok := backupScopeLabels[s]; ok {
				labels = append(labels, label)
			}
		}
		items = append(items, backupItem{
			ConfigBackup: b,
			ScopeText:    strings.Join(labels, "、"),
			Size:         formatFileSize(b.FileSize),
			CreatedAt:    b.CreatedAt.String(),
		})
	}

	SuccessPaginated(c, total, items)
}

// CreateBackup 创建备份
// POST /api/v1/system/backups
func (h *BackupsHandler) CreateBackup(c *gin.Context) {
	var req struct {
		Name   string   `json:"name"`
		Scope  []string `json:"scope" binding:"required"`
		Remark string   `json:"remark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请选择备份范围")
		return
	}

	for _, s := range req.Scope {
		if !validScopes[s] {
			BadRequest(c, fmt.Sprintf("无效的备份范围: %s", s))
			return
		}
	}

	now := time.Now()
	timeSuffix := now.Format("20060102_150405")
	name := "backup_" + timeSuffix
	if req.Name != "" {
		name = req.Name + "_" + timeSuffix
	}
	filePath := filepath.Join(".", "uploads", "backups", name+".json")

	record := model.ConfigBackup{
		Name:      name,
		Type:      "manual",
		Scope:     model.StringArray(req.Scope),
		FilePath:  filePath,
		Status:    "creating",
		Remark:    req.Remark,
		CreatedAt: model.LocalTime(now),
	}
	if err := h.db.Create(&record).Error; err != nil {
		h.logger.Error("创建备份记录失败", zap.Error(err))
		InternalError(c, "创建备份失败")
		return
	}

	// 同步导出数据
	data, err := h.exportData(req.Scope)
	if err != nil {
		h.db.Model(&record).Update("status", "failed")
		h.logger.Error("导出备份数据失败", zap.Error(err))
		InternalError(c, "备份数据导出失败")
		return
	}

	bd := backupData{
		Version:   "1.0",
		CreatedAt: now.Format(model.TimeFormat),
		Scope:     req.Scope,
		Data:      data,
	}

	jsonBytes, err := json.MarshalIndent(bd, "", "  ")
	if err != nil {
		h.db.Model(&record).Update("status", "failed")
		h.logger.Error("序列化备份数据失败", zap.Error(err))
		InternalError(c, "备份数据序列化失败")
		return
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		h.db.Model(&record).Update("status", "failed")
		h.logger.Error("创建备份目录失败", zap.Error(err))
		InternalError(c, "创建备份目录失败")
		return
	}

	if err := os.WriteFile(filePath, jsonBytes, 0o644); err != nil {
		h.db.Model(&record).Update("status", "failed")
		h.logger.Error("写入备份文件失败", zap.Error(err))
		InternalError(c, "写入备份文件失败")
		return
	}

	h.db.Model(&record).Updates(map[string]interface{}{
		"status":    "completed",
		"file_size": int64(len(jsonBytes)),
	})

	h.logger.Info("配置备份创建成功", zap.String("name", name), zap.Strings("scope", req.Scope))
	SuccessWithMessage(c, "备份创建成功", record)
}

// GetBackupConfig 获取自动备份配置
// GET /api/v1/system/backup-config
func (h *BackupsHandler) GetBackupConfig(c *gin.Context) {
	var cfg model.SystemConfig
	err := h.db.Where("`key` = ? AND category = ?", "backup_config", "backup").First(&cfg).Error
	if err != nil {
		// 不存在则返回默认值
		Success(c, gin.H{"enabled": false, "frequency": "daily", "retention": 7})
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.Value), &result); err != nil {
		Success(c, gin.H{"enabled": false, "frequency": "daily", "retention": 7})
		return
	}
	Success(c, result)
}

// UpdateBackupConfig 更新自动备份配置
// PUT /api/v1/system/backup-config
func (h *BackupsHandler) UpdateBackupConfig(c *gin.Context) {
	var req struct {
		Enabled   bool   `json:"enabled"`
		Frequency string `json:"frequency"`
		Retention int    `json:"retention"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	valueBytes, _ := json.Marshal(req)

	result := h.db.Where("`key` = ? AND category = ?", "backup_config", "backup").
		Assign(model.SystemConfig{Value: string(valueBytes)}).
		FirstOrCreate(&model.SystemConfig{
			Key:         "backup_config",
			Category:    "backup",
			Value:       string(valueBytes),
			Description: "自动备份配置",
		})
	if result.Error != nil {
		h.logger.Error("保存备份配置失败", zap.Error(result.Error))
		InternalError(c, "保存配置失败")
		return
	}

	SuccessMessage(c, "配置已保存")
}

// DownloadBackup 下载备份文件
// GET /api/v1/system/backups/:id/download
func (h *BackupsHandler) DownloadBackup(c *gin.Context) {
	id := c.Param("id")
	var record model.ConfigBackup
	if err := h.db.First(&record, id).Error; err != nil {
		NotFound(c, "备份记录不存在")
		return
	}

	if record.Status != "completed" {
		BadRequest(c, "备份尚未完成，无法下载")
		return
	}

	if _, err := os.Stat(record.FilePath); os.IsNotExist(err) {
		NotFound(c, "备份文件不存在")
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", record.Name))
	c.File(record.FilePath)
}

// RestoreBackup 恢复备份
// POST /api/v1/system/backups/:id/restore
func (h *BackupsHandler) RestoreBackup(c *gin.Context) {
	id := c.Param("id")
	var record model.ConfigBackup
	if err := h.db.First(&record, id).Error; err != nil {
		NotFound(c, "备份记录不存在")
		return
	}

	if record.Status != "completed" {
		BadRequest(c, "备份尚未完成，无法恢复")
		return
	}

	fileBytes, err := os.ReadFile(record.FilePath)
	if err != nil {
		h.logger.Error("读取备份文件失败", zap.Error(err))
		InternalError(c, "读取备份文件失败")
		return
	}

	var bd backupData
	if err := json.Unmarshal(fileBytes, &bd); err != nil {
		h.logger.Error("解析备份文件失败", zap.Error(err))
		InternalError(c, "备份文件格式错误")
		return
	}

	if err := h.restoreData(bd.Scope, bd.Data); err != nil {
		h.logger.Error("恢复备份数据失败", zap.Error(err))
		InternalError(c, fmt.Sprintf("恢复失败: %v", err))
		return
	}

	h.logger.Info("配置备份恢复成功", zap.String("name", record.Name), zap.Strings("scope", bd.Scope))
	SuccessMessage(c, "恢复成功")
}

// DeleteBackup 删除备份
// DELETE /api/v1/system/backups/:id
func (h *BackupsHandler) DeleteBackup(c *gin.Context) {
	id := c.Param("id")
	var record model.ConfigBackup
	if err := h.db.First(&record, id).Error; err != nil {
		NotFound(c, "备份记录不存在")
		return
	}

	// 删除磁盘文件
	if record.FilePath != "" {
		_ = os.Remove(record.FilePath)
	}

	if err := h.db.Delete(&record).Error; err != nil {
		h.logger.Error("删除备份记录失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	SuccessMessage(c, "已删除")
}

// exportData 按 scope 导出数据
func (h *BackupsHandler) exportData(scopes []string) (map[string]interface{}, error) {
	data := make(map[string]interface{})

	for _, scope := range scopes {
		switch scope {
		case "policies":
			pd := make(map[string]interface{})
			var groups []model.PolicyGroup
			if err := h.db.Find(&groups).Error; err != nil {
				return nil, fmt.Errorf("导出策略组失败: %w", err)
			}
			pd["policy_groups"] = groups

			var policies []model.Policy
			if err := h.db.Find(&policies).Error; err != nil {
				return nil, fmt.Errorf("导出策略失败: %w", err)
			}
			pd["policies"] = policies

			var rules []model.Rule
			if err := h.db.Find(&rules).Error; err != nil {
				return nil, fmt.Errorf("导出规则失败: %w", err)
			}
			pd["rules"] = rules

			data["policies"] = pd

		case "users":
			var users []model.User
			if err := h.db.Find(&users).Error; err != nil {
				return nil, fmt.Errorf("导出用户失败: %w", err)
			}
			data["users"] = users

		case "notifications":
			var notifications []model.Notification
			if err := h.db.Find(&notifications).Error; err != nil {
				return nil, fmt.Errorf("导出通知失败: %w", err)
			}
			data["notifications"] = notifications

		case "settings":
			var configs []model.SystemConfig
			if err := h.db.Find(&configs).Error; err != nil {
				return nil, fmt.Errorf("导出系统配置失败: %w", err)
			}
			data["settings"] = configs

		case "business_lines":
			var lines []model.BusinessLine
			if err := h.db.Find(&lines).Error; err != nil {
				return nil, fmt.Errorf("导出业务线失败: %w", err)
			}
			data["business_lines"] = lines

		case "fim_policies":
			var policies []model.FIMPolicy
			if err := h.db.Find(&policies).Error; err != nil {
				return nil, fmt.Errorf("导出 FIM 策略失败: %w", err)
			}
			data["fim_policies"] = policies
		}
	}

	return data, nil
}

// restoreData 按 scope 恢复数据（事务内执行）
func (h *BackupsHandler) restoreData(scopes []string, data map[string]interface{}) error {
	return h.db.Transaction(func(tx *gorm.DB) error {
		for _, scope := range scopes {
			raw, ok := data[scope]
			if !ok {
				continue
			}

			rawBytes, err := json.Marshal(raw)
			if err != nil {
				return fmt.Errorf("序列化 %s 数据失败: %w", scope, err)
			}

			switch scope {
			case "policies":
				if err := h.restorePolicies(tx, rawBytes); err != nil {
					return err
				}
			case "users":
				if err := restoreTable[model.User](tx, rawBytes); err != nil {
					return fmt.Errorf("恢复用户失败: %w", err)
				}
			case "notifications":
				if err := restoreTable[model.Notification](tx, rawBytes); err != nil {
					return fmt.Errorf("恢复通知失败: %w", err)
				}
			case "settings":
				if err := restoreTable[model.SystemConfig](tx, rawBytes); err != nil {
					return fmt.Errorf("恢复系统配置失败: %w", err)
				}
			case "business_lines":
				if err := restoreTable[model.BusinessLine](tx, rawBytes); err != nil {
					return fmt.Errorf("恢复业务线失败: %w", err)
				}
			case "fim_policies":
				if err := restoreTable[model.FIMPolicy](tx, rawBytes); err != nil {
					return fmt.Errorf("恢复 FIM 策略失败: %w", err)
				}
			}
		}
		return nil
	})
}

// restorePolicies 恢复策略数据（处理外键顺序）
func (h *BackupsHandler) restorePolicies(tx *gorm.DB, rawBytes []byte) error {
	var pd struct {
		PolicyGroups []model.PolicyGroup `json:"policy_groups"`
		Policies     []model.Policy      `json:"policies"`
		Rules        []model.Rule        `json:"rules"`
	}
	if err := json.Unmarshal(rawBytes, &pd); err != nil {
		return fmt.Errorf("解析策略数据失败: %w", err)
	}

	// 清空顺序：rules → policies → groups（外键约束）
	if err := tx.Where("1 = 1").Delete(&model.Rule{}).Error; err != nil {
		return fmt.Errorf("清空规则失败: %w", err)
	}
	if err := tx.Where("1 = 1").Delete(&model.Policy{}).Error; err != nil {
		return fmt.Errorf("清空策略失败: %w", err)
	}
	if err := tx.Where("1 = 1").Delete(&model.PolicyGroup{}).Error; err != nil {
		return fmt.Errorf("清空策略组失败: %w", err)
	}

	// 插入顺序：groups → policies → rules
	for i := range pd.PolicyGroups {
		if err := tx.Create(&pd.PolicyGroups[i]).Error; err != nil {
			return fmt.Errorf("恢复策略组失败: %w", err)
		}
	}
	for i := range pd.Policies {
		if err := tx.Create(&pd.Policies[i]).Error; err != nil {
			return fmt.Errorf("恢复策略失败: %w", err)
		}
	}
	for i := range pd.Rules {
		if err := tx.Create(&pd.Rules[i]).Error; err != nil {
			return fmt.Errorf("恢复规则失败: %w", err)
		}
	}

	return nil
}

// restoreTable 通用表恢复：清空 + 重插
func restoreTable[T any](tx *gorm.DB, rawBytes []byte) error {
	var items []T
	if err := json.Unmarshal(rawBytes, &items); err != nil {
		return fmt.Errorf("解析数据失败: %w", err)
	}

	if err := tx.Where("1 = 1").Delete(new(T)).Error; err != nil {
		return fmt.Errorf("清空表失败: %w", err)
	}

	for i := range items {
		if err := tx.Create(&items[i]).Error; err != nil {
			return fmt.Errorf("插入数据失败: %w", err)
		}
	}
	return nil
}

// formatFileSize 格式化文件大小
func formatFileSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
}
