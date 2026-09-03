// Package api 提供 HTTP API 处理器
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// SystemConfigHandler 是系统配置 API 处理器
type SystemConfigHandler struct {
	db         *gorm.DB
	logger     *zap.Logger
	uploadDir  string // 文件上传目录（文件系统路径，例如：./uploads）
	staticPath string // 静态文件访问路径（HTTP URL 路径，例如：/uploads）
}

// NewSystemConfigHandler 创建系统配置处理器
// uploadDir: 文件系统路径，用于存储上传的文件（例如：./uploads）
// staticPath: HTTP 访问路径，用于通过 HTTP 访问上传的文件（例如：/uploads）
func NewSystemConfigHandler(db *gorm.DB, logger *zap.Logger, uploadDir, staticPath string) *SystemConfigHandler {
	// 设置默认值：如果未指定，使用项目根目录下的 uploads 目录
	if uploadDir == "" {
		uploadDir = "./uploads"
	}
	// 设置默认 HTTP 访问路径（与上传目录对应）
	if staticPath == "" {
		staticPath = "/uploads"
	}

	// 确保上传目录存在
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		logger.Warn("创建上传目录失败", zap.String("dir", uploadDir), zap.Error(err))
	}

	return &SystemConfigHandler{
		db:         db,
		logger:     logger,
		uploadDir:  uploadDir,
		staticPath: staticPath,
	}
}

// GetKubernetesImageConfig 获取 Kubernetes 镜像配置
// GET /api/v1/system-config/kubernetes-image
func (h *SystemConfigHandler) GetKubernetesImageConfig(c *gin.Context) {
	// 默认配置
	defaultConfig := model.KubernetesImageConfig{
		Repository:     "mxcwpp/mxcwpp-agent",
		Versions:       []string{"latest", "v1.0.0"},
		DefaultVersion: "latest",
	}

	// 尝试查询配置，如果失败则返回默认配置
	// 注意：key 是 MySQL 保留关键字，需要使用反引号包裹
	var config model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "kubernetes_image", "kubernetes").First(&config)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// 配置不存在，返回默认配置
			h.logger.Debug("Kubernetes 镜像配置不存在，使用默认配置")
			SuccessWithMessage(c, "success", defaultConfig)
			return
		}
		// 其他错误（如表不存在），记录日志但返回默认配置，避免 500 错误
		h.logger.Warn("查询 Kubernetes 镜像配置失败，使用默认配置", zap.Error(result.Error))
		SuccessWithMessage(c, "success", defaultConfig)
		return
	}

	// 解析配置值
	if config.Value == "" {
		// 配置值为空，返回默认配置
		h.logger.Debug("Kubernetes 镜像配置值为空，使用默认配置")
		SuccessWithMessage(c, "success", defaultConfig)
		return
	}

	var imageConfig model.KubernetesImageConfig
	if err := json.Unmarshal([]byte(config.Value), &imageConfig); err != nil {
		// 解析失败，记录日志但返回默认配置
		h.logger.Warn("解析 Kubernetes 镜像配置失败，使用默认配置", zap.Error(err))
		SuccessWithMessage(c, "success", defaultConfig)
		return
	}

	// 验证配置有效性
	if imageConfig.Repository == "" {
		imageConfig.Repository = defaultConfig.Repository
	}
	if len(imageConfig.Versions) == 0 {
		imageConfig.Versions = defaultConfig.Versions
	}
	if imageConfig.DefaultVersion == "" {
		imageConfig.DefaultVersion = defaultConfig.DefaultVersion
	}

	SuccessWithMessage(c, "success", imageConfig)
}

// UpdateKubernetesImageConfigRequest 更新 Kubernetes 镜像配置请求
type UpdateKubernetesImageConfigRequest struct {
	Repository     string   `json:"repository" binding:"required"`
	Versions       []string `json:"versions" binding:"required"`
	DefaultVersion string   `json:"default_version" binding:"required"`
}

// UpdateKubernetesImageConfig 更新 Kubernetes 镜像配置
// PUT /api/v1/system-config/kubernetes-image
func (h *SystemConfigHandler) UpdateKubernetesImageConfig(c *gin.Context) {
	var req UpdateKubernetesImageConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	imageConfig := model.KubernetesImageConfig{
		Repository:     req.Repository,
		Versions:       req.Versions,
		DefaultVersion: req.DefaultVersion,
	}

	valueJSON, err := json.Marshal(imageConfig)
	if err != nil {
		h.logger.Error("序列化 Kubernetes 镜像配置失败", zap.Error(err))
		InternalError(c, "序列化配置失败")
		return
	}

	config := model.SystemConfig{
		Key:         "kubernetes_image",
		Category:    "kubernetes",
		Value:       string(valueJSON),
		Description: "Kubernetes Agent 镜像仓库配置",
	}

	// 使用 FirstOrCreate 或 Updates
	// 注意：key 是 MySQL 保留关键字，需要使用反引号包裹
	var existingConfig model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "kubernetes_image", "kubernetes").First(&existingConfig)

	if result.Error == nil {
		// 更新现有配置
		if err := h.db.Model(&existingConfig).Updates(map[string]interface{}{
			"value":       string(valueJSON),
			"description": config.Description,
		}).Error; err != nil {
			h.logger.Error("更新 Kubernetes 镜像配置失败", zap.Error(err))
			InternalError(c, "更新配置失败")
			return
		}
	} else if result.Error == gorm.ErrRecordNotFound {
		// 创建新配置
		if err := h.db.Create(&config).Error; err != nil {
			h.logger.Error("创建 Kubernetes 镜像配置失败", zap.Error(err))
			InternalError(c, "创建配置失败")
			return
		}
	} else {
		h.logger.Error("查询 Kubernetes 镜像配置失败", zap.Error(result.Error))
		InternalError(c, "查询配置失败")
		return
	}

	SuccessWithMessage(c, "配置更新成功", imageConfig)
}

// GetSiteConfig 获取站点配置
// GET /api/v1/system-config/site
func (h *SystemConfigHandler) GetSiteConfig(c *gin.Context) {
	// 默认配置
	defaultConfig := model.SiteConfig{
		SiteName:   "矩阵云安全平台",
		SiteLogo:   "",
		SiteDomain: "",
		BackendURL: "",
	}

	// 尝试查询配置
	// 注意：key 是 MySQL 保留关键字，需要使用反引号包裹
	var config model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&config)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// 配置不存在，返回默认配置
			h.logger.Debug("站点配置不存在，使用默认配置")
			SuccessWithMessage(c, "success", defaultConfig)
			return
		}
		// 其他错误，记录日志但返回默认配置
		h.logger.Warn("查询站点配置失败，使用默认配置", zap.Error(result.Error))
		SuccessWithMessage(c, "success", defaultConfig)
		return
	}

	// 解析配置值
	if config.Value == "" {
		SuccessWithMessage(c, "success", defaultConfig)
		return
	}

	var siteConfig model.SiteConfig
	if err := json.Unmarshal([]byte(config.Value), &siteConfig); err != nil {
		h.logger.Warn("解析站点配置失败，使用默认配置", zap.Error(err))
		SuccessWithMessage(c, "success", defaultConfig)
		return
	}

	// 验证配置有效性
	if siteConfig.SiteName == "" {
		siteConfig.SiteName = defaultConfig.SiteName
	}

	SuccessWithMessage(c, "success", siteConfig)
}

// UpdateSiteConfigRequest 更新站点配置请求
type UpdateSiteConfigRequest struct {
	SiteName   string  `json:"site_name"`   // 站点名称（必填，手动验证）
	SiteLogo   *string `json:"site_logo"`   // Logo URL（指针类型，nil表示不修改，空字符串表示删除）
	SiteDomain string  `json:"site_domain"` // 前端访问域名（可选）
	BackendURL string  `json:"backend_url"` // 后端接口地址（必填）
}

// UpdateSiteConfig 更新站点配置
// PUT /api/v1/system-config/site
func (h *SystemConfigHandler) UpdateSiteConfig(c *gin.Context) {
	// 添加 panic 恢复
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error("UpdateSiteConfig panic",
				zap.Any("panic", r),
				zap.String("stack", fmt.Sprintf("%+v", r)),
			)
			InternalError(c, "服务器内部错误，请稍后重试")
		}
	}()

	var req UpdateSiteConfigRequest

	// 使用 ShouldBindJSON 绑定请求，但不使用 required 标签，手动验证
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("更新站点配置请求参数绑定失败",
			zap.Error(err),
		)
		BadRequest(c, "请求参数格式错误")
		return
	}

	siteLogoValue := ""
	if req.SiteLogo != nil {
		siteLogoValue = *req.SiteLogo
	}
	h.logger.Info("收到更新站点配置请求",
		zap.String("site_name", req.SiteName),
		zap.String("site_domain", req.SiteDomain),
		zap.String("backend_url", req.BackendURL),
		zap.String("site_logo", siteLogoValue),
		zap.Bool("site_logo_provided", req.SiteLogo != nil),
	)

	// 验证必填字段
	if strings.TrimSpace(req.SiteName) == "" {
		h.logger.Warn("站点名称为空")
		BadRequest(c, "站点名称不能为空")
		return
	}

	if strings.TrimSpace(req.BackendURL) == "" {
		h.logger.Warn("后端接口地址为空")
		BadRequest(c, "后端接口地址不能为空")
		return
	}

	// 清理空格
	req.SiteName = strings.TrimSpace(req.SiteName)
	req.SiteDomain = strings.TrimSpace(req.SiteDomain)
	req.BackendURL = strings.TrimSpace(req.BackendURL)

	// 检查数据库连接
	if h.db == nil {
		h.logger.Error("数据库连接未初始化")
		InternalError(c, "数据库连接未初始化")
		return
	}

	// 查询现有配置
	// 注意：key 是 MySQL 保留关键字，需要使用反引号包裹
	var existingConfig model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&existingConfig)

	// 记录查询结果（用于调试）
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			h.logger.Debug("站点配置不存在，将创建新配置")
		} else {
			// 记录详细的错误信息
			errorMsg := result.Error.Error()
			h.logger.Error("查询站点配置时出现错误",
				zap.Error(result.Error),
				zap.String("error_type", fmt.Sprintf("%T", result.Error)),
				zap.String("error_message", errorMsg),
				zap.String("key", "site_config"),
				zap.String("category", "site"),
			)
			// 如果是表不存在的错误，返回更友好的错误信息
			if strings.Contains(strings.ToLower(errorMsg), "doesn't exist") ||
				strings.Contains(strings.ToLower(errorMsg), "table") ||
				strings.Contains(strings.ToLower(errorMsg), "no such table") {
				h.logger.Warn("检测到表可能不存在")
				InternalError(c, "数据库表不存在，请确保已执行数据库迁移。错误详情: "+errorMsg)
				return
			}
			// 其他数据库错误也返回
			InternalError(c, "查询配置失败: "+errorMsg)
			return
		}
	} else {
		h.logger.Debug("找到现有站点配置", zap.Uint("id", existingConfig.ID))
	}

	// 处理 Logo：如果未传递（nil），保留现有值；如果传递了空字符串，清空；如果传递了值，使用新值
	var finalLogo string
	if req.SiteLogo == nil {
		// 未传递 site_logo 字段，保留现有值
		if result.Error == nil && existingConfig.Value != "" {
			var existingSiteConfig model.SiteConfig
			if err := json.Unmarshal([]byte(existingConfig.Value), &existingSiteConfig); err == nil {
				finalLogo = existingSiteConfig.SiteLogo
				h.logger.Debug("保留现有 Logo（用户未修改）", zap.String("logo", finalLogo))
			} else {
				h.logger.Warn("解析现有站点配置失败", zap.Error(err))
				finalLogo = ""
			}
		} else {
			finalLogo = ""
			h.logger.Debug("配置不存在或为空，使用空 Logo")
		}
	} else {
		// 传递了 site_logo 字段，使用传递的值（可能是空字符串，表示删除）
		finalLogo = *req.SiteLogo
		if finalLogo == "" {
			h.logger.Debug("用户清空 Logo")
		} else {
			h.logger.Debug("用户设置新 Logo", zap.String("logo", finalLogo))
		}
	}

	// 构建站点配置
	siteConfig := model.SiteConfig{
		SiteName:   req.SiteName,
		SiteLogo:   finalLogo,
		SiteDomain: req.SiteDomain,
		BackendURL: req.BackendURL,
	}

	// 序列化配置值
	valueJSON, err := json.Marshal(siteConfig)
	if err != nil {
		h.logger.Error("序列化站点配置失败", zap.Error(err), zap.Any("site_config", siteConfig))
		InternalError(c, "序列化配置失败")
		return
	}

	// 更新或创建配置
	updateData := map[string]interface{}{
		"value":       string(valueJSON),
		"description": "站点配置（站点名称、Logo、域名）",
	}

	if result.Error == nil && existingConfig.ID > 0 {
		// 更新现有配置
		h.logger.Debug("准备更新站点配置",
			zap.Uint("id", existingConfig.ID),
			zap.String("site_name", req.SiteName),
			zap.String("site_domain", req.SiteDomain),
			zap.String("site_logo", finalLogo),
		)
		if err := h.db.Model(&existingConfig).Updates(updateData).Error; err != nil {
			h.logger.Error("更新站点配置失败",
				zap.Error(err),
				zap.Uint("id", existingConfig.ID),
				zap.String("error_type", fmt.Sprintf("%T", err)),
				zap.String("value_json", string(valueJSON)),
			)
			InternalError(c, "更新配置失败")
			return
		}
		h.logger.Info("站点配置更新成功", zap.Uint("id", existingConfig.ID))
	} else {
		// 创建新配置
		config := model.SystemConfig{
			Key:         "site_config",
			Category:    "site",
			Value:       string(valueJSON),
			Description: "站点配置（站点名称、Logo、域名）",
		}
		h.logger.Debug("准备创建新站点配置",
			zap.String("site_name", req.SiteName),
			zap.String("site_domain", req.SiteDomain),
			zap.String("site_logo", finalLogo),
		)
		if err := h.db.Create(&config).Error; err != nil {
			// 如果是唯一索引冲突，尝试更新
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") ||
				strings.Contains(strings.ToLower(err.Error()), "unique") {
				h.logger.Warn("检测到唯一索引冲突，尝试更新现有配置", zap.Error(err))
				// 重新查询并更新
				// 注意：key 是 MySQL 保留关键字，需要使用反引号包裹
				var existing model.SystemConfig
				if queryErr := h.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&existing).Error; queryErr == nil {
					if updateErr := h.db.Model(&existing).Updates(updateData).Error; updateErr != nil {
						h.logger.Error("更新站点配置失败（唯一索引冲突后）",
							zap.Error(updateErr),
							zap.Uint("id", existing.ID),
						)
						InternalError(c, "更新配置失败")
						return
					}
					h.logger.Info("站点配置更新成功（唯一索引冲突后）", zap.Uint("id", existing.ID))
				} else {
					h.logger.Error("创建站点配置失败（唯一索引冲突且无法更新）",
						zap.Error(err),
						zap.Error(queryErr),
					)
					InternalError(c, "保存配置失败")
					return
				}
			} else {
				h.logger.Error("创建站点配置失败",
					zap.Error(err),
					zap.String("error_type", fmt.Sprintf("%T", err)),
					zap.String("key", config.Key),
					zap.String("category", config.Category),
					zap.String("value_json", string(valueJSON)),
				)
				InternalError(c, "创建配置失败")
				return
			}
		} else {
			h.logger.Info("站点配置创建成功", zap.Uint("id", config.ID))
		}
	}

	SuccessWithMessage(c, "配置更新成功", siteConfig)
}

// UploadLogo 上传 Logo
// POST /api/v1/system-config/upload-logo
func (h *SystemConfigHandler) UploadLogo(c *gin.Context) {
	// 检查上传目录
	if h.uploadDir == "" {
		InternalError(c, "文件上传功能未配置")
		return
	}

	// 获取上传的文件
	file, err := c.FormFile("logo")
	if err != nil {
		BadRequest(c, "请选择要上传的文件")
		return
	}

	// 验证文件类型（只允许图片）
	allowedTypes := []string{".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	allowed := false
	for _, t := range allowedTypes {
		if ext == t {
			allowed = true
			break
		}
	}
	if !allowed {
		BadRequest(c, "不支持的文件类型，仅支持: "+strings.Join(allowedTypes, ", "))
		return
	}

	// 验证文件大小（最大 5MB）
	if file.Size > 5*1024*1024 {
		BadRequest(c, "文件大小不能超过 5MB")
		return
	}

	// 生成唯一文件名
	timestamp := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("logo_%s%s", timestamp, ext)
	filePath := filepath.Join(h.uploadDir, filename)

	// 保存文件
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		h.logger.Error("保存 Logo 文件失败", zap.Error(err))
		InternalError(c, "保存文件失败")
		return
	}

	// 生成访问 URL（通过静态文件服务访问）
	logoURL := h.staticPath + "/" + filename

	// 删除旧的 Logo（如果存在）
	// 注意：key 是 MySQL 保留关键字，需要使用反引号包裹
	var existingConfig model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&existingConfig)
	if result.Error == nil && existingConfig.Value != "" {
		var existingSiteConfig model.SiteConfig
		if err := json.Unmarshal([]byte(existingConfig.Value), &existingSiteConfig); err == nil {
			if existingSiteConfig.SiteLogo != "" {
				// 提取旧文件名
				oldFilename := filepath.Base(existingSiteConfig.SiteLogo)
				if oldFilename != filename {
					oldFilepath := filepath.Join(h.uploadDir, oldFilename)
					if err := os.Remove(oldFilepath); err != nil && !os.IsNotExist(err) {
						h.logger.Warn("删除旧 Logo 文件失败", zap.String("file", oldFilepath), zap.Error(err))
					}
				}
			}
		}
	}

	// 更新站点配置中的 Logo URL
	siteConfig := model.SiteConfig{
		SiteName:   "矩阵云安全平台", // 默认值，实际应该从现有配置读取
		SiteLogo:   logoURL,
		SiteDomain: "", // 默认值，实际应该从现有配置读取
		BackendURL: "", // 默认值，实际应该从现有配置读取
	}

	// 如果存在现有配置，保留其他字段
	if result.Error == nil && existingConfig.Value != "" {
		var existingSiteConfig model.SiteConfig
		if err := json.Unmarshal([]byte(existingConfig.Value), &existingSiteConfig); err == nil {
			siteConfig.SiteName = existingSiteConfig.SiteName
			siteConfig.SiteDomain = existingSiteConfig.SiteDomain
			siteConfig.BackendURL = existingSiteConfig.BackendURL
		}
	}

	valueJSON, err := json.Marshal(siteConfig)
	if err != nil {
		h.logger.Error("序列化站点配置失败", zap.Error(err))
		InternalError(c, "更新配置失败")
		return
	}

	// 更新数据库配置
	if result.Error == nil {
		// 更新现有配置
		if err := h.db.Model(&existingConfig).Updates(map[string]interface{}{
			"value": string(valueJSON),
		}).Error; err != nil {
			h.logger.Error("更新站点配置失败", zap.Error(err))
			InternalError(c, "更新配置失败")
			return
		}
	} else {
		// 创建新配置
		config := model.SystemConfig{
			Key:         "site_config",
			Category:    "site",
			Value:       string(valueJSON),
			Description: "站点配置（站点名称、Logo、域名）",
		}
		if err := h.db.Create(&config).Error; err != nil {
			h.logger.Error("创建站点配置失败", zap.Error(err))
			InternalError(c, "创建配置失败")
			return
		}
	}

	SuccessWithMessage(c, "Logo 上传成功", gin.H{
		"logo_url": logoURL,
	})
}

// GetLogo 获取 Logo 文件
// GET /api/v1/system-config/logo/:filename
func (h *SystemConfigHandler) GetLogo(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		BadRequest(c, "文件名不能为空")
		return
	}

	// 安全检查：防止路径遍历
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		BadRequest(c, "无效的文件名")
		return
	}

	filePath := filepath.Join(h.uploadDir, filename)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		NotFound(c, "文件不存在")
		return
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		h.logger.Error("打开 Logo 文件失败", zap.Error(err))
		InternalError(c, "读取文件失败")
		return
	}
	defer file.Close()

	// 设置响应头
	c.Header("Content-Type", "image/"+strings.TrimPrefix(filepath.Ext(filename), "."))
	c.Header("Cache-Control", "public, max-age=31536000") // 缓存1年

	// 返回文件内容
	_, _ = io.Copy(c.Writer, file)
}

// GetAlertConfig 获取告警配置
// GET /api/v1/system-config/alert
func (h *SystemConfigHandler) GetAlertConfig(c *gin.Context) {
	defaultConfig := model.DefaultAlertConfig()

	var config model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "alert_config", "alert").First(&config)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			h.logger.Debug("告警配置不存在，使用默认配置")
		} else {
			h.logger.Warn("查询告警配置失败，使用默认配置", zap.Error(result.Error))
		}
		Success(c, defaultConfig)
		return
	}

	if config.Value == "" {
		Success(c, defaultConfig)
		return
	}

	var alertConfig model.AlertConfig
	if err := json.Unmarshal([]byte(config.Value), &alertConfig); err != nil {
		h.logger.Warn("解析告警配置失败，使用默认配置", zap.Error(err))
		Success(c, defaultConfig)
		return
	}

	// 验证配置有效性
	if alertConfig.RepeatAlertInterval <= 0 {
		alertConfig.RepeatAlertInterval = defaultConfig.RepeatAlertInterval
	}

	Success(c, alertConfig)
}

// UpdateAlertConfigRequest 更新告警配置请求
type UpdateAlertConfigRequest struct {
	RepeatAlertInterval   int  `json:"repeat_alert_interval" binding:"required,min=1"`
	EnablePeriodicSummary bool `json:"enable_periodic_summary"`
}

// UpdateAlertConfig 更新告警配置
// PUT /api/v1/system-config/alert
func (h *SystemConfigHandler) UpdateAlertConfig(c *gin.Context) {
	var req UpdateAlertConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	alertConfig := model.AlertConfig{
		RepeatAlertInterval:   req.RepeatAlertInterval,
		EnablePeriodicSummary: req.EnablePeriodicSummary,
	}

	valueJSON, err := json.Marshal(alertConfig)
	if err != nil {
		h.logger.Error("序列化告警配置失败", zap.Error(err))
		InternalError(c, "序列化配置失败")
		return
	}

	var existingConfig model.SystemConfig
	result := h.db.Where("`key` = ? AND category = ?", "alert_config", "alert").First(&existingConfig)

	if result.Error == nil {
		// 更新现有配置
		if err := h.db.Model(&existingConfig).Updates(map[string]interface{}{
			"value":       string(valueJSON),
			"description": "告警配置（重复告警间隔、定期汇总开关）",
		}).Error; err != nil {
			h.logger.Error("更新告警配置失败", zap.Error(err))
			InternalError(c, "更新配置失败")
			return
		}
		h.logger.Info("告警配置更新成功",
			zap.Int("repeat_alert_interval", req.RepeatAlertInterval),
			zap.Bool("enable_periodic_summary", req.EnablePeriodicSummary),
		)
	} else if result.Error == gorm.ErrRecordNotFound {
		// 创建新配置
		config := model.SystemConfig{
			Key:         "alert_config",
			Category:    "alert",
			Value:       string(valueJSON),
			Description: "告警配置（重复告警间隔、定期汇总开关）",
		}
		if err := h.db.Create(&config).Error; err != nil {
			h.logger.Error("创建告警配置失败", zap.Error(err))
			InternalError(c, "创建配置失败")
			return
		}
		h.logger.Info("告警配置创建成功",
			zap.Int("repeat_alert_interval", req.RepeatAlertInterval),
			zap.Bool("enable_periodic_summary", req.EnablePeriodicSummary),
		)
	} else {
		h.logger.Error("查询告警配置失败", zap.Error(result.Error))
		InternalError(c, "查询配置失败")
		return
	}

	SuccessWithMessage(c, "配置更新成功", alertConfig)
}
