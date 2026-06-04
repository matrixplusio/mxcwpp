// Package api 提供 HTTP API 处理器
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/common/signing"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ComponentsHandler 组件管理 API 处理器
type ComponentsHandler struct {
	db          *gorm.DB
	logger      *zap.Logger
	cfg         *config.Config  // Server 配置
	uploadDir   string          // 上传文件存储目录
	urlPrefix   string          // 文件访问 URL 前缀
	signer      *signing.Signer // Ed25519 签名器（可选）
	downloadSem chan struct{}   // 并发下载信号量，限制同时下载数
}

// NewComponentsHandler 创建组件管理处理器
func NewComponentsHandler(db *gorm.DB, logger *zap.Logger, cfg *config.Config, uploadDir, urlPrefix string) *ComponentsHandler {
	// 确保上传目录存在
	packagesDir := filepath.Join(uploadDir, "packages")
	if err := os.MkdirAll(packagesDir, 0755); err != nil {
		logger.Error("创建组件包上传目录失败", zap.Error(err))
	}
	pluginsDir := filepath.Join(uploadDir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		logger.Error("创建插件上传目录失败", zap.Error(err))
	}
	concurrency := 50
	if cfg != nil && cfg.Plugins.DownloadConcurrency > 0 {
		concurrency = cfg.Plugins.DownloadConcurrency
	}
	handler := &ComponentsHandler{
		db:          db,
		logger:      logger,
		cfg:         cfg,
		uploadDir:   uploadDir,
		urlPrefix:   urlPrefix,
		downloadSem: make(chan struct{}, concurrency),
	}
	logger.Info("插件下载并发上限已加载", zap.Int("download_concurrency", concurrency))

	// 初始化签名器（如果配置了私钥）
	if cfg != nil && cfg.Plugins.SignPrivateKey != "" {
		signer, err := signing.NewSignerFromFile(cfg.Plugins.SignPrivateKey)
		if err != nil {
			logger.Error("初始化插件签名器失败", zap.String("key_path", cfg.Plugins.SignPrivateKey), zap.Error(err))
		} else {
			handler.signer = signer
			logger.Info("插件签名器初始化成功")
		}
	}

	return handler
}

// ==================== 组件管理 API ====================

// CreateComponentRequest 创建组件请求
type CreateComponentRequest struct {
	Name        string `json:"name" binding:"required"`     // 组件名称
	Category    string `json:"category" binding:"required"` // 分类: agent, plugin
	Description string `json:"description"`                 // 描述
}

// CreateComponent 创建组件
// POST /api/v1/components
func (h *ComponentsHandler) CreateComponent(c *gin.Context) {
	var req CreateComponentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 验证组件名称（只允许字母、数字、下划线、横线）
	if !isValidComponentName(req.Name) {
		BadRequest(c, "组件名称只能包含字母、数字、下划线和横线")
		return
	}

	// 验证分类
	if req.Category != "agent" && req.Category != "plugin" && req.Category != "dependency" {
		BadRequest(c, "无效的组件分类，支持: agent, plugin, dependency")
		return
	}

	// 检查是否已存在
	var existingCount int64
	h.db.Model(&model.Component{}).Where("name = ?", req.Name).Count(&existingCount)
	if existingCount > 0 {
		Conflict(c, fmt.Sprintf("组件 %s 已存在", req.Name))
		return
	}

	// 获取当前用户
	username := h.getCurrentUser(c)

	// 创建组件
	component := model.Component{
		Name:        req.Name,
		Category:    model.ComponentCategory(req.Category),
		Description: req.Description,
		CreatedBy:   username,
	}

	if err := h.db.Create(&component).Error; err != nil {
		h.logger.Error("创建组件失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	h.logger.Info("创建组件成功",
		zap.String("name", req.Name),
		zap.String("category", req.Category),
		zap.String("created_by", username),
	)

	SuccessWithMessage(c, "创建成功", component)
}

// ListComponents 获取组件列表
// GET /api/v1/components
func (h *ComponentsHandler) ListComponents(c *gin.Context) {
	var components []model.Component
	if err := h.db.Order("created_at DESC").Find(&components).Error; err != nil {
		h.logger.Error("查询组件列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 构建带统计信息的响应
	var result []gin.H
	for _, comp := range components {
		// 获取最新版本
		var latestVersion model.ComponentVersion
		h.db.Where("component_id = ? AND is_latest = ?", comp.ID, true).First(&latestVersion)

		// 获取版本数量
		var versionCount int64
		h.db.Model(&model.ComponentVersion{}).Where("component_id = ?", comp.ID).Count(&versionCount)

		// 获取包数量
		var packageCount int64
		h.db.Model(&model.ComponentPackage{}).
			Joins("JOIN component_versions ON component_versions.id = component_packages.version_id").
			Where("component_versions.component_id = ?", comp.ID).
			Count(&packageCount)

		result = append(result, gin.H{
			"id":             comp.ID,
			"name":           comp.Name,
			"category":       comp.Category,
			"description":    comp.Description,
			"created_by":     comp.CreatedBy,
			"created_at":     comp.CreatedAt,
			"latest_version": latestVersion.Version,
			"version_count":  versionCount,
			"package_count":  packageCount,
		})
	}

	Success(c, result)
}

// GetComponent 获取组件详情
// GET /api/v1/components/:id
func (h *ComponentsHandler) GetComponent(c *gin.Context) {
	id := c.Param("id")

	var component model.Component
	if err := h.db.First(&component, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "组件不存在")
			return
		}
		h.logger.Error("查询组件详情失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, component)
}

// DeleteComponent 删除组件
// DELETE /api/v1/components/:id
func (h *ComponentsHandler) DeleteComponent(c *gin.Context) {
	id := c.Param("id")

	var component model.Component
	if err := h.db.First(&component, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "组件不存在")
			return
		}
		h.logger.Error("查询组件失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	// 检查是否有版本
	var versionCount int64
	h.db.Model(&model.ComponentVersion{}).Where("component_id = ?", component.ID).Count(&versionCount)
	if versionCount > 0 {
		BadRequest(c, fmt.Sprintf("组件下有 %d 个版本，请先删除所有版本", versionCount))
		return
	}

	// 删除组件
	if err := h.db.Delete(&component).Error; err != nil {
		h.logger.Error("删除组件失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	h.logger.Info("删除组件成功",
		zap.Uint("id", component.ID),
		zap.String("name", component.Name),
	)

	SuccessMessage(c, "删除成功")
}

// ==================== 版本管理 API ====================

// ReleaseVersionRequest 发布版本请求
type ReleaseVersionRequest struct {
	Version   string `json:"version" binding:"required"` // 版本号
	Changelog string `json:"changelog"`                  // 更新日志
	SetLatest bool   `json:"set_latest"`                 // 是否设为最新版本
	Force     bool   `json:"force"`                      // 是否强制覆盖已存在的版本
}

// ReleaseVersion 发布新版本（仅创建版本记录，包文件单独上传）
// POST /api/v1/components/:id/versions
func (h *ComponentsHandler) ReleaseVersion(c *gin.Context) {
	componentID := c.Param("id")

	var req ReleaseVersionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 验证版本号格式
	if !isValidVersion(req.Version) {
		BadRequest(c, "版本号格式不正确，例如: 1.0.0 或 1.8.5.31")
		return
	}

	// 查找组件
	var component model.Component
	if err := h.db.First(&component, componentID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "组件不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	// 检查版本是否已存在
	var existingVersion model.ComponentVersion
	existErr := h.db.Where("component_id = ? AND version = ?", component.ID, req.Version).First(&existingVersion).Error
	if existErr == nil {
		// 版本已存在
		if !req.Force {
			Conflict(c, fmt.Sprintf("版本 %s 已存在，如需覆盖请设置 force=true", req.Version))
			return
		}

		// force=true，删除旧版本及其包文件
		h.logger.Info("强制覆盖版本，删除旧版本",
			zap.String("component", component.Name),
			zap.String("version", req.Version),
		)

		// 查找并删除关联的包文件
		var packages []model.ComponentPackage
		h.db.Where("version_id = ?", existingVersion.ID).Find(&packages)
		for _, pkg := range packages {
			if err := os.Remove(pkg.FilePath); err != nil && !os.IsNotExist(err) {
				h.logger.Warn("删除旧包文件失败", zap.Error(err), zap.String("path", pkg.FilePath))
			}
		}
		// 删除数据库中的包记录
		h.db.Where("version_id = ?", existingVersion.ID).Delete(&model.ComponentPackage{})
		// 删除旧版本记录
		h.db.Delete(&existingVersion)
	} else if existErr != gorm.ErrRecordNotFound {
		h.logger.Error("查询版本失败", zap.Error(existErr))
		InternalError(c, "查询失败")
		return
	}

	// 获取当前用户
	username := h.getCurrentUser(c)

	// 开始事务
	tx := h.db.Begin()

	// 如果设为最新版本，先将其他版本的 is_latest 设为 false
	if req.SetLatest {
		if err := tx.Model(&model.ComponentVersion{}).
			Where("component_id = ?", component.ID).
			Update("is_latest", false).Error; err != nil {
			tx.Rollback()
			h.logger.Error("更新最新版本状态失败", zap.Error(err))
			InternalError(c, "发布失败")
			return
		}
	}

	// 创建版本
	version := model.ComponentVersion{
		ComponentID: component.ID,
		Version:     req.Version,
		Changelog:   req.Changelog,
		IsLatest:    req.SetLatest,
		CreatedBy:   username,
	}

	if err := tx.Create(&version).Error; err != nil {
		tx.Rollback()
		h.logger.Error("创建版本失败", zap.Error(err))
		InternalError(c, "发布失败")
		return
	}

	tx.Commit()

	h.logger.Info("发布版本成功",
		zap.String("component", component.Name),
		zap.String("version", req.Version),
		zap.String("created_by", username),
	)

	SuccessWithMessage(c, "发布成功", version)
}

// ListVersions 获取组件的版本列表
// GET /api/v1/components/:id/versions
func (h *ComponentsHandler) ListVersions(c *gin.Context) {
	componentID := c.Param("id")

	// 验证组件存在
	var component model.Component
	if err := h.db.First(&component, componentID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "组件不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	// 查询版本列表
	var versions []model.ComponentVersion
	if err := h.db.Where("component_id = ?", component.ID).
		Order("created_at DESC").
		Find(&versions).Error; err != nil {
		h.logger.Error("查询版本列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 构建带包信息的响应
	var result []gin.H
	for _, ver := range versions {
		// 获取该版本的所有包
		var packages []model.ComponentPackage
		h.db.Where("version_id = ?", ver.ID).Find(&packages)

		// 构建包摘要
		packagesSummary := make([]gin.H, 0)
		for _, pkg := range packages {
			packagesSummary = append(packagesSummary, gin.H{
				"id":        pkg.ID,
				"arch":      pkg.Arch,
				"pkg_type":  pkg.PkgType,
				"file_size": pkg.FileSize,
				"sha256":    pkg.SHA256,
			})
		}

		result = append(result, gin.H{
			"id":               ver.ID,
			"version":          ver.Version,
			"changelog":        ver.Changelog,
			"is_latest":        ver.IsLatest,
			"created_by":       ver.CreatedBy,
			"created_at":       ver.CreatedAt,
			"packages":         packagesSummary,
			"packages_summary": buildPackagesSummary(packages),
		})
	}

	Success(c, gin.H{
		"component": component,
		"versions":  result,
	})
}

// GetVersion 获取版本详情
// GET /api/v1/components/:id/versions/:version_id
func (h *ComponentsHandler) GetVersion(c *gin.Context) {
	versionID := c.Param("version_id")

	var version model.ComponentVersion
	if err := h.db.Preload("Packages").First(&version, versionID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "版本不存在")
			return
		}
		h.logger.Error("查询版本详情失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, version)
}

// SetLatestVersion 设置为最新版本
// PUT /api/v1/components/:id/versions/:version_id/set-latest
func (h *ComponentsHandler) SetLatestVersion(c *gin.Context) {
	componentID := c.Param("id")
	versionID := c.Param("version_id")

	var version model.ComponentVersion
	if err := h.db.First(&version, versionID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "版本不存在")
			return
		}
		h.logger.Error("查询版本失败", zap.Error(err))
		InternalError(c, "设置失败")
		return
	}

	// 使用事务更新
	tx := h.db.Begin()

	// 将同组件的其他版本设为非最新
	if err := tx.Model(&model.ComponentVersion{}).
		Where("component_id = ?", componentID).
		Update("is_latest", false).Error; err != nil {
		tx.Rollback()
		h.logger.Error("更新最新版本状态失败", zap.Error(err))
		InternalError(c, "设置失败")
		return
	}

	// 将当前版本设为最新
	if err := tx.Model(&version).Update("is_latest", true).Error; err != nil {
		tx.Rollback()
		h.logger.Error("设置最新版本失败", zap.Error(err))
		InternalError(c, "设置失败")
		return
	}

	tx.Commit()

	// 同步更新插件配置（如果是插件）
	var component model.Component
	if err := h.db.First(&component, componentID).Error; err == nil {
		if component.Category == model.ComponentCategoryPlugin {
			h.logger.Info("设置最新版本后同步插件配置",
				zap.String("component_name", component.Name),
				zap.String("version", version.Version),
				zap.Uint("version_id", version.ID),
				zap.Bool("is_latest", true),
			)
			h.syncPluginConfigForVersion(&version, component.Name)
		} else {
			h.logger.Debug("组件不是插件类型，跳过同步插件配置",
				zap.String("component_name", component.Name),
				zap.String("category", string(component.Category)),
			)
		}
	} else {
		h.logger.Warn("查询组件失败，无法同步插件配置",
			zap.Uint("component_id", version.ComponentID),
			zap.Error(err),
		)
	}

	h.logger.Info("设置最新版本成功",
		zap.Uint("version_id", version.ID),
		zap.String("version", version.Version),
	)

	SuccessMessage(c, "设置成功")
}

// DeleteVersion 删除版本
// DELETE /api/v1/components/:id/versions/:version_id
func (h *ComponentsHandler) DeleteVersion(c *gin.Context) {
	versionID := c.Param("version_id")

	var version model.ComponentVersion
	if err := h.db.First(&version, versionID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "版本不存在")
			return
		}
		h.logger.Error("查询版本失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	// 删除该版本的所有包文件
	var packages []model.ComponentPackage
	h.db.Where("version_id = ?", version.ID).Find(&packages)
	for _, pkg := range packages {
		if err := os.Remove(pkg.FilePath); err != nil && !os.IsNotExist(err) {
			h.logger.Warn("删除包文件失败", zap.Error(err), zap.String("path", pkg.FilePath))
		}
	}

	// 删除数据库中的包记录
	h.db.Where("version_id = ?", version.ID).Delete(&model.ComponentPackage{})

	// 删除版本记录
	if err := h.db.Delete(&version).Error; err != nil {
		h.logger.Error("删除版本记录失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	h.logger.Info("删除版本成功",
		zap.Uint("id", version.ID),
		zap.String("version", version.Version),
	)

	SuccessMessage(c, "删除成功")
}

// ==================== 包上传 API ====================

// UploadPackage 上传包文件到指定版本
// POST /api/v1/components/:id/versions/:version_id/packages
func (h *ComponentsHandler) UploadPackage(c *gin.Context) {
	componentID := c.Param("id")
	versionID := c.Param("version_id")

	// 获取表单参数
	pkgType := c.PostForm("pkg_type") // rpm, deb, binary
	arch := c.PostForm("arch")        // amd64, arm64
	force := c.PostForm("force")      // 是否强制覆盖

	// 验证参数
	if arch != "amd64" && arch != "arm64" {
		BadRequest(c, "无效的架构，支持: amd64, arm64")
		return
	}

	if pkgType != "rpm" && pkgType != "deb" && pkgType != "binary" && pkgType != "tgz" {
		BadRequest(c, "无效的包类型，支持: rpm, deb, binary, tgz")
		return
	}

	// 查找组件
	var component model.Component
	if err := h.db.First(&component, componentID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "组件不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	// Agent 必须是 rpm/deb，插件可以是 binary
	if component.Category == model.ComponentCategoryAgent && pkgType != "rpm" && pkgType != "deb" {
		BadRequest(c, "Agent 包类型必须是 rpm 或 deb")
		return
	}

	// Plugin 只允许 binary
	if component.Category == model.ComponentCategoryPlugin && pkgType != "binary" {
		BadRequest(c, "插件包类型必须是 binary")
		return
	}

	// Dependency 只允许 tgz
	if component.Category == model.ComponentCategoryDependency && pkgType != "tgz" {
		BadRequest(c, "依赖包类型必须是 tgz")
		return
	}

	// 查找版本
	var version model.ComponentVersion
	if err := h.db.First(&version, versionID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "版本不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	// 检查是否已存在相同类型的包
	var existingPkg model.ComponentPackage
	err := h.db.Where("version_id = ? AND pkg_type = ? AND arch = ?", version.ID, pkgType, arch).First(&existingPkg).Error
	if err == nil {
		// 包已存在
		if force != "true" {
			Conflict(c, fmt.Sprintf("该版本已存在 %s/%s 包，如需覆盖请设置 force=true", pkgType, arch))
			return
		}

		// force=true，删除旧包文件和记录
		h.logger.Info("强制覆盖包，删除旧包",
			zap.String("component", component.Name),
			zap.String("version", version.Version),
			zap.String("pkg_type", pkgType),
			zap.String("arch", arch),
		)
		if err := os.Remove(existingPkg.FilePath); err != nil && !os.IsNotExist(err) {
			h.logger.Warn("删除旧包文件失败", zap.Error(err), zap.String("path", existingPkg.FilePath))
		}
		if err := h.db.Delete(&existingPkg).Error; err != nil {
			h.logger.Error("删除旧包记录失败", zap.Error(err))
			InternalError(c, "删除旧包失败")
			return
		}
	} else if err != gorm.ErrRecordNotFound {
		h.logger.Error("查询包失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		BadRequest(c, "请上传文件")
		return
	}
	defer file.Close()

	// 验证文件扩展名
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if pkgType == "rpm" && ext != ".rpm" {
		BadRequest(c, "RPM 包文件扩展名必须是 .rpm")
		return
	}
	if pkgType == "deb" && ext != ".deb" {
		BadRequest(c, "DEB 包文件扩展名必须是 .deb")
		return
	}
	if pkgType == "tgz" {
		lowerName := strings.ToLower(header.Filename)
		if !strings.HasSuffix(lowerName, ".tar.gz") && !strings.HasSuffix(lowerName, ".tgz") {
			BadRequest(c, "tar.gz 包文件扩展名必须是 .tar.gz 或 .tgz")
			return
		}
	}

	// 生成存储路径
	var filePath, fileName string
	if pkgType == "binary" {
		// 二进制插件文件存储到 uploads/plugins/{component}/{version}/ 目录
		pluginsDir := filepath.Join(h.uploadDir, "plugins", component.Name, version.Version)
		if err := os.MkdirAll(pluginsDir, 0755); err != nil {
			h.logger.Error("创建插件目录失败", zap.Error(err))
			InternalError(c, "保存文件失败")
			return
		}
		// 文件名格式：{name}_{arch}（例如 baseline_amd64）
		fileName = fmt.Sprintf("%s_%s", component.Name, arch)
		filePath = filepath.Join(pluginsDir, fileName)
	} else if pkgType == "tgz" {
		// tar.gz 依赖包存储到 uploads/packages/{component}/{version}/ 目录
		packagesDir := filepath.Join(h.uploadDir, "packages", component.Name, version.Version)
		if err := os.MkdirAll(packagesDir, 0755); err != nil {
			h.logger.Error("创建依赖包目录失败", zap.Error(err))
			InternalError(c, "保存文件失败")
			return
		}
		// 文件名: {name}-v{version}-{arch}.tar.gz
		fileName = fmt.Sprintf("%s-v%s-%s.tar.gz", component.Name, version.Version, arch)
		filePath = filepath.Join(packagesDir, fileName)
	} else {
		// RPM/DEB 包存储到 uploads/packages/{component}/{version}/ 目录
		packagesDir := filepath.Join(h.uploadDir, "packages", component.Name, version.Version)
		if err := os.MkdirAll(packagesDir, 0755); err != nil {
			h.logger.Error("创建组件包目录失败", zap.Error(err))
			InternalError(c, "保存文件失败")
			return
		}
		fileName = fmt.Sprintf("mxsec-%s-%s-linux-%s.%s", component.Name, version.Version, arch, pkgType)
		filePath = filepath.Join(packagesDir, fileName)
	}

	// 创建目标文件
	dst, err := os.Create(filePath)
	if err != nil {
		h.logger.Error("创建文件失败", zap.Error(err))
		InternalError(c, "保存文件失败")
		return
	}
	defer dst.Close()

	// 同时计算 SHA256 和写入文件
	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)
	fileSize, err := io.Copy(writer, file)
	if err != nil {
		os.Remove(filePath)
		h.logger.Error("写入文件失败", zap.Error(err))
		InternalError(c, "保存文件失败")
		return
	}

	sha256Sum := hex.EncodeToString(hasher.Sum(nil))

	// 获取当前用户
	username := h.getCurrentUser(c)

	// 创建数据库记录
	pkg := model.ComponentPackage{
		VersionID:  version.ID,
		OS:         "linux",
		Arch:       arch,
		PkgType:    model.PackageType(pkgType),
		FilePath:   filePath,
		FileName:   header.Filename,
		FileSize:   fileSize,
		SHA256:     sha256Sum,
		Enabled:    true,
		UploadedBy: username,
		UploadedAt: model.Now(),
	}

	if err := h.db.Create(&pkg).Error; err != nil {
		os.Remove(filePath)
		h.logger.Error("创建包记录失败", zap.Error(err))
		InternalError(c, "保存失败")
		return
	}

	h.logger.Info("上传包成功",
		zap.String("component", component.Name),
		zap.String("version", version.Version),
		zap.String("pkg_type", pkgType),
		zap.String("arch", arch),
		zap.Int64("file_size", fileSize),
	)

	// 如果是插件，尝试同步更新插件配置
	// 注意：这里需要重新查询版本以获取最新的 is_latest 状态
	if component.Category == model.ComponentCategoryPlugin {
		var currentVersion model.ComponentVersion
		if err := h.db.First(&currentVersion, version.ID).Error; err == nil {
			if currentVersion.IsLatest {
				h.logger.Info("上传包后同步插件配置",
					zap.String("component_name", component.Name),
					zap.String("version", currentVersion.Version),
					zap.Uint("version_id", currentVersion.ID),
					zap.Bool("is_latest", currentVersion.IsLatest),
					zap.String("package_arch", pkg.Arch),
					zap.String("package_sha256", pkg.SHA256[:16]+"..."),
				)
				h.syncPluginConfigForVersion(&currentVersion, component.Name)
			} else {
				h.logger.Warn("版本不是最新版本，跳过同步插件配置",
					zap.String("component_name", component.Name),
					zap.String("version", currentVersion.Version),
					zap.Uint("version_id", currentVersion.ID),
					zap.Bool("is_latest", currentVersion.IsLatest),
					zap.String("hint", "如需同步，请先调用 SetLatestVersion API 将此版本设为最新版本"),
				)
			}
		} else {
			h.logger.Error("查询版本失败，无法同步插件配置",
				zap.String("component_name", component.Name),
				zap.Uint("version_id", version.ID),
				zap.Error(err),
			)
		}
	} else {
		h.logger.Debug("组件不是插件类型，跳过同步",
			zap.String("component_name", component.Name),
			zap.String("category", string(component.Category)),
		)
	}

	SuccessWithMessage(c, "上传成功", pkg)
}

// DeletePackage 删除包
// DELETE /api/v1/packages/:id
func (h *ComponentsHandler) DeletePackage(c *gin.Context) {
	id := c.Param("id")

	var pkg model.ComponentPackage
	if err := h.db.First(&pkg, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "包不存在")
			return
		}
		h.logger.Error("查询包失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	// 删除文件
	if err := os.Remove(pkg.FilePath); err != nil && !os.IsNotExist(err) {
		h.logger.Warn("删除包文件失败", zap.Error(err), zap.String("path", pkg.FilePath))
	}

	// 删除数据库记录
	if err := h.db.Delete(&pkg).Error; err != nil {
		h.logger.Error("删除包记录失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	h.logger.Info("删除包成功", zap.Uint("id", pkg.ID))

	SuccessMessage(c, "删除成功")
}

// ==================== 下载 API ====================

// DownloadAgentPackage 下载 Agent 安装包 (无需认证)
// GET /api/v1/agent/download/:pkg_type/:arch
func (h *ComponentsHandler) DownloadAgentPackage(c *gin.Context) {
	pkgType := c.Param("pkg_type")
	arch := c.Param("arch")

	// 验证参数
	if pkgType != "rpm" && pkgType != "deb" {
		BadRequest(c, "无效的包类型，支持: rpm, deb")
		return
	}

	if arch != "amd64" && arch != "arm64" {
		BadRequest(c, "无效的架构，支持: amd64, arm64")
		return
	}

	// 查找 agent 组件
	var component model.Component
	if err := h.db.Where("name = ?", "agent").First(&component).Error; err != nil {
		NotFound(c, "Agent 组件不存在")
		return
	}

	// 查找最新版本
	var latestVersion model.ComponentVersion
	if err := h.db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&latestVersion).Error; err != nil {
		// 如果没有标记为最新的，尝试获取最新上传的
		if err := h.db.Where("component_id = ?", component.ID).
			Order("created_at DESC").First(&latestVersion).Error; err != nil {
			NotFound(c, "未找到 Agent 版本")
			return
		}
	}

	// 查找对应的包
	var pkg model.ComponentPackage
	if err := h.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
		latestVersion.ID, pkgType, arch, true).First(&pkg).Error; err != nil {
		NotFound(c, fmt.Sprintf("未找到 Agent %s 包 (%s)", pkgType, arch))
		return
	}

	// 检查文件是否存在
	fileInfo, err := os.Stat(pkg.FilePath)
	if os.IsNotExist(err) {
		h.logger.Error("Agent 包文件不存在", zap.String("path", pkg.FilePath))
		NotFound(c, "文件不存在")
		return
	}

	// 大文件下载需要延长写超时，避免被 Manager 全局 WriteTimeout(30s) 切断
	// 之前 agent 拿到截断的 RPM → sha256 不匹配 → 升级失败 → scheduler 反复重试。
	// 按文件大小估算：1 MB/s 下限 + 60s 余量；不少于 5 分钟。
	deadline := time.Duration(fileInfo.Size()/(1024*1024)+60) * time.Second
	if deadline < 5*time.Minute {
		deadline = 5 * time.Minute
	}
	rc := http.NewResponseController(c.Writer)
	if err := rc.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
		h.logger.Warn("设置 Agent 包下载写超时失败，使用默认超时", zap.Error(err))
	}

	// 设置下载响应头
	fileName := fmt.Sprintf("mxsec-agent-%s.%s", latestVersion.Version, pkgType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	c.Header("X-Package-Version", latestVersion.Version)
	c.Header("X-Package-SHA256", pkg.SHA256)

	// 发送文件
	c.File(pkg.FilePath)

	h.logger.Info("Agent 包下载",
		zap.String("version", latestVersion.Version),
		zap.String("pkg_type", pkgType),
		zap.String("arch", arch),
		zap.String("client_ip", c.ClientIP()),
	)
}

// CheckAgentUpdate 检查 Agent 是否有可用更新 (无需认证，供 Agent CLI 调用)
// GET /api/v1/agent/update-check?arch=amd64&current_version=1.0.0&pkg_type=rpm
func (h *ComponentsHandler) CheckAgentUpdate(c *gin.Context) {
	arch := c.DefaultQuery("arch", "amd64")
	currentVersion := c.DefaultQuery("current_version", "")
	pkgType := c.DefaultQuery("pkg_type", "rpm")

	// 验证参数
	if arch != "amd64" && arch != "arm64" {
		BadRequest(c, "无效的架构，支持: amd64, arm64")
		return
	}
	if pkgType != "rpm" && pkgType != "deb" {
		BadRequest(c, "无效的包类型，支持: rpm, deb")
		return
	}

	// 查找 agent 组件
	var component model.Component
	if err := h.db.Where("name = ?", "agent").First(&component).Error; err != nil {
		NotFound(c, "Agent 组件不存在")
		return
	}

	// 查找最新版本
	var latestVersion model.ComponentVersion
	if err := h.db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&latestVersion).Error; err != nil {
		if err := h.db.Where("component_id = ?", component.ID).
			Order("created_at DESC").First(&latestVersion).Error; err != nil {
			NotFound(c, "未找到 Agent 版本")
			return
		}
	}

	// 查找对应的包
	var pkg model.ComponentPackage
	if err := h.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
		latestVersion.ID, pkgType, arch, true).First(&pkg).Error; err != nil {
		NotFound(c, fmt.Sprintf("未找到 Agent %s 包 (%s)", pkgType, arch))
		return
	}

	// 判断是否有更新
	hasUpdate := currentVersion == "" || currentVersion != latestVersion.Version

	Success(c, gin.H{
		"has_update":      hasUpdate,
		"latest_version":  latestVersion.Version,
		"current_version": currentVersion,
		"download_url":    fmt.Sprintf("/api/v1/agent/download/%s/%s", pkgType, arch),
		"sha256":          pkg.SHA256,
		"pkg_type":        pkgType,
		"arch":            arch,
		"file_size":       pkg.FileSize,
	})

	h.logger.Info("Agent 更新检查",
		zap.String("current_version", currentVersion),
		zap.String("latest_version", latestVersion.Version),
		zap.Bool("has_update", hasUpdate),
		zap.String("arch", arch),
		zap.String("pkg_type", pkgType),
		zap.String("client_ip", c.ClientIP()),
	)
}

// DownloadPluginPackage 下载插件包 (供 Agent 调用)
// GET /api/v1/plugins/download/:name
func (h *ComponentsHandler) DownloadPluginPackage(c *gin.Context) {
	// 并发限制：超过 10 个同时下载时返回 429
	select {
	case h.downloadSem <- struct{}{}:
		defer func() { <-h.downloadSem }()
	default:
		TooManyRequests(c, "下载并发数已达上限，请稍后重试")
		return
	}

	name := c.Param("name")
	arch := c.DefaultQuery("arch", "amd64")

	// 验证架构
	if arch != "amd64" && arch != "arm64" {
		BadRequest(c, "无效的架构，支持: amd64, arm64")
		return
	}

	// 查找插件组件
	var component model.Component
	if err := h.db.Where("name = ? AND category = ?", name, model.ComponentCategoryPlugin).First(&component).Error; err != nil {
		NotFound(c, fmt.Sprintf("插件 %s 不存在", name))
		return
	}

	// 查找最新版本
	var latestVersion model.ComponentVersion
	if err := h.db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&latestVersion).Error; err != nil {
		if err := h.db.Where("component_id = ?", component.ID).
			Order("created_at DESC").First(&latestVersion).Error; err != nil {
			NotFound(c, fmt.Sprintf("插件 %s 没有可用版本", name))
			return
		}
	}

	// 查找对应架构的二进制包（先查指定架构，再 fallback 到 arch=all）
	var pkg model.ComponentPackage
	if err := h.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
		latestVersion.ID, "binary", arch, true).First(&pkg).Error; err != nil {
		// fallback: 查 arch=all（如 virus-database 等不分架构的包）
		if err2 := h.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
			latestVersion.ID, "binary", "all", true).First(&pkg).Error; err2 != nil {
			NotFound(c, fmt.Sprintf("插件 %s 没有 %s 架构的包", name, arch))
			return
		}
	}

	// 检查文件是否存在
	fileInfo, err := os.Stat(pkg.FilePath)
	if os.IsNotExist(err) {
		h.logger.Error("插件包文件不存在", zap.String("path", pkg.FilePath))
		NotFound(c, "文件不存在")
		return
	}

	// 大文件下载需要延长写超时，避免传输中途被 WriteTimeout 断开
	// 按实际文件大小估算：假设最低 1 MB/s + 60s 余量
	deadline := time.Duration(fileInfo.Size()/(1024*1024)+60) * time.Second
	if deadline < 5*time.Minute {
		deadline = 5 * time.Minute
	}
	rc := http.NewResponseController(c.Writer)
	if err := rc.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
		h.logger.Warn("设置写超时失败，使用默认超时", zap.Error(err))
	}

	// 设置下载响应头 - 文件名使用插件名（Agent 下载后可直接使用）
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	c.Header("X-Plugin-Name", name)
	c.Header("X-Plugin-Version", latestVersion.Version)
	c.Header("X-Plugin-SHA256", pkg.SHA256)

	// 发送文件
	c.File(pkg.FilePath)

	h.logger.Info("插件包下载",
		zap.String("name", name),
		zap.String("version", latestVersion.Version),
		zap.String("arch", arch),
		zap.String("client_ip", c.ClientIP()),
	)
}

// ==================== 插件状态 API ====================

// GetPluginSyncStatus 获取插件同步状态
// GET /api/v1/components/plugin-status
func (h *ComponentsHandler) GetPluginSyncStatus(c *gin.Context) {
	type PluginStatus struct {
		Name           string   `json:"name"`
		Type           string   `json:"type"`
		ConfigVersion  string   `json:"config_version"`
		ConfigSHA256   string   `json:"config_sha256"`
		ConfigEnabled  bool     `json:"config_enabled"`
		DownloadURLs   []string `json:"download_urls"`
		Description    string   `json:"description"`
		HasPackage     bool     `json:"has_package"`
		PackageVersion string   `json:"package_version,omitempty"`
		PackageArch    string   `json:"package_arch,omitempty"`
		Status         string   `json:"status"`
	}

	var statuses []PluginStatus

	// 查询所有插件配置
	var pluginConfigs []model.PluginConfig
	if err := h.db.Find(&pluginConfigs).Error; err != nil {
		h.logger.Error("查询插件配置失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	for _, pc := range pluginConfigs {
		status := PluginStatus{
			Name:          pc.Name,
			Type:          string(pc.Type),
			ConfigVersion: pc.Version,
			ConfigSHA256:  pc.SHA256,
			ConfigEnabled: pc.Enabled,
			DownloadURLs:  []string(pc.DownloadURLs),
			Description:   pc.Description,
			Status:        "missing_package",
		}

		// 查找对应的组件
		var component model.Component
		if err := h.db.Where("name = ?", pc.Name).First(&component).Error; err == nil {
			// 查找最新版本
			var latestVersion model.ComponentVersion
			if err := h.db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&latestVersion).Error; err == nil {
				// 查找包
				var packages []model.ComponentPackage
				h.db.Where("version_id = ? AND enabled = ?", latestVersion.ID, true).Find(&packages)

				if len(packages) > 0 {
					status.HasPackage = true
					status.PackageVersion = latestVersion.Version

					// 拼接架构信息
					archs := make([]string, len(packages))
					for i, pkg := range packages {
						archs[i] = pkg.Arch
					}
					status.PackageArch = strings.Join(archs, ", ")

					// 检查版本是否匹配
					if latestVersion.Version == pc.Version {
						status.Status = "ready"
					} else {
						status.Status = "outdated"
					}
				}
			}
		}

		// 检查是否是默认配置
		if status.Status == "missing_package" && len(pc.DownloadURLs) > 0 && strings.HasPrefix(pc.DownloadURLs[0], "file://") {
			status.Status = "default_config"
		}

		statuses = append(statuses, status)
	}

	Success(c, statuses)
}

// ==================== 辅助函数 ====================

// getCurrentUser 获取当前用户
func (h *ComponentsHandler) getCurrentUser(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		return fmt.Sprintf("%v", username)
	}
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("%v", userID)
	}
	return "admin"
}

// isValidComponentName 验证组件名称
func isValidComponentName(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// isValidVersion 验证版本号格式
func isValidVersion(version string) bool {
	if len(version) == 0 || len(version) > 32 {
		return false
	}
	// 支持格式：1.0.0, 1.0.0-beta, 1.8.5.31 等
	parts := strings.Split(version, "-")
	mainPart := parts[0]

	// 检查主版本号部分
	segments := strings.Split(mainPart, ".")
	if len(segments) < 2 || len(segments) > 4 {
		return false
	}
	for _, seg := range segments {
		if len(seg) == 0 {
			return false
		}
		for _, c := range seg {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// buildPackagesSummary 构建包摘要
func buildPackagesSummary(packages []model.ComponentPackage) string {
	if len(packages) == 0 {
		return "无"
	}

	var parts []string
	for _, pkg := range packages {
		parts = append(parts, fmt.Sprintf("%s/%s", pkg.Arch, pkg.PkgType))
	}
	return strings.Join(parts, ", ")
}

// syncPluginConfigForVersion 同步插件配置
func (h *ComponentsHandler) syncPluginConfigForVersion(version *model.ComponentVersion, componentName string) {
	h.logger.Info("开始同步插件配置",
		zap.String("name", componentName),
		zap.String("version", version.Version),
		zap.Uint("version_id", version.ID),
	)

	// 获取该版本的包（优先 amd64）
	var pkg model.ComponentPackage
	if err := h.db.Where("version_id = ? AND arch = ? AND enabled = ?", version.ID, "amd64", true).First(&pkg).Error; err != nil {
		// 如果没有 amd64，取任意一个启用的包
		if err := h.db.Where("version_id = ? AND enabled = ?", version.ID, true).First(&pkg).Error; err != nil {
			h.logger.Warn("同步插件配置失败：没有找到可用的包",
				zap.String("name", componentName),
				zap.String("version", version.Version),
				zap.Uint("version_id", version.ID),
				zap.Error(err),
			)
			return
		}
	}

	h.logger.Info("找到插件包",
		zap.String("name", componentName),
		zap.String("arch", pkg.Arch),
		zap.String("sha256", pkg.SHA256),
		zap.String("file_path", pkg.FilePath),
	)

	// 确定插件类型
	var pluginType model.PluginType
	switch componentName {
	case "baseline":
		pluginType = model.PluginTypeBaseline
	case "collector":
		pluginType = model.PluginTypeCollector
	default:
		pluginType = model.PluginType(componentName)
	}

	// 构建下载 URL（始终使用相对路径，由 AC 端根据 backend_url 动态拼接完整地址）
	downloadURL := fmt.Sprintf("/api/v1/plugins/download/%s", componentName)

	// 对 SHA256 进行签名（如果配置了签名器）
	var pluginSignature string
	if h.signer != nil && pkg.SHA256 != "" {
		sig, err := h.signer.SignSHA256(pkg.SHA256)
		if err != nil {
			h.logger.Error("插件签名失败",
				zap.String("name", componentName),
				zap.String("sha256", pkg.SHA256),
				zap.Error(err))
		} else {
			pluginSignature = sig
			h.logger.Info("插件签名成功",
				zap.String("name", componentName),
				zap.String("sha256", pkg.SHA256))
		}
	}

	// 查找或创建插件配置
	var pluginConfig model.PluginConfig
	err := h.db.Where("name = ?", componentName).First(&pluginConfig).Error

	if err == gorm.ErrRecordNotFound {
		// 创建新的插件配置
		pluginConfig = model.PluginConfig{
			Name:      componentName,
			Type:      pluginType,
			Version:   version.Version,
			SHA256:    pkg.SHA256,
			Signature: pluginSignature,
			DownloadURLs: model.StringArray{
				downloadURL,
			},
			RuntimeTypes: runtimeTypesForPlugin(componentName),
			Detail:       fmt.Sprintf(`{"updated_at": "%s"}`, time.Now().Format(time.RFC3339)),
			Enabled:      true,
			Description:  fmt.Sprintf("%s 插件 v%s", componentName, version.Version),
		}
		if err := h.db.Create(&pluginConfig).Error; err != nil {
			h.logger.Error("创建插件配置失败",
				zap.String("name", componentName),
				zap.Error(err),
			)
			return
		}
		h.logger.Info("创建插件配置成功",
			zap.String("name", componentName),
			zap.String("version", version.Version),
			zap.String("sha256", pkg.SHA256),
		)
	} else if err == nil {
		// 更新已存在的插件配置
		updates := map[string]interface{}{
			"version":       version.Version,
			"sha256":        pkg.SHA256,
			"signature":     pluginSignature,
			"download_urls": model.StringArray{downloadURL},
			"runtime_types": runtimeTypesForPlugin(componentName),
			"detail":        fmt.Sprintf(`{"updated_at": "%s"}`, time.Now().Format(time.RFC3339)),
			"enabled":       true,
			"description":   fmt.Sprintf("%s 插件 v%s", componentName, version.Version),
		}
		if err := h.db.Model(&pluginConfig).Updates(updates).Error; err != nil {
			h.logger.Error("更新插件配置失败",
				zap.String("name", componentName),
				zap.Error(err),
			)
			return
		}
		h.logger.Info("更新插件配置成功",
			zap.String("name", componentName),
			zap.String("old_version", pluginConfig.Version),
			zap.String("new_version", version.Version),
			zap.String("sha256", pkg.SHA256),
		)
	} else {
		h.logger.Error("查询插件配置失败",
			zap.String("name", componentName),
			zap.Error(err),
		)
		return
	}

	h.logger.Info("同步插件配置完成",
		zap.String("name", componentName),
		zap.String("version", version.Version),
	)
}

// PushAgentUpdate 手动推送 Agent 更新
// POST /api/v1/components/agent/push-update
func (h *ComponentsHandler) PushAgentUpdate(c *gin.Context) {
	var req struct {
		HostIDs []string `json:"host_ids"` // 主机 ID 列表，空则推送给所有在线主机
		Force   bool     `json:"force"`    // 是否强制更新（即使版本相同也更新）
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 查找 agent 组件的最新版本
	var agentComponent model.Component
	if err := h.db.Where("name = ? AND category = ?", "agent", model.ComponentCategoryAgent).First(&agentComponent).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "Agent 组件不存在")
			return
		}
		h.logger.Error("查询 Agent 组件失败", zap.Error(err))
		InternalError(c, "查询 Agent 组件失败")
		return
	}

	var latestVersion model.ComponentVersion
	if err := h.db.Where("component_id = ? AND is_latest = ?", agentComponent.ID, true).First(&latestVersion).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "未找到 Agent 最新版本")
			return
		}
		h.logger.Error("查询 Agent 最新版本失败", zap.Error(err))
		InternalError(c, "查询 Agent 最新版本失败")
		return
	}

	// 查询需要更新的主机（排除容器环境，容器应通过重建镜像更新）
	var hosts []model.Host
	query := h.db.Where("status = ? AND is_container = ?", model.HostStatusOnline, false)
	if len(req.HostIDs) > 0 {
		query = query.Where("host_id IN ?", req.HostIDs)
	}
	if err := query.Find(&hosts).Error; err != nil {
		h.logger.Error("查询主机失败", zap.Error(err))
		InternalError(c, "查询主机失败")
		return
	}

	// 统计被跳过的容器主机数量
	var containerCount int64
	containerQuery := h.db.Model(&model.Host{}).Where("status = ? AND is_container = ?", model.HostStatusOnline, true)
	if len(req.HostIDs) > 0 {
		containerQuery = containerQuery.Where("host_id IN ?", req.HostIDs)
	}
	containerQuery.Count(&containerCount)

	if len(hosts) == 0 {
		msg := "没有需要更新的在线主机"
		if containerCount > 0 {
			msg = fmt.Sprintf("没有需要更新的在线主机（已跳过 %d 台容器主机，容器环境请通过重建镜像更新）", containerCount)
		}
		SuccessWithMessage(c, msg, gin.H{
			"total":             0,
			"success":           0,
			"failed":            0,
			"skipped_container": containerCount,
			"latest_version":    latestVersion.Version,
		})
		return
	}

	// 确定目标主机列表
	targetType := "all"
	if len(req.HostIDs) > 0 {
		targetType = "selected"
	}

	// 构建目标主机 ID 列表（所有在线主机）
	var targetHostIDs []string
	for _, host := range hosts {
		targetHostIDs = append(targetHostIDs, host.HostID)
	}

	// 统计实际需要更新的主机数量
	needUpdateCount := 0
	for _, host := range hosts {
		if req.Force || host.AgentVersion == "" || host.AgentVersion != latestVersion.Version {
			needUpdateCount++
		}
	}

	pushRecord := model.ComponentPushRecord{
		ComponentID:   agentComponent.ID,
		ComponentName: "agent",
		Version:       latestVersion.Version,
		TargetType:    targetType,
		TargetHosts:   model.StringArray(targetHostIDs),
		Status:        model.ComponentPushStatusPending,
		TotalCount:    len(targetHostIDs),
		SuccessCount:  0,
		FailedCount:   0,
		Force:         req.Force, // 保存 force 标志
		Message:       fmt.Sprintf("推送 Agent 更新到 %d 台主机（需要更新: %d，强制: %v）", len(targetHostIDs), needUpdateCount, req.Force),
		CreatedBy:     h.getCurrentUser(c),
	}

	if err := h.db.Create(&pushRecord).Error; err != nil {
		h.logger.Error("创建推送记录失败", zap.Error(err))
		InternalError(c, "创建推送记录失败")
		return
	}

	h.logger.Info("创建推送记录成功",
		zap.Uint("record_id", pushRecord.ID),
		zap.Int("total_count", pushRecord.TotalCount))

	h.logger.Info("Agent 更新推送请求",
		zap.Uint("record_id", pushRecord.ID),
		zap.Int("total_hosts", len(hosts)),
		zap.Int("need_update", needUpdateCount),
		zap.Int64("skipped_container", containerCount),
		zap.String("latest_version", latestVersion.Version),
		zap.Bool("force", req.Force))

	msg := "推送任务已创建，AgentCenter 将在 30 秒内开始推送"
	if containerCount > 0 {
		msg = fmt.Sprintf("推送任务已创建，AgentCenter 将在 30 秒内开始推送（已跳过 %d 台容器主机）", containerCount)
	}

	SuccessWithMessage(c, msg, gin.H{
		"record_id":         pushRecord.ID,
		"total":             len(hosts),
		"need_update":       needUpdateCount,
		"skipped_container": containerCount,
		"latest_version":    latestVersion.Version,
	})
}

// ListPushRecords 获取推送记录列表
// GET /api/v1/components/push-records
func (h *ComponentsHandler) ListPushRecords(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	componentName := c.Query("component_name")
	status := c.Query("status")

	query := h.db.Model(&model.ComponentPushRecord{})

	// 过滤条件
	if componentName != "" {
		query = query.Where("component_name = ?", componentName)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// 查询总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询推送记录总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 查询列表
	var records []model.ComponentPushRecord
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&records).Error; err != nil {
		h.logger.Error("查询推送记录列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 计算进度并构建响应
	var response []map[string]interface{}
	for _, record := range records {
		progress := 0.0
		if record.TotalCount > 0 {
			progress = float64(record.SuccessCount+record.FailedCount) / float64(record.TotalCount) * 100
		}

		item := map[string]interface{}{
			"id":             record.ID,
			"component_name": record.ComponentName,
			"version":        record.Version,
			"target_type":    record.TargetType,
			"target_hosts":   record.TargetHosts,
			"status":         string(record.Status),
			"total_count":    record.TotalCount,
			"success_count":  record.SuccessCount,
			"failed_count":   record.FailedCount,
			"failed_hosts":   record.FailedHosts,
			"progress":       progress,
			"message":        record.Message,
			"created_by":     record.CreatedBy,
			"created_at":     record.CreatedAt.Time().Format("2006-01-02 15:04:05"),
			"updated_at":     record.UpdatedAt.Time().Format("2006-01-02 15:04:05"),
			"completed_at":   nil,
		}
		if record.CompletedAt != nil {
			item["completed_at"] = record.CompletedAt.Time().Format("2006-01-02 15:04:05")
		}
		response = append(response, item)
	}

	SuccessPaginated(c, total, response)
}

// GetPushRecord 获取推送记录详情
// GET /api/v1/components/push-records/:id
func (h *ComponentsHandler) GetPushRecord(c *gin.Context) {
	id := c.Param("id")
	recordID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		BadRequest(c, "无效的记录 ID")
		return
	}

	var record model.ComponentPushRecord
	if err := h.db.First(&record, recordID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "推送记录不存在")
			return
		}
		h.logger.Error("查询推送记录失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 计算进度
	progress := 0.0
	if record.TotalCount > 0 {
		progress = float64(record.SuccessCount+record.FailedCount) / float64(record.TotalCount) * 100
	}

	// 查询主机推送详情
	var pushHosts []model.ComponentPushHost
	h.db.Where("record_id = ?", record.ID).Order("status DESC, hostname ASC").Find(&pushHosts)

	response := map[string]interface{}{
		"id":             record.ID,
		"component_name": record.ComponentName,
		"version":        record.Version,
		"target_type":    record.TargetType,
		"target_hosts":   record.TargetHosts,
		"status":         string(record.Status),
		"total_count":    record.TotalCount,
		"success_count":  record.SuccessCount,
		"failed_count":   record.FailedCount,
		"failed_hosts":   record.FailedHosts,
		"progress":       progress,
		"message":        record.Message,
		"created_by":     record.CreatedBy,
		"created_at":     record.CreatedAt.Time().Format("2006-01-02 15:04:05"),
		"updated_at":     record.UpdatedAt.Time().Format("2006-01-02 15:04:05"),
		"completed_at":   nil,
		"push_hosts":     pushHosts,
	}
	if record.CompletedAt != nil {
		response["completed_at"] = record.CompletedAt.Time().Format("2006-01-02 15:04:05")
	}

	Success(c, response)
}

// SyncAllPluginsToLatest 同步所有插件配置到最新版本
// POST /api/v1/components/plugins/sync-latest
func (h *ComponentsHandler) SyncAllPluginsToLatest(c *gin.Context) {
	h.logger.Info("收到同步所有插件到最新版本的请求")

	// 查询所有插件组件
	var components []model.Component
	if err := h.db.Where("category = ?", model.ComponentCategoryPlugin).Find(&components).Error; err != nil {
		h.logger.Error("查询插件组件失败", zap.Error(err))
		InternalError(c, "查询插件组件失败")
		return
	}

	if len(components) == 0 {
		SuccessWithMessage(c, "没有找到插件组件", gin.H{
			"synced_count": 0,
		})
		return
	}

	// 对每个插件，同步到最新版本
	syncedCount := 0
	var syncResults []map[string]interface{}

	for _, component := range components {
		// 查询最新版本
		var latestVersion model.ComponentVersion
		if err := h.db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&latestVersion).Error; err != nil {
			h.logger.Warn("未找到插件的最新版本",
				zap.String("plugin_name", component.Name),
				zap.Error(err))
			syncResults = append(syncResults, map[string]interface{}{
				"name":    component.Name,
				"success": false,
				"error":   "未找到最新版本",
			})
			continue
		}

		// 调用同步方法
		h.logger.Info("同步插件到最新版本",
			zap.String("plugin_name", component.Name),
			zap.String("version", latestVersion.Version),
			zap.Bool("is_latest", latestVersion.IsLatest))

		h.syncPluginConfigForVersion(&latestVersion, component.Name)
		syncedCount++

		syncResults = append(syncResults, map[string]interface{}{
			"name":    component.Name,
			"version": latestVersion.Version,
			"success": true,
		})
	}

	h.logger.Info("同步所有插件完成",
		zap.Int("total_count", len(components)),
		zap.Int("synced_count", syncedCount))

	SuccessWithMessage(c, "同步完成", gin.H{
		"total_count":  len(components),
		"synced_count": syncedCount,
		"results":      syncResults,
	})
}

// BroadcastPluginConfigs 手动广播插件配置
// POST /api/v1/components/plugins/broadcast
func (h *ComponentsHandler) BroadcastPluginConfigs(c *gin.Context) {
	h.logger.Info("收到手动广播插件配置请求")

	// 查询所有启用的插件配置
	var pluginConfigs []model.PluginConfig
	if err := h.db.Where("enabled = ?", true).Find(&pluginConfigs).Error; err != nil {
		h.logger.Error("查询插件配置失败", zap.Error(err))
		InternalError(c, "查询插件配置失败")
		return
	}

	if len(pluginConfigs) == 0 {
		SuccessWithMessage(c, "没有启用的插件配置，无需广播", gin.H{
			"plugin_count": 0,
		})
		return
	}

	// 获取在线 Agent 数量和主机列表（排除容器环境）
	var onlineHosts []model.Host
	if err := h.db.Where("status = ? AND is_container = ?", model.HostStatusOnline, false).Find(&onlineHosts).Error; err != nil {
		h.logger.Error("查询在线主机失败", zap.Error(err))
		InternalError(c, "查询在线主机失败")
		return
	}
	onlineCount := len(onlineHosts)

	// 统计被跳过的容器主机
	var containerCount int64
	h.db.Model(&model.Host{}).Where("status = ? AND is_container = ?", model.HostStatusOnline, true).Count(&containerCount)

	h.logger.Info("查询到在线主机",
		zap.Int("online_count", onlineCount),
		zap.Int64("skipped_container", containerCount),
		zap.Int("plugin_count", len(pluginConfigs)))

	// 为每个插件创建推送记录
	var pushRecords []model.ComponentPushRecord
	for _, cfg := range pluginConfigs {
		// 查找对应的组件
		var component model.Component
		if err := h.db.Where("name = ?", cfg.Name).First(&component).Error; err != nil {
			h.logger.Warn("找不到对应的组件", zap.String("name", cfg.Name), zap.Error(err))
			continue
		}

		record := model.ComponentPushRecord{
			ComponentID:   component.ID,
			ComponentName: cfg.Name,
			Version:       cfg.Version,
			TargetType:    "all",
			Status:        model.ComponentPushStatusPushing,
			TotalCount:    onlineCount,
			SuccessCount:  0,
			FailedCount:   0,
			Message:       "手动触发推送",
			CreatedBy:     h.getCurrentUser(c),
			CreatedAt:     model.Now(),
			UpdatedAt:     model.Now(),
		}
		pushRecords = append(pushRecords, record)
	}

	// 批量创建推送记录
	if len(pushRecords) > 0 {
		if err := h.db.Create(&pushRecords).Error; err != nil {
			h.logger.Error("创建推送记录失败", zap.Error(err))
			// 不影响主流程，继续执行
		} else {
			h.logger.Info("创建推送记录成功", zap.Int("count", len(pushRecords)))

			// 为每个推送记录创建主机推送详情
			for _, record := range pushRecords {
				var pushHosts []model.ComponentPushHost
				for _, host := range onlineHosts {
					pushHost := model.ComponentPushHost{
						RecordID:  record.ID,
						HostID:    host.HostID,
						Hostname:  host.Hostname,
						Status:    model.ComponentPushHostStatusPending,
						CreatedAt: model.Now(),
						UpdatedAt: model.Now(),
					}
					pushHosts = append(pushHosts, pushHost)
				}

				if len(pushHosts) > 0 {
					if err := h.db.Create(&pushHosts).Error; err != nil {
						h.logger.Error("创建主机推送记录失败",
							zap.Uint("record_id", record.ID),
							zap.Error(err))
					} else {
						h.logger.Info("创建主机推送记录成功",
							zap.Uint("record_id", record.ID),
							zap.Int("host_count", len(pushHosts)))
					}
				}
			}
		}
	}

	// 更新所有插件配置的 updated_at 时间戳，触发自动广播
	// 这会让 PluginUpdateScheduler 在下一次检查时（30秒内）检测到更新并广播
	result := h.db.Model(&model.PluginConfig{}).
		Where("enabled = ?", true).
		Update("updated_at", time.Now())

	if result.Error != nil {
		h.logger.Error("更新插件配置时间戳失败", zap.Error(result.Error))
		InternalError(c, "触发广播失败")
		return
	}

	h.logger.Info("手动触发插件配置广播成功",
		zap.Int("plugin_count", len(pluginConfigs)),
		zap.Int64("updated_rows", result.RowsAffected),
		zap.Int("push_records", len(pushRecords)))

	broadcastMsg := "广播触发成功，将在30秒内推送到所有在线Agent"
	if containerCount > 0 {
		broadcastMsg = fmt.Sprintf("广播触发成功，将在30秒内推送到所有在线Agent（已跳过 %d 台容器主机）", containerCount)
	}

	SuccessWithMessage(c, broadcastMsg, gin.H{
		"plugin_count":       len(pluginConfigs),
		"online_agent_count": onlineCount,
		"skipped_container":  containerCount,
		"plugins":            pluginConfigsToNames(pluginConfigs),
	})
}

// pluginConfigsToNames 提取插件配置的名称和版本
func pluginConfigsToNames(configs []model.PluginConfig) []map[string]string {
	result := make([]map[string]string, len(configs))
	for i, cfg := range configs {
		result[i] = map[string]string{
			"name":    cfg.Name,
			"version": cfg.Version,
		}
	}
	return result
}

// runtimeTypesForPlugin 根据插件名推断适用的运行时类型
func runtimeTypesForPlugin(name string) model.StringArray {
	switch name {
	case "collector":
		// collector 适用于全平台
		return model.StringArray{"vm", "docker", "k8s"}
	default:
		// baseline, fim 及其他插件默认仅适用于 VM
		return model.StringArray{"vm"}
	}
}

// DownloadDependencyPackage 下载第三方依赖包（无需认证，Agent 直接下载）
// GET /api/v1/dependency/download/:name?arch=amd64
// 从 DB 查询 category=dependency 的组件 → 最新版本 → 对应 arch 的 tgz 包
func (h *ComponentsHandler) DownloadDependencyPackage(c *gin.Context) {
	name := c.Param("name")
	arch := c.DefaultQuery("arch", "amd64")

	if name == "" {
		BadRequest(c, "缺少参数")
		return
	}
	if arch != "amd64" && arch != "arm64" {
		BadRequest(c, "无效的架构，支持: amd64, arm64")
		return
	}

	// 查找依赖组件
	var component model.Component
	if err := h.db.Where("name = ? AND category = ?", name, model.ComponentCategoryDependency).First(&component).Error; err != nil {
		NotFound(c, fmt.Sprintf("依赖 %s 不存在", name))
		return
	}

	// 查找最新版本
	var latestVersion model.ComponentVersion
	if err := h.db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&latestVersion).Error; err != nil {
		if err := h.db.Where("component_id = ?", component.ID).
			Order("created_at DESC").First(&latestVersion).Error; err != nil {
			NotFound(c, fmt.Sprintf("依赖 %s 没有可用版本", name))
			return
		}
	}

	// 查找对应架构的 tgz 包
	var pkg model.ComponentPackage
	if err := h.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
		latestVersion.ID, "tgz", arch, true).First(&pkg).Error; err != nil {
		NotFound(c, fmt.Sprintf("依赖 %s 没有 %s 架构的包", name, arch))
		return
	}

	// 检查文件是否存在
	fileInfo, err := os.Stat(pkg.FilePath)
	if os.IsNotExist(err) {
		h.logger.Error("依赖包文件不存在", zap.String("path", pkg.FilePath))
		NotFound(c, "文件不存在")
		return
	}

	// 大文件下载延长写超时（同 Agent/Plugin 包）
	deadline := time.Duration(fileInfo.Size()/(1024*1024)+60) * time.Second
	if deadline < 5*time.Minute {
		deadline = 5 * time.Minute
	}
	rc := http.NewResponseController(c.Writer)
	if err := rc.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
		h.logger.Warn("设置依赖包下载写超时失败", zap.Error(err))
	}

	// 设置下载响应头
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", pkg.FileName))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	c.Header("X-Dependency-Name", name)
	c.Header("X-Dependency-Version", latestVersion.Version)
	c.Header("X-Dependency-SHA256", pkg.SHA256)

	// 发送文件
	c.File(pkg.FilePath)

	h.logger.Info("依赖包下载",
		zap.String("name", name),
		zap.String("version", latestVersion.Version),
		zap.String("arch", arch),
		zap.String("client_ip", c.ClientIP()),
	)
}
