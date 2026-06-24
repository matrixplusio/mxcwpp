package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ImageScansHandler 镜像扫描 API 处理器
type ImageScansHandler struct {
	db      *gorm.DB
	logger  *zap.Logger
	scanner *biz.ImageScanner
}

// NewImageScansHandler 创建处理器
func NewImageScansHandler(db *gorm.DB, logger *zap.Logger) *ImageScansHandler {
	return &ImageScansHandler{
		db:      db,
		logger:  logger,
		scanner: biz.NewImageScanner(db, logger),
	}
}

// ScanImage 触发镜像扫描
func (h *ImageScansHandler) ScanImage(c *gin.Context) {
	var req struct {
		Image string `json:"image" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误: "+err.Error())
		return
	}

	scan, err := h.scanner.ScanImage(req.Image)
	if err != nil {
		h.logger.Warn("镜像扫描失败", zap.Error(err))
		// 即使失败也返回扫描记录（包含错误信息）
		if scan != nil {
			Success(c, scan)
			return
		}
		InternalError(c, "镜像扫描失败: "+err.Error())
		return
	}

	Success(c, scan)
}

// ListScans 扫描记录列表
func (h *ImageScansHandler) ListScans(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}

	var clusterID *uint
	if cid, err := strconv.ParseUint(c.Query("cluster_id"), 10, 64); err == nil && cid > 0 {
		v := uint(cid)
		clusterID = &v
	}

	scans, total, err := h.scanner.GetScanHistory(page, pageSize, clusterID)
	if err != nil {
		InternalError(c, "查询扫描记录失败")
		return
	}

	SuccessPaginated(c, total, scans)
}

// GetScan 扫描详情
func (h *ImageScansHandler) GetScan(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	scan, err := h.scanner.GetScanByID(uint(id))
	if err != nil {
		NotFound(c, "扫描记录不存在")
		return
	}

	Success(c, scan)
}

// GetScanVulns 镜像漏洞列表
func (h *ImageScansHandler) GetScanVulns(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	vulns, err := h.scanner.GetScanVulns(uint(id))
	if err != nil {
		InternalError(c, "查询镜像漏洞失败")
		return
	}

	Success(c, vulns)
}

// CreateRegistry 添加 Registry
func (h *ImageScansHandler) CreateRegistry(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		Type     string `json:"type"`
		URL      string `json:"url" binding:"required"`
		Username string `json:"username"`
		Password string `json:"password"`
		Insecure bool   `json:"insecure"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if req.Type == "" {
		req.Type = "basic"
	}

	registry := model.ImageRegistry{
		Name:     req.Name,
		Type:     req.Type,
		URL:      req.URL,
		Username: req.Username,
		Password: req.Password,
		Insecure: req.Insecure,
	}
	if err := h.db.Create(&registry).Error; err != nil {
		InternalError(c, "创建 Registry 失败")
		return
	}
	Success(c, registry)
}

// ListRegistries Registry 列表
func (h *ImageScansHandler) ListRegistries(c *gin.Context) {
	var registries []model.ImageRegistry
	h.db.Order("created_at DESC").Find(&registries)
	Success(c, registries)
}

// UpdateRegistry 更新 Registry
func (h *ImageScansHandler) UpdateRegistry(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Insecure *bool  `json:"insecure"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Type != "" {
		updates["type"] = req.Type
	}
	if req.URL != "" {
		updates["url"] = req.URL
	}
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.Password != "" {
		updates["password"] = req.Password
	}
	if req.Insecure != nil {
		updates["insecure"] = *req.Insecure
	}

	if err := h.db.Model(&model.ImageRegistry{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		InternalError(c, "更新 Registry 失败")
		return
	}

	var registry model.ImageRegistry
	h.db.First(&registry, id)
	Success(c, registry)
}

// DeleteRegistry 删除 Registry
func (h *ImageScansHandler) DeleteRegistry(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}
	if err := h.db.Delete(&model.ImageRegistry{}, id).Error; err != nil {
		InternalError(c, "删除 Registry 失败")
		return
	}
	Success(c, nil)
}

// ScanRegistryImages 触发 Registry 批量扫描
func (h *ImageScansHandler) ScanRegistryImages(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}

	go func() {
		if err := h.scanner.ScanRegistry(uint(id)); err != nil {
			h.logger.Warn("Registry 批量扫描失败", zap.Error(err))
		}
	}()

	Success(c, gin.H{"message": "Registry 批量扫描任务已启动"})
}
