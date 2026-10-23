package api

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
)

// VulnCacheHandler 漏洞库缓存 API 处理器
type VulnCacheHandler struct {
	db      *gorm.DB
	logger  *zap.Logger
	manager *biz.VulnCacheManager
}

// NewVulnCacheHandler 创建处理器
func NewVulnCacheHandler(db *gorm.DB, logger *zap.Logger) *VulnCacheHandler {
	return &VulnCacheHandler{
		db:      db,
		logger:  logger,
		manager: biz.NewVulnCacheManager(db, logger),
	}
}

// GetStats 缓存统计
func (h *VulnCacheHandler) GetStats(c *gin.Context) {
	stats, err := h.manager.GetStats()
	if err != nil {
		InternalError(c, "获取缓存统计失败")
		return
	}
	Success(c, stats)
}

// ImportDB 上传离线数据包
func (h *VulnCacheHandler) ImportDB(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		BadRequest(c, "请上传文件")
		return
	}

	// 保存到临时目录
	tmpDir := os.TempDir()
	tmpPath := filepath.Join(tmpDir, file.Filename)
	if err := c.SaveUploadedFile(file, tmpPath); err != nil {
		InternalError(c, "保存文件失败")
		return
	}
	defer os.Remove(tmpPath)

	record, err := h.manager.ImportOfflineDB(tmpPath)
	if err != nil {
		h.logger.Warn("离线数据库导入失败", zap.Error(err))
		if record != nil {
			Success(c, record)
			return
		}
		InternalError(c, "导入失败: "+err.Error())
		return
	}

	Success(c, record)
}

// GetImportHistory 导入历史
func (h *VulnCacheHandler) GetImportHistory(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}

	records, total, err := h.manager.GetImportHistory(page, pageSize)
	if err != nil {
		InternalError(c, "查询导入历史失败")
		return
	}

	SuccessPaginated(c, total, records)
}

// PurgeExpired 清理过期缓存
func (h *VulnCacheHandler) PurgeExpired(c *gin.Context) {
	purged, err := h.manager.PurgeExpired()
	if err != nil {
		InternalError(c, "清理失败: "+err.Error())
		return
	}

	SuccessWithMessage(c, "清理完成", gin.H{"purged": purged})
}
