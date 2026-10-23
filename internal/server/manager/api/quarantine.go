package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// QuarantineHandler 文件隔离箱 API 处理器
type QuarantineHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewQuarantineHandler 创建文件隔离箱处理器
func NewQuarantineHandler(db *gorm.DB, logger *zap.Logger) *QuarantineHandler {
	return &QuarantineHandler{db: db, logger: logger}
}

// ListFiles 获取隔离文件列表
// GET /api/v1/quarantine/files
func (h *QuarantineHandler) ListFiles(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.QuarantineFile{})

	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		pattern := "%" + keyword + "%"
		query = query.Where("threat_name LIKE ? OR original_path LIKE ? OR hostname LIKE ? OR ip LIKE ?", pattern, pattern, pattern, pattern)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if severity := strings.TrimSpace(c.Query("severity")); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if threatType := strings.TrimSpace(c.Query("threat_type")); threatType != "" {
		query = query.Where("threat_type = ?", threatType)
	}
	if hostID := strings.TrimSpace(c.Query("host_id")); hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询隔离文件总数失败", zap.Error(err))
		InternalError(c, "查询隔离文件失败")
		return
	}

	var files []model.QuarantineFile
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("quarantined_at DESC").Find(&files).Error; err != nil {
		h.logger.Error("查询隔离文件列表失败", zap.Error(err))
		InternalError(c, "查询隔离文件失败")
		return
	}

	SuccessPaginated(c, total, files)
}

// GetFile 获取隔离文件详情
// GET /api/v1/quarantine/files/:id
func (h *QuarantineHandler) GetFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的文件 ID")
		return
	}

	var file model.QuarantineFile
	if err := h.db.First(&file, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "隔离文件不存在")
			return
		}
		h.logger.Error("查询隔离文件失败", zap.Error(err))
		InternalError(c, "查询隔离文件失败")
		return
	}

	Success(c, file)
}

// RestoreFile 恢复隔离文件
// POST /api/v1/quarantine/files/:id/restore
func (h *QuarantineHandler) RestoreFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的文件 ID")
		return
	}

	var file model.QuarantineFile
	if err := h.db.First(&file, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "隔离文件不存在")
			return
		}
		h.logger.Error("查询隔离文件失败", zap.Error(err))
		InternalError(c, "查询隔离文件失败")
		return
	}

	if file.Status != "quarantined" {
		BadRequest(c, "只能恢复处于隔离状态的文件")
		return
	}

	now := model.LocalTime(time.Now())
	if err := h.db.Model(&file).Updates(map[string]interface{}{
		"status":      "restored",
		"restored_at": &now,
	}).Error; err != nil {
		h.logger.Error("恢复隔离文件失败", zap.Uint("id", file.ID), zap.Error(err))
		InternalError(c, "恢复隔离文件失败")
		return
	}

	h.logger.Info("恢复隔离文件",
		zap.Uint("file_id", file.ID),
		zap.String("original_path", file.OriginalPath),
		zap.String("host_id", file.HostID),
	)
	SuccessMessage(c, "文件已恢复")
}

// DeleteFile 永久删除隔离文件
// DELETE /api/v1/quarantine/files/:id
func (h *QuarantineHandler) DeleteFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的文件 ID")
		return
	}

	var file model.QuarantineFile
	if err := h.db.First(&file, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "隔离文件不存在")
			return
		}
		h.logger.Error("查询隔离文件失败", zap.Error(err))
		InternalError(c, "查询隔离文件失败")
		return
	}

	now := model.LocalTime(time.Now())
	if err := h.db.Model(&file).Updates(map[string]interface{}{
		"status":     "deleted",
		"deleted_at": &now,
	}).Error; err != nil {
		h.logger.Error("删除隔离文件失败", zap.Uint("id", file.ID), zap.Error(err))
		InternalError(c, "删除隔离文件失败")
		return
	}

	h.logger.Info("永久删除隔离文件",
		zap.Uint("file_id", file.ID),
		zap.String("original_path", file.OriginalPath),
	)
	SuccessMessage(c, "文件已永久删除")
}

// BatchDeleteRequest 批量删除请求
type BatchDeleteQuarantineRequest struct {
	IDs []uint `json:"ids" binding:"required,min=1"`
}

// BatchDelete 批量永久删除隔离文件
// POST /api/v1/quarantine/files/batch-delete
func (h *QuarantineHandler) BatchDelete(c *gin.Context) {
	var req BatchDeleteQuarantineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	now := model.LocalTime(time.Now())
	result := h.db.Model(&model.QuarantineFile{}).
		Where("id IN ? AND status = ?", req.IDs, "quarantined").
		Updates(map[string]interface{}{
			"status":     "deleted",
			"deleted_at": &now,
		})

	if result.Error != nil {
		h.logger.Error("批量删除隔离文件失败", zap.Error(result.Error))
		InternalError(c, "批量删除失败")
		return
	}

	h.logger.Info("批量删除隔离文件",
		zap.Int64("affected", result.RowsAffected),
		zap.Uints("ids", req.IDs),
	)
	SuccessWithMessage(c, "批量删除成功", gin.H{
		"deleted": result.RowsAffected,
	})
}

// GetStatistics 获取隔离箱统计
// GET /api/v1/quarantine/statistics
func (h *QuarantineHandler) GetStatistics(c *gin.Context) {
	var stats struct {
		Total       int64 `gorm:"column:total"`
		Quarantined int64 `gorm:"column:quarantined"`
		Restored    int64 `gorm:"column:restored"`
		Deleted     int64 `gorm:"column:deleted"`
	}
	h.db.Model(&model.QuarantineFile{}).Select(
		"COUNT(*) as total",
		"SUM(CASE WHEN status = 'quarantined' THEN 1 ELSE 0 END) as quarantined",
		"SUM(CASE WHEN status = 'restored' THEN 1 ELSE 0 END) as restored",
		"SUM(CASE WHEN status = 'deleted' THEN 1 ELSE 0 END) as deleted",
	).Scan(&stats)

	var totalSize int64
	h.db.Model(&model.QuarantineFile{}).
		Where("status = ?", "quarantined").
		Select("COALESCE(SUM(file_size), 0)").
		Scan(&totalSize)

	var severityRows []struct {
		Severity string `gorm:"column:severity"`
		Count    int64  `gorm:"column:count"`
	}
	h.db.Model(&model.QuarantineFile{}).
		Where("status = ?", "quarantined").
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityRows)

	severityMap := make(map[string]int64)
	for _, row := range severityRows {
		severityMap[row.Severity] = row.Count
	}

	var affectedHosts int64
	h.db.Model(&model.QuarantineFile{}).
		Where("status = ?", "quarantined").
		Distinct("host_id").
		Count(&affectedHosts)

	Success(c, gin.H{
		"total":       stats.Total,
		"quarantined": stats.Quarantined,
		"restored":    stats.Restored,
		"deleted":     stats.Deleted,
		"totalSize":   totalSize,
		"severity": gin.H{
			"critical": severityMap["critical"],
			"high":     severityMap["high"],
			"medium":   severityMap["medium"],
			"low":      severityMap["low"],
		},
		"affectedHosts": affectedHosts,
	})
}
