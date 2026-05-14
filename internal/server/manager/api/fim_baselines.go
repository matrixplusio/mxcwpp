package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// FIMBaselinesHandler FIM 基线管理处理器
type FIMBaselinesHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewFIMBaselinesHandler 创建 FIM 基线处理器
func NewFIMBaselinesHandler(db *gorm.DB, logger *zap.Logger) *FIMBaselinesHandler {
	return &FIMBaselinesHandler{db: db, logger: logger}
}

// ListBaselines 获取基线列表
func (h *FIMBaselinesHandler) ListBaselines(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	query := h.db.Model(&model.FIMBaseline{})

	if policyID := c.Query("policy_id"); policyID != "" {
		query = query.Where("policy_id = ?", policyID)
	}
	if hostID := c.Query("host_id"); hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询基线总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var baselines []model.FIMBaseline
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&baselines).Error; err != nil {
		h.logger.Error("查询基线列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	SuccessPaginated(c, total, baselines)
}

// GetBaseline 获取基线详情（含条目分页）
func (h *FIMBaselinesHandler) GetBaseline(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的基线 ID")
		return
	}

	var baseline model.FIMBaseline
	if err := h.db.First(&baseline, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "基线不存在")
			return
		}
		h.logger.Error("查询基线失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 分页查询条目
	entryPage, _ := strconv.Atoi(c.DefaultQuery("entry_page", "1"))
	entryPageSize, _ := strconv.Atoi(c.DefaultQuery("entry_page_size", "50"))
	if entryPage < 1 {
		entryPage = 1
	}
	if entryPageSize < 1 || entryPageSize > 500 {
		entryPageSize = 50
	}

	var entryTotal int64
	h.db.Model(&model.FIMBaselineEntry{}).Where("baseline_id = ?", baseline.ID).Count(&entryTotal)

	var entries []model.FIMBaselineEntry
	entryOffset := (entryPage - 1) * entryPageSize
	h.db.Where("baseline_id = ?", baseline.ID).
		Offset(entryOffset).Limit(entryPageSize).
		Order("file_path ASC").
		Find(&entries)

	Success(c, gin.H{
		"baseline":    baseline,
		"entries":     entries,
		"entry_total": entryTotal,
	})
}

// ApproveBaseline 审批基线
func (h *FIMBaselinesHandler) ApproveBaseline(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的基线 ID")
		return
	}

	username, _ := c.Get("username")

	var baseline model.FIMBaseline
	if err := h.db.First(&baseline, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "基线不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	if baseline.Status != "pending" {
		BadRequest(c, "仅待审批的基线可以审批")
		return
	}

	now := model.Now()
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// 将同策略+主机的旧 approved 基线标记为 outdated
		tx.Model(&model.FIMBaseline{}).
			Where("policy_id = ? AND host_id = ? AND status = ?",
				baseline.PolicyID, baseline.HostID, "approved").
			Update("status", "outdated")

		// 审批当前基线
		return tx.Model(&baseline).Updates(map[string]any{
			"status":      "approved",
			"approved_by": username,
			"approved_at": &now,
		}).Error
	})
	if err != nil {
		h.logger.Error("审批基线失败", zap.Error(err))
		InternalError(c, "审批失败")
		return
	}

	Success(c, gin.H{"message": "基线已审批"})
}

// BatchApproveBaselines 批量审批基线
func (h *FIMBaselinesHandler) BatchApproveBaselines(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		BadRequest(c, "请提供基线 ID 列表")
		return
	}

	username, _ := c.Get("username")
	now := model.Now()
	approved := 0

	for _, id := range req.IDs {
		var bl model.FIMBaseline
		if err := h.db.First(&bl, id).Error; err != nil || bl.Status != "pending" {
			continue
		}

		err := h.db.Transaction(func(tx *gorm.DB) error {
			tx.Model(&model.FIMBaseline{}).
				Where("policy_id = ? AND host_id = ? AND status = ?",
					bl.PolicyID, bl.HostID, "approved").
				Update("status", "outdated")

			return tx.Model(&bl).Updates(map[string]any{
				"status":      "approved",
				"approved_by": username,
				"approved_at": &now,
			}).Error
		})
		if err == nil {
			approved++
		}
	}

	Success(c, gin.H{"approved": approved})
}

// RejectBaseline 拒绝基线（删除候选基线及其条目）
func (h *FIMBaselinesHandler) RejectBaseline(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的基线 ID")
		return
	}

	var baseline model.FIMBaseline
	if err := h.db.First(&baseline, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "基线不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	if baseline.Status != "pending" {
		BadRequest(c, "仅待审批的基线可以拒绝")
		return
	}

	err = h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("baseline_id = ?", baseline.ID).Delete(&model.FIMBaselineEntry{}).Error; err != nil {
			return err
		}
		return tx.Delete(&baseline).Error
	})
	if err != nil {
		h.logger.Error("拒绝基线失败", zap.Error(err))
		InternalError(c, "操作失败")
		return
	}

	Success(c, gin.H{"message": "基线已拒绝并删除"})
}
