// Package api 提供 HTTP API 处理器
package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// AlertWhitelistSuggestionHandler 自动调优建议 API 处理器（P2-B）
type AlertWhitelistSuggestionHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAlertWhitelistSuggestionHandler 创建自动调优建议 API 处理器
func NewAlertWhitelistSuggestionHandler(db *gorm.DB, logger *zap.Logger) *AlertWhitelistSuggestionHandler {
	return &AlertWhitelistSuggestionHandler{db: db, logger: logger}
}

// ListSuggestionsRequest 查询建议列表请求
type ListSuggestionsRequest struct {
	Page     int    `form:"page" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Status   string `form:"status"` // 空=pending；可传 adopted/dismissed/all
}

// ListSuggestions 获取自动调优建议列表
// GET /api/v1/alerts/whitelist/suggestions
func (h *AlertWhitelistSuggestionHandler) ListSuggestions(c *gin.Context) {
	var req ListSuggestionsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}

	query := h.db.Model(&model.AlertWhitelistSuggestion{})
	switch req.Status {
	case "", model.SuggestionStatusPending:
		query = query.Where("status = ?", model.SuggestionStatusPending)
	case "all":
		// 不过滤
	default:
		query = query.Where("status = ?", req.Status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询建议总数失败", zap.Error(err))
		InternalError(c, "查询建议失败")
		return
	}

	var items []model.AlertWhitelistSuggestion
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("confidence DESC, hit_count DESC").
		Offset(offset).Limit(req.PageSize).Find(&items).Error; err != nil {
		h.logger.Error("查询建议列表失败", zap.Error(err))
		InternalError(c, "查询建议失败")
		return
	}

	Success(c, gin.H{
		"items":      items,
		"total":      total,
		"page":       req.Page,
		"page_size":  req.PageSize,
		"total_page": (int(total) + req.PageSize - 1) / req.PageSize,
	})
}

// AdoptSuggestion 采纳建议：写入 AlertWhitelist 并标记建议为 adopted
// POST /api/v1/alerts/whitelist/suggestions/:id/adopt
func (h *AlertWhitelistSuggestionHandler) AdoptSuggestion(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的建议ID")
		return
	}
	operator := c.GetString("username")
	if operator == "" {
		operator = "unknown"
	}

	var s model.AlertWhitelistSuggestion
	if err := h.db.First(&s, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "建议不存在")
			return
		}
		InternalError(c, "查询建议失败")
		return
	}
	if s.Status != model.SuggestionStatusPending {
		BadRequest(c, "建议已被处理")
		return
	}

	name := fmt.Sprintf("自动调优采纳: %s", s.Exe)
	if len(name) > 100 {
		name = name[:100]
	}
	wl := &model.AlertWhitelist{
		Name:     name,
		RuleID:   s.RuleID,
		HostID:   s.HostID,
		Category: s.Category,
		Severity: s.Severity,
		Exe:      s.Exe,
		Cmdline:  s.Cmdline,
		Reason: fmt.Sprintf("P2-B 自动调优采纳(建议#%d): rule=%s exe=%s 命中%d次 置信度%d; 代表原因: %s",
			s.ID, s.RuleName, s.Exe, s.HitCount, s.Confidence, s.ResolveReasonSample),
		CreatedBy: "auto-tuning:" + operator,
	}

	now := model.ToLocalTime(time.Now())
	err = h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(wl).Error; err != nil {
			return err
		}
		decidedAt := now
		return tx.Model(&model.AlertWhitelistSuggestion{}).Where("id = ?", s.ID).Updates(map[string]any{
			"status":       model.SuggestionStatusAdopted,
			"decided_by":   operator,
			"decided_at":   decidedAt,
			"whitelist_id": wl.ID,
		}).Error
	})
	if err != nil {
		h.logger.Error("采纳建议失败", zap.Uint64("id", id), zap.Error(err))
		InternalError(c, "采纳建议失败")
		return
	}

	h.logger.Info("自动调优建议已采纳",
		zap.Uint64("suggestion_id", id),
		zap.Uint("whitelist_id", wl.ID),
		zap.String("rule_id", s.RuleID),
		zap.String("exe", s.Exe),
		zap.String("operator", operator),
	)
	SuccessWithMessage(c, "已采纳并写入白名单", gin.H{"whitelist_id": wl.ID})
}

// DismissSuggestion 驳回建议
// POST /api/v1/alerts/whitelist/suggestions/:id/dismiss
func (h *AlertWhitelistSuggestionHandler) DismissSuggestion(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的建议ID")
		return
	}
	operator := c.GetString("username")
	if operator == "" {
		operator = "unknown"
	}

	now := model.ToLocalTime(time.Now())
	result := h.db.Model(&model.AlertWhitelistSuggestion{}).
		Where("id = ? AND status = ?", id, model.SuggestionStatusPending).
		Updates(map[string]any{
			"status":     model.SuggestionStatusDismissed,
			"decided_by": operator,
			"decided_at": now,
		})
	if result.Error != nil {
		h.logger.Error("驳回建议失败", zap.Uint64("id", id), zap.Error(result.Error))
		InternalError(c, "驳回建议失败")
		return
	}
	if result.RowsAffected == 0 {
		BadRequest(c, "建议不存在或已被处理")
		return
	}

	h.logger.Info("自动调优建议已驳回", zap.Uint64("id", id), zap.String("operator", operator))
	SuccessWithMessage(c, "已驳回", nil)
}

// RevokeSuggestion 撤销已采纳的建议：删除对应白名单条目并将建议标记为 revoked。
// 用于采纳后发现误判时即时回退（原本需手删 alert_whitelists 表）。
// POST /api/v1/alerts/whitelist/suggestions/:id/revoke
func (h *AlertWhitelistSuggestionHandler) RevokeSuggestion(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的建议ID")
		return
	}
	operator := c.GetString("username")
	if operator == "" {
		operator = "unknown"
	}

	var s model.AlertWhitelistSuggestion
	if err := h.db.First(&s, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "建议不存在")
			return
		}
		InternalError(c, "查询建议失败")
		return
	}
	if s.Status != model.SuggestionStatusAdopted {
		BadRequest(c, "仅可撤销已采纳的建议")
		return
	}

	now := model.ToLocalTime(time.Now())
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// 删除采纳时生成的白名单条目（若已被手动删除则忽略）
		if s.WhitelistID > 0 {
			if err := tx.Delete(&model.AlertWhitelist{}, s.WhitelistID).Error; err != nil {
				return err
			}
		}
		// 标记为 revoked（终态，不复活；upsertSuggestion 只放行 pending）
		return tx.Model(&model.AlertWhitelistSuggestion{}).Where("id = ?", s.ID).Updates(map[string]any{
			"status":       model.SuggestionStatusRevoked,
			"decided_by":   operator,
			"decided_at":   now,
			"whitelist_id": 0,
		}).Error
	})
	if err != nil {
		h.logger.Error("撤销建议失败", zap.Uint64("id", id), zap.Error(err))
		InternalError(c, "撤销建议失败")
		return
	}

	h.logger.Info("自动调优建议已撤销",
		zap.Uint64("suggestion_id", id),
		zap.Uint("whitelist_id", s.WhitelistID),
		zap.String("rule_id", s.RuleID),
		zap.String("operator", operator),
	)
	SuccessWithMessage(c, "已撤销，对应白名单已删除", nil)
}
