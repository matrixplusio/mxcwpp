package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/casework"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// OncallHandler 值班表 API。
type OncallHandler struct {
	logger *zap.Logger
	cases  *casework.Service
}

// NewOncallHandler 创建值班表处理器。
func NewOncallHandler(db *gorm.DB, logger *zap.Logger) *OncallHandler {
	return &OncallHandler{logger: logger, cases: casework.NewService(db, logger)}
}

// ListShifts GET /api/v1/oncall/shifts?days=14
func (h *OncallHandler) ListShifts(c *gin.Context) {
	days := 14
	if v := c.Query("days"); v != "" {
		if n, err := time.ParseDuration(v + "h"); err == nil && n > 0 {
			days = int(n.Hours())
		}
	}
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	shifts, err := h.cases.ListShifts(from, to)
	if err != nil {
		h.logger.Error("查询排班失败", zap.Error(err))
		InternalError(c, "查询排班失败")
		return
	}
	Success(c, gin.H{"items": shifts, "total": len(shifts)})
}

// CurrentOncall GET /api/v1/oncall/current
//
// 返回各层级当前值班人。无人值班要如实说明——排班缺口本身就是运维要知道的事，
// 藏起来只会让事件一直无主。
func (h *OncallHandler) CurrentOncall(c *gin.Context) {
	out := map[string]string{}
	gaps := []string{}
	for _, tier := range []string{
		model.OncallTierL1, model.OncallTierL2, model.OncallTierSecurity,
	} {
		who, err := h.cases.CurrentOncall(tier)
		if err != nil {
			gaps = append(gaps, tier)
			continue
		}
		out[tier] = who
	}
	Success(c, gin.H{"oncall": out, "uncovered_tiers": gaps})
}

// SaveShiftRequest POST /api/v1/oncall/shifts
type SaveShiftRequest struct {
	ID       uint   `json:"id"`
	Tier     string `json:"tier" binding:"required"`
	Username string `json:"username" binding:"required"`
	StartsAt string `json:"starts_at" binding:"required"`
	EndsAt   string `json:"ends_at" binding:"required"`
}

// SaveShift 新增或更新排班。
func (h *OncallHandler) SaveShift(c *gin.Context) {
	var req SaveShiftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请填写层级、值班人与起止时间")
		return
	}
	start, err := time.Parse(time.RFC3339, req.StartsAt)
	if err != nil {
		BadRequest(c, "开始时间格式错误，应为 RFC3339")
		return
	}
	end, err := time.Parse(time.RFC3339, req.EndsAt)
	if err != nil {
		BadRequest(c, "结束时间格式错误，应为 RFC3339")
		return
	}

	shift := &model.OncallShift{
		ID:       req.ID,
		Tier:     req.Tier,
		Username: req.Username,
		StartsAt: model.ToLocalTime(start),
		EndsAt:   model.ToLocalTime(end),
	}
	if err := h.cases.SaveShift(shift); err != nil {
		BadRequest(c, err.Error())
		return
	}
	SuccessWithMessage(c, "已保存", shift)
}
