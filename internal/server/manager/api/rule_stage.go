package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/detquality"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RuleStageHandler 暴露规则生命周期与检测质量。
type RuleStageHandler struct {
	svc    *detquality.Service
	db     *gorm.DB
	logger *zap.Logger
}

// NewRuleStageHandler 构造 handler。
func NewRuleStageHandler(db *gorm.DB, logger *zap.Logger) *RuleStageHandler {
	return &RuleStageHandler{
		svc:    detquality.NewService(db, logger),
		db:     db,
		logger: logger,
	}
}

// GetRuleQuality 返回规则的检测质量。
//
// GET /api/v1/detection-rules/:id/quality
func (h *RuleStageHandler) GetRuleQuality(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}
	q, err := h.svc.RuleQuality("cel-" + strconv.FormatUint(id, 10))
	if err != nil {
		InternalError(c, "查询检测质量失败: "+err.Error())
		return
	}
	Success(c, q)
}

// GetPromotionReadiness 返回规则能否晋级及原因。
//
// 单独提供一个"能不能升"的查询：让运维在点之前就看到差在哪，
// 而不是靠反复点击去试探门槛。
//
// GET /api/v1/detection-rules/:id/promotion
func (h *RuleStageHandler) GetPromotionReadiness(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}
	var rule model.DetectionRule
	if err := h.db.First(&rule, uint(id)).Error; err != nil {
		NotFound(c, "规则不存在")
		return
	}
	d, err := h.svc.EvaluatePromotion(&rule)
	if err != nil {
		InternalError(c, "评估晋级条件失败: "+err.Error())
		return
	}
	Success(c, d)
}

// PromoteRule 晋级规则。
//
// POST /api/v1/detection-rules/:id/promote
func (h *RuleStageHandler) PromoteRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}
	d, err := h.svc.PromoteRule(uint(id), actorOf(c))
	if err != nil {
		// 连同判定详情一起返回：只说"不满足条件"等于让人自己猜差在哪。
		c.JSON(400, gin.H{"code": 400, "message": err.Error(), "data": d})
		return
	}
	Success(c, d)
}

// DemoteRuleRequest 降级请求。
type DemoteRuleRequest struct {
	Stage  string `json:"stage" binding:"required"`
	Reason string `json:"reason" binding:"required"`
}

// DemoteRule 降级规则。
//
// POST /api/v1/detection-rules/:id/demote
func (h *RuleStageHandler) DemoteRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的规则 ID")
		return
	}
	var req DemoteRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "降级必须指定目标阶段与原因")
		return
	}
	if err := h.svc.DemoteRule(uint(id), req.Stage, req.Reason, actorOf(c)); err != nil {
		BadRequest(c, err.Error())
		return
	}
	Success(c, gin.H{"stage": req.Stage})
}
