package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/mlquality"
)

// MLQualityHandler 暴露 ML 异常检测的质量与档位。
type MLQualityHandler struct {
	svc    *mlquality.Service
	db     *gorm.DB
	logger *zap.Logger
}

// NewMLQualityHandler 构造 handler。
func NewMLQualityHandler(db *gorm.DB, logger *zap.Logger) *MLQualityHandler {
	return &MLQualityHandler{
		svc:    mlquality.NewService(db, logger),
		db:     db,
		logger: logger,
	}
}

// GetMLQuality 返回 ML 异常检测质量。
//
// GET /api/v1/anomalies/quality
func (h *MLQualityHandler) GetMLQuality(c *gin.Context) {
	q, err := h.svc.Measure()
	if err != nil {
		InternalError(c, "统计 ML 检测质量失败: "+err.Error())
		return
	}
	Success(c, gin.H{
		"quality":      q,
		"current_mode": anomaly.LoadMode(h.db, h.logger),
	})
}

// SetMLModeRequest 档位变更请求。
type SetMLModeRequest struct {
	Mode string `json:"mode" binding:"required"`
}

// SetMLMode 变更 ML 异常检测档位。
//
// 升档需要人工研判数据支撑；降档无条件允许。
//
// POST /api/v1/anomalies/mode
func (h *MLQualityHandler) SetMLMode(c *gin.Context) {
	var req SetMLModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "必须指定目标档位")
		return
	}
	current := anomaly.LoadMode(h.db, h.logger)
	d, err := h.svc.ApplyModeChange(current, anomaly.Mode(req.Mode), actorOf(c))
	if err != nil {
		// 连同判定详情一起返回，让人直接看到差在哪，而不是自己猜门槛。
		c.JSON(400, gin.H{"code": 400, "message": err.Error(), "data": d})
		return
	}
	Success(c, d)
}

// GetMLModeReadiness 返回切到目标档位的可行性评估。
//
// GET /api/v1/anomalies/mode-readiness?target=context
func (h *MLQualityHandler) GetMLModeReadiness(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		BadRequest(c, "必须指定 target 档位")
		return
	}
	current := anomaly.LoadMode(h.db, h.logger)
	d, err := h.svc.EvaluateModeChange(current, anomaly.Mode(target))
	if err != nil {
		InternalError(c, "评估档位变更失败: "+err.Error())
		return
	}
	Success(c, d)
}
