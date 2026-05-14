package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
)

// AlertAnalysisHandler LLM 告警分析 API 处理器
type AlertAnalysisHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	cfg    *config.Config
}

// NewAlertAnalysisHandler 创建告警分析处理器
func NewAlertAnalysisHandler(db *gorm.DB, logger *zap.Logger, cfg *config.Config) *AlertAnalysisHandler {
	return &AlertAnalysisHandler{db: db, logger: logger, cfg: cfg}
}

// AnalyzeAlert LLM 告警分析
// POST /api/v1/alerts/:id/analyze
func (h *AlertAnalysisHandler) AnalyzeAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的告警 ID")
		return
	}

	llmCfg := h.cfg.LLM
	if llmCfg.APIURL == "" {
		BadRequest(c, "LLM 服务未配置")
		return
	}

	assist := biz.NewLLMAssist(h.db, h.logger, llmCfg.APIURL, llmCfg.APIKey, llmCfg.Model)
	result, err := assist.AnalyzeAlert(uint(id))
	if err != nil {
		h.logger.Error("LLM 告警分析失败", zap.Uint64("alert_id", id), zap.Error(err))
		InternalError(c, "分析失败")
		return
	}

	Success(c, result)
}
