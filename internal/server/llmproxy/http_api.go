package llmproxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/llmproxy/provider"
	"github.com/imkerbos/mxsec-platform/internal/server/llmproxy/router"
)

// CompleteAPIHandler 提供 POST /complete HTTP 接口。
type CompleteAPIHandler struct {
	router *router.Router
	logger *zap.Logger
}

// NewCompleteAPIHandler 构造 handler。
func NewCompleteAPIHandler(r *router.Router, logger *zap.Logger) *CompleteAPIHandler {
	return &CompleteAPIHandler{router: r, logger: logger}
}

// CompleteRequest /complete 请求体。
type CompleteRequest struct {
	Scene       string             `json:"scene" binding:"required"`
	Model       string             `json:"model" binding:"required"`
	System      string             `json:"system,omitempty"`
	Messages    []provider.Message `json:"messages" binding:"required,min=1"`
	Temperature float64            `json:"temperature,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
	TenantID    string             `json:"tenant_id,omitempty"`
	TraceID     string             `json:"trace_id,omitempty"`
}

// Complete POST /complete
func (h *CompleteAPIHandler) Complete(c *gin.Context) {
	var req CompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest, "message": "请求参数无效"})
		return
	}

	pReq := provider.CompletionRequest{
		Model:       req.Model,
		System:      req.System,
		Messages:    req.Messages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
		Metadata: map[string]string{
			"tenant_id": req.TenantID,
			"trace_id":  req.TraceID,
			"scene":     req.Scene,
		},
	}

	resp, err := h.router.Complete(c.Request.Context(), router.Scene(req.Scene), pReq)
	if err != nil {
		h.logger.Warn("complete failed",
			zap.String("scene", req.Scene),
			zap.String("model", req.Model),
			zap.String("tenant_id", req.TenantID),
			zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"code": http.StatusBadGateway, "message": "模型补全失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{
		"content":       resp.Content,
		"model":         resp.Model,
		"finish_reason": resp.FinishReason,
		"tokens_in":     resp.TokensIn,
		"tokens_out":    resp.TokensOut,
		"provider":      resp.Provider,
	}})
}

// EmbedRequest /embed 请求体。
type EmbedRequest struct {
	Text     string `json:"text" binding:"required"`
	Model    string `json:"model" binding:"required"`
	TenantID string `json:"tenant_id,omitempty"`
}

// Embed POST /embed
func (h *CompleteAPIHandler) Embed(c *gin.Context) {
	var req EmbedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest, "message": "请求参数无效"})
		return
	}
	emb, err := h.router.Embed(c.Request.Context(), req.Text, req.Model)
	if err != nil {
		h.logger.Warn("embed failed",
			zap.String("model", req.Model),
			zap.String("tenant_id", req.TenantID),
			zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"code": http.StatusBadGateway, "message": "向量化失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{
		"model":     req.Model,
		"dimension": len(emb),
		"embedding": emb,
	}})
}

// ServerSetup 把 handler 挂到 NewHTTPHandler。
//
// 接入 main 时调用:
//
//	gin := llmproxy.NewHTTPHandler(...)
//	llmproxy.AttachAPI(gin.(*gin.Engine), handler)
func AttachAPI(r *gin.Engine, h *CompleteAPIHandler) {
	r.POST("/complete", h.Complete)
	r.POST("/embed", h.Embed)
}
