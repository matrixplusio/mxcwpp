package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
)

// VulnDataSourcesHandler 漏洞数据源 admin 配置 API。
type VulnDataSourcesHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	svc    *biz.VulnDataSourceService
}

// NewVulnDataSourcesHandler 构造。
func NewVulnDataSourcesHandler(db *gorm.DB, logger *zap.Logger) *VulnDataSourcesHandler {
	return &VulnDataSourcesHandler{
		db:     db,
		logger: logger,
		svc:    biz.NewVulnDataSourceService(db, logger),
	}
}

// List GET /api/v1/vuln-data-sources
// 列出全部 source + 启用状态 + 上次同步信息。
func (h *VulnDataSourcesHandler) List(c *gin.Context) {
	rows, err := h.svc.List()
	if err != nil {
		InternalError(c, "查询漏洞数据源失败")
		return
	}
	Success(c, rows)
}

// Update PUT /api/v1/vuln-data-sources/:id
// 更新 enabled / base_url。
func (h *VulnDataSourcesHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "invalid id")
		return
	}
	var req struct {
		Enabled *bool   `json:"enabled,omitempty"`
		BaseURL *string `json:"baseUrl,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效")
		return
	}
	if req.Enabled != nil {
		if err := h.svc.SetEnabled(uint(id), *req.Enabled); err != nil {
			InternalError(c, err.Error())
			return
		}
	}
	if req.BaseURL != nil {
		if err := h.svc.SetBaseURL(uint(id), *req.BaseURL); err != nil {
			InternalError(c, err.Error())
			return
		}
	}
	src, err := h.svc.Get(uint(id))
	if err != nil {
		InternalError(c, "查询失败")
		return
	}
	Success(c, src)
}

// TestConnection POST /api/v1/vuln-data-sources/:id/test
// 测试 source 上游可达性（HEAD 请求 base_url，60s 超时）。
func (h *VulnDataSourcesHandler) TestConnection(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "invalid id")
		return
	}
	src, err := h.svc.Get(uint(id))
	if err != nil {
		NotFound(c, "source 不存在")
		return
	}
	if src.BaseURL == "" {
		BadRequest(c, "source 未配置 base_url")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, src.BaseURL, nil)
	if err != nil {
		InternalError(c, "构造 HTTP 请求失败")
		return
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		Success(c, gin.H{
			"reachable": false,
			"error":     err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	Success(c, gin.H{
		"reachable":   resp.StatusCode < 500,
		"http_status": resp.StatusCode,
	})
}

// TriggerSync POST /api/v1/vuln-data-sources/:id/sync
// 手动触发单源同步（异步）。
func (h *VulnDataSourcesHandler) TriggerSync(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "invalid id")
		return
	}
	src, err := h.svc.Get(uint(id))
	if err != nil {
		NotFound(c, "source 不存在")
		return
	}
	if !src.Enabled {
		BadRequest(c, "source 未启用，无法同步")
		return
	}

	// 异步触发完整 sync 流程（含所有 enabled source）。
	// MVP 不做单源精确触发；用户在 UI 看到 source 启用后调用 /vulnerabilities/sync 是等效的。
	scanner := biz.NewVulnScanner(h.db, h.logger)
	go func() {
		if err := scanner.SyncOnly(); err != nil {
			h.logger.Error("手动 trigger sync 失败", zap.String("source", src.Name), zap.Error(err))
		}
	}()
	SuccessMessage(c, "同步任务已触发，将拉取全部启用的数据源")
}
