package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/common/ssrf"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
)

// VulnDataSourcesHandler 漏洞数据源 admin 配置 API。
type VulnDataSourcesHandler struct {
	db          *gorm.DB
	logger      *zap.Logger
	svc         *biz.VulnDataSourceService
	vulnSyncURL string // VulnSync 服务地址(os_advisory 源同步经此触发)
}

// NewVulnDataSourcesHandler 构造。
func NewVulnDataSourcesHandler(db *gorm.DB, logger *zap.Logger, vulnSyncURL string) *VulnDataSourcesHandler {
	return &VulnDataSourcesHandler{
		db:          db,
		logger:      logger,
		svc:         biz.NewVulnDataSourceService(db, logger),
		vulnSyncURL: vulnSyncURL,
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

	// 防 SSRF：校验地址 + 用 dial 期 IP 复查的安全客户端
	if err := ssrf.ValidateURL(src.BaseURL); err != nil {
		Success(c, gin.H{"reachable": false, "error": "地址不合法（疑似内网/元数据）"})
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, src.BaseURL, nil)
	if err != nil {
		InternalError(c, "构造 HTTP 请求失败")
		return
	}
	client := ssrf.NewSafeClient(30 * time.Second)
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

	// os_advisory 源(rhsa/rocky/usn/debian 等)已剥离到 VulnSync(VulnSync→Kafka→consumer 匹配),
	// 走 scanner.SyncOnly() 不会拉 advisory,必须触发 VulnSync /sync。
	if src.Category == "os_advisory" {
		if h.vulnSyncURL == "" {
			InternalError(c, "VulnSync 服务地址未配置（vuln.vulnsync_url），无法同步 advisory 源")
			return
		}
		go func() {
			if err := triggerVulnSync(h.vulnSyncURL); err != nil {
				h.logger.Error("触发 VulnSync 拉取失败", zap.String("source", src.Name), zap.Error(err))
			}
		}()
		SuccessMessage(c, "已触发 VulnSync 拉取 advisory 源")
		return
	}

	// CVE 元数据源(mitre/osv/nvd 等)走 vuln_scanner 同步。
	scanner := biz.NewVulnScanner(h.db, h.logger)
	go func() {
		if err := scanner.SyncOnly(); err != nil {
			h.logger.Error("手动 trigger sync 失败", zap.String("source", src.Name), zap.Error(err))
		}
	}()
	SuccessMessage(c, "同步任务已触发，将拉取全部启用的数据源")
}

// triggerVulnSync POST {vulnSyncURL}/sync 触发 VulnSync 立即拉取全源 advisory。
func triggerVulnSync(vulnSyncURL string) error {
	url := strings.TrimRight(vulnSyncURL, "/") + "/sync"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vulnsync /sync 返回 %d", resp.StatusCode)
	}
	return nil
}
