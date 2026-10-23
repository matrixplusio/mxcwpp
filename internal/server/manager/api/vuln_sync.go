package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// VulnSyncHandler advisory 同步触发 admin API。
//
// advisory 拉源已剥离至 VulnSync 服务（VulnSync→Kafka→manager consumer 匹配）。
// 本 handler 仅作为「立即同步」入口，HTTP 触发 VulnSync 拉取，不再 manager 内自拉。
type VulnSyncHandler struct {
	logger      *zap.Logger
	vulnSyncURL string
}

// NewVulnSyncHandler 构造 handler。vulnSyncURL 为 VulnSync 服务地址（如 http://vulnsync:8083）。
func NewVulnSyncHandler(logger *zap.Logger, vulnSyncURL string) *VulnSyncHandler {
	return &VulnSyncHandler{logger: logger, vulnSyncURL: vulnSyncURL}
}

// SyncAdvisories POST /api/v1/vulnerabilities/advisory-sync
//
// 触发 VulnSync 服务立即拉取 OS advisory（RHSA/Rocky/USN/Debian/Alpine/CentOS）。
// advisory 经 Kafka mxcwpp.vuln.advisory 由 manager consumer 匹配主机写 host_vulnerabilities。
func (h *VulnSyncHandler) SyncAdvisories(c *gin.Context) {
	if h.vulnSyncURL == "" {
		InternalError(c, "VulnSync 服务地址未配置（vuln.vulnsync_url），无法触发拉取")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	url := strings.TrimRight(h.vulnSyncURL, "/") + "/sync"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		InternalError(c, "构造 VulnSync 请求失败: "+err.Error())
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.logger.Warn("调用 VulnSync /sync 失败", zap.String("url", url), zap.Error(err))
		InternalError(c, "调用 VulnSync /sync 失败: "+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		InternalError(c, fmt.Sprintf("VulnSync /sync 返回 %d: %v", resp.StatusCode, body))
		return
	}

	Success(c, gin.H{
		"triggered": true,
		"vulnsync":  body,
		"note":      "已触发 VulnSync 拉取；advisory 经 Kafka 由 manager consumer 匹配入库",
	})
}
