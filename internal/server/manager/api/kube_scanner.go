package api

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeScannerHandler 集群内扫描器（trivy-operator）生命周期 API
type KubeScannerHandler struct {
	db       *gorm.DB
	logger   *zap.Logger
	cfg      *config.Config
	operator *biz.KubeVulnOperator
}

// NewKubeScannerHandler 创建扫描器 Handler
func NewKubeScannerHandler(db *gorm.DB, logger *zap.Logger, kubeClient *biz.KubeClientManager, cfg *config.Config) *KubeScannerHandler {
	return &KubeScannerHandler{
		db:       db,
		logger:   logger,
		cfg:      cfg,
		operator: biz.NewKubeVulnOperator(db, logger, kubeClient),
	}
}

// webhookURL 拼接 manager 外部可达的 Push 接收 URL（无 ExternalURL 则返回空=不启用 Push）
func (h *KubeScannerHandler) webhookURL(token string) string {
	if h.cfg.Server.ExternalURL == "" {
		return ""
	}
	return strings.TrimRight(h.cfg.Server.ExternalURL, "/") + "/api/v1/kube/scanner/report-webhook/" + token
}

func (h *KubeScannerHandler) loadCluster(c *gin.Context) (*model.KubeCluster, bool) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的集群 ID")
		return nil, false
	}
	var cluster model.KubeCluster
	if err := h.db.First(&cluster, id).Error; err != nil {
		NotFound(c, "集群不存在")
		return nil, false
	}
	return &cluster, true
}

// Preflight 安装前预检
func (h *KubeScannerHandler) Preflight(c *gin.Context) {
	cluster, ok := h.loadCluster(c)
	if !ok {
		return
	}
	res, err := h.operator.Preflight(c.Request.Context(), cluster.ID)
	if err != nil {
		InternalError(c, "预检失败: "+err.Error())
		return
	}
	Success(c, res)
}

// Install 自动安装扫描器
func (h *KubeScannerHandler) Install(c *gin.Context) {
	cluster, ok := h.loadCluster(c)
	if !ok {
		return
	}
	var req struct {
		ImageRegistry string `json:"imageRegistry"`
	}
	_ = c.ShouldBindJSON(&req)

	// 同步预检，给出即时反馈
	pre, err := h.operator.Preflight(c.Request.Context(), cluster.ID)
	if err != nil {
		InternalError(c, "预检失败: "+err.Error())
		return
	}
	if !pre.CanAutoInstall {
		BadRequest(c, "无法自动安装："+pre.Reason+"（可改用 manifest 导出方式手动安装）")
		return
	}

	opts := biz.InstallOptions{
		ImageRegistry:  req.ImageRegistry,
		WebhookBaseURL: h.webhookURL(cluster.AuditToken),
	}
	// 安装涉及应用 ~30 个资源，异步执行，前端通过 status 轮询
	go func() {
		if err := h.operator.Install(c.Copy().Request.Context(), cluster.ID, opts); err != nil {
			h.logger.Warn("扫描器安装失败", zap.Uint("clusterID", cluster.ID), zap.Error(err))
		}
	}()

	Success(c, gin.H{"message": "扫描器安装任务已启动", "webhookEnabled": opts.WebhookBaseURL != ""})
}

// Manifest 导出渲染后的 operator manifest（兜底的手动安装路径）
func (h *KubeScannerHandler) Manifest(c *gin.Context) {
	cluster, ok := h.loadCluster(c)
	if !ok {
		return
	}
	imageRegistry := c.Query("image_registry")
	data, err := h.operator.RenderManifest(imageRegistry, h.webhookURL(cluster.AuditToken))
	if err != nil {
		InternalError(c, "生成 manifest 失败: "+err.Error())
		return
	}
	c.Header("Content-Disposition", "attachment; filename=trivy-operator.yaml")
	c.Data(200, "application/yaml", data)
}

// Status 扫描器运行状态
func (h *KubeScannerHandler) Status(c *gin.Context) {
	cluster, ok := h.loadCluster(c)
	if !ok {
		return
	}
	status, err := h.operator.Status(c.Request.Context(), cluster.ID)
	if err != nil {
		InternalError(c, "查询状态失败: "+err.Error())
		return
	}
	Success(c, status)
}

// Sync 按需 Pull 同步漏洞报告
func (h *KubeScannerHandler) Sync(c *gin.Context) {
	cluster, ok := h.loadCluster(c)
	if !ok {
		return
	}
	count, err := h.operator.SyncReports(c.Request.Context(), cluster.ID)
	if err != nil {
		InternalError(c, "同步失败: "+err.Error())
		return
	}
	Success(c, gin.H{"reports": count})
}

// Uninstall 卸载扫描器
func (h *KubeScannerHandler) Uninstall(c *gin.Context) {
	cluster, ok := h.loadCluster(c)
	if !ok {
		return
	}
	go func() {
		if err := h.operator.Uninstall(c.Copy().Request.Context(), cluster.ID); err != nil {
			h.logger.Warn("扫描器卸载失败", zap.Uint("clusterID", cluster.ID), zap.Error(err))
		}
	}()
	Success(c, gin.H{"message": "扫描器卸载任务已启动"})
}

// ReceiveReportWebhook 接收 trivy-operator Push（webhook broadcast）的漏洞报告
func (h *KubeScannerHandler) ReceiveReportWebhook(c *gin.Context) {
	token := c.Param("cluster_token")
	if token == "" {
		Unauthorized(c, "missing token")
		return
	}
	var cluster model.KubeCluster
	if err := h.db.Where("audit_token = ?", token).First(&cluster).Error; err != nil {
		Unauthorized(c, "invalid token")
		return
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 10<<20))
	if err != nil {
		BadRequest(c, "read body failed")
		return
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		BadRequest(c, "invalid report json")
		return
	}
	u := &unstructured.Unstructured{Object: raw}

	// broadcast 会推送多种报告类型，仅处理 VulnerabilityReport
	if u.GetKind() != "VulnerabilityReport" {
		Success(c, gin.H{"ignored": u.GetKind()})
		return
	}
	if err := h.operator.IngestReport(cluster.ID, u); err != nil {
		h.logger.Warn("接收漏洞报告失败", zap.Uint("clusterID", cluster.ID), zap.Error(err))
		InternalError(c, "ingest failed")
		return
	}
	Success(c, gin.H{"received": 1})
}
