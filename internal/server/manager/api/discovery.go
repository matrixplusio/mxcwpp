package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
)

// DiscoveryHandler 处理 AC 注册/心跳/注销 和服务发现查询
type DiscoveryHandler struct {
	registry *sd.Registry
	logger   *zap.Logger
}

// NewDiscoveryHandler 创建 DiscoveryHandler
func NewDiscoveryHandler(registry *sd.Registry, logger *zap.Logger) *DiscoveryHandler {
	return &DiscoveryHandler{registry: registry, logger: logger}
}

// registerReq 是 AC 注册请求体
type registerReq struct {
	ID       string `json:"id" binding:"required"`        // AC 实例 ID（hostname 或配置值）
	GRPCAddr string `json:"grpc_addr" binding:"required"` // AC gRPC 地址，供 Agent 连接
	HTTPAddr string `json:"http_addr" binding:"required"` // AC HTTP 管理地址，供 Manager 探测
}

// Register godoc
// POST /api/v1/internal/ac/register
// AC 启动时向 Manager 注册自身
func (h *DiscoveryHandler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	h.registry.Register(req.ID, req.GRPCAddr, req.HTTPAddr)
	c.JSON(http.StatusOK, gin.H{"status": "registered"})
}

// heartbeatReq 是 AC 心跳请求体
type heartbeatReq struct {
	ID        string `json:"id" binding:"required"`
	ConnCount int64  `json:"conn_count"` // 当前在线 Agent 数
}

// Heartbeat godoc
// POST /api/v1/internal/ac/heartbeat
// AC 每 30s 上报一次心跳和连接数
func (h *DiscoveryHandler) Heartbeat(c *gin.Context) {
	var req heartbeatReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	if err := h.registry.Heartbeat(req.ID, req.ConnCount); err != nil {
		// 实例不存在，要求重新注册
		c.JSON(http.StatusNotFound, gin.H{"error": "实例未注册", "action": "re-register"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// deregisterReq 是 AC 注销请求体
type deregisterReq struct {
	ID string `json:"id" binding:"required"`
}

// Deregister godoc
// DELETE /api/v1/internal/ac/deregister
// AC 优雅关闭时主动注销（Manager 不等探测超时即可感知）
func (h *DiscoveryHandler) Deregister(c *gin.Context) {
	var req deregisterReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	h.registry.Deregister(req.ID)
	c.JSON(http.StatusOK, gin.H{"status": "deregistered"})
}

// ListACInstances godoc
// GET /api/v1/discovery/agentcenter
// 返回所有健康 AC 实例列表（Agent 侧服务发现 / 运维监控用）
func (h *DiscoveryHandler) ListACInstances(c *gin.Context) {
	all := c.Query("all") == "true"
	var instances []*sd.ACInstance
	if all {
		instances = h.registry.ListAll()
	} else {
		instances = h.registry.ListHealthy()
	}
	c.JSON(http.StatusOK, gin.H{
		"total":     len(instances),
		"instances": instances,
	})
}
