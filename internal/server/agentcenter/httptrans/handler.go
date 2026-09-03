// Package httptrans 提供 AgentCenter HTTP 管理接口
// 供 Manager 的服务发现模块调用，用于：健康探测、连接统计、命令下发
package httptrans

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/transfer"
	"github.com/matrixplusio/mxcwpp/internal/server/common/internalauth"
)

// Handler 是 AC HTTP 管理接口的处理器
type Handler struct {
	transfer *transfer.Service
	logger   *zap.Logger
}

// NewHandler 创建 Handler
func NewHandler(t *transfer.Service, logger *zap.Logger) *Handler {
	return &Handler{transfer: t, logger: logger}
}

// RegisterRoutes 注册所有管理路由到给定的 RouterGroup。
//
// 威胁模型：/command、/command/batch、/dependency/install 可向 Agent 下发任务，
// /conn/stat、/conn/list 泄漏在线 Agent 清单（ID/主机名/IP/版本）——全部强制内部
// 服务认证（X-Internal-Secret，常量时间比较，空 secret 一律拒绝）。
// /health 保持匿名，仅暴露最小 liveness（供 Manager SD 探活），不含任何在线明细。
// /metrics 由 setup 注册（匿名，依赖部署拓扑限制在受控网络内，不发布到宿主公网）。
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup, internalSecret string) {
	rg.GET("/health", h.Health)

	protected := rg.Group("", internalauth.Middleware(internalSecret))
	protected.GET("/conn/stat", h.ConnStat)
	protected.GET("/conn/list", h.ConnList)
	protected.POST("/command", h.SendCommand)
	protected.POST("/command/batch", h.SendCommandBatch)
	protected.POST("/dependency/install", h.SendDependencyInstall)
	protected.GET("/agent-cert-stats", h.AgentCertStats)
}

// healthResp 是 /health 的响应体（仅最小 liveness，不含在线明细）。
type healthResp struct {
	Status string `json:"status"`
}

// Health godoc
// GET /health
// Manager SD 模块每 10s 主动探测，判断 AC 实例是否存活。
// 匿名可达，故只返回存活状态；在线 Agent 数经受保护的 /conn/stat 或 SD 心跳上报，
// 不在此匿名端点泄漏。
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, healthResp{Status: "ok"})
}

// connStatResp 是 /conn/stat 的响应体
type connStatResp struct {
	OnlineCount int      `json:"online_count"`
	AgentIDs    []string `json:"agent_ids"`
}

// connListResp 是 /conn/list 的响应体
type connListResp struct {
	Count  int                    `json:"count"`
	Agents []transfer.AgentDetail `json:"agents"`
}

// ConnList godoc
// GET /conn/list
// 返回所有当前连接 Agent 的详细信息（主机名、IP、版本等）
func (h *Handler) ConnList(c *gin.Context) {
	agents := h.transfer.GetOnlineAgentDetails()
	c.JSON(http.StatusOK, connListResp{
		Count:  len(agents),
		Agents: agents,
	})
}

// ConnStat godoc
// GET /conn/stat
// 返回当前在线 Agent 数量和 ID 列表，用于 Manager 监控大盘
func (h *Handler) ConnStat(c *gin.Context) {
	c.JSON(http.StatusOK, connStatResp{
		OnlineCount: h.transfer.GetOnlineAgentCount(),
		AgentIDs:    h.transfer.GetOnlineAgentIDs(),
	})
}

// taskReq 对应 grpcProto.Task 的 JSON 表示
type taskReq struct {
	DataType   int32  `json:"data_type" binding:"required"`
	ObjectName string `json:"object_name"`
	Data       string `json:"data"`
	Token      string `json:"token"`
}

// sendCommandReq 是 /command 的请求体
type sendCommandReq struct {
	AgentID string    `json:"agent_id" binding:"required"`
	Tasks   []taskReq `json:"tasks" binding:"required,min=1"`
}

// SendCommand godoc
// POST /command
// 向单个 Agent 下发命令，Manager 在分配任务时调用
func (h *Handler) SendCommand(c *gin.Context) {
	var req sendCommandReq
	if err := c.ShouldBindJSON(&req); err != nil {
		ackErr(c, http.StatusBadRequest, err)
		return
	}

	cmd := buildCommand(req.Tasks)
	if err := h.transfer.SendCommand(req.AgentID, cmd); err != nil {
		h.logger.Warn("命令下发失败",
			zap.String("agent_id", req.AgentID),
			zap.Error(err),
		)
		ackErr(c, http.StatusServiceUnavailable, err)
		return
	}
	ackStatus(c, http.StatusOK, "sent")
}

// batchCommandReq 是 /command/batch 的请求体
type batchCommandReq struct {
	AgentIDs []string  `json:"agent_ids" binding:"required,min=1"`
	Tasks    []taskReq `json:"tasks" binding:"required,min=1"`
}

// batchCommandResp 是 /command/batch 的响应体
type batchCommandResp struct {
	Sent   []string `json:"sent"`
	Failed []string `json:"failed"`
}

// SendCommandBatch godoc
// POST /command/batch
// 向多个 Agent 批量下发命令（如并行触发基线扫描）
func (h *Handler) SendCommandBatch(c *gin.Context) {
	var req batchCommandReq
	if err := c.ShouldBindJSON(&req); err != nil {
		ackErr(c, http.StatusBadRequest, err)
		return
	}

	resp := batchCommandResp{
		Sent:   make([]string, 0, len(req.AgentIDs)),
		Failed: make([]string, 0),
	}
	cmd := buildCommand(req.Tasks)
	for _, agentID := range req.AgentIDs {
		// 每个 Agent 下发独立的 Command 副本（避免共享指针竞争）
		cmdCopy := buildCommand(req.Tasks)
		_ = cmd // cmd 仅用于预热，实际用 cmdCopy
		if err := h.transfer.SendCommand(agentID, cmdCopy); err != nil {
			h.logger.Warn("批量命令下发失败",
				zap.String("agent_id", agentID),
				zap.Error(err),
			)
			resp.Failed = append(resp.Failed, agentID)
		} else {
			resp.Sent = append(resp.Sent, agentID)
		}
	}

	httpStatus := http.StatusOK
	if len(resp.Sent) == 0 {
		httpStatus = http.StatusServiceUnavailable
	}
	c.JSON(httpStatus, resp)
}

// buildCommand 将请求中的 taskReq 列表转换为 grpcProto.Command
func buildCommand(tasks []taskReq) *grpcProto.Command {
	protoTasks := make([]*grpcProto.Task, 0, len(tasks))
	for _, t := range tasks {
		protoTasks = append(protoTasks, &grpcProto.Task{
			DataType:   t.DataType,
			ObjectName: t.ObjectName,
			Data:       t.Data,
			Token:      t.Token,
		})
	}
	return &grpcProto.Command{Tasks: protoTasks}
}

// depInstallReq 是 /dependency/install 的请求体
type depInstallReq struct {
	AgentID     string `json:"agent_id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Action      string `json:"action" binding:"required"`
	Version     string `json:"version"`
	RequestID   string `json:"request_id" binding:"required"`
	DownloadURL string `json:"download_url"`
}

// SendDependencyInstall godoc
// POST /dependency/install
// 向单个 Agent 下发依赖安装命令
func (h *Handler) SendDependencyInstall(c *gin.Context) {
	var req depInstallReq
	if err := c.ShouldBindJSON(&req); err != nil {
		ackErr(c, http.StatusBadRequest, err)
		return
	}

	if err := h.transfer.SendDependencyInstall(req.AgentID, req.Name, req.Action, req.Version, req.RequestID, req.DownloadURL); err != nil {
		h.logger.Warn("依赖安装命令下发失败",
			zap.String("agent_id", req.AgentID),
			zap.String("name", req.Name),
			zap.Error(err),
		)
		ackErr(c, http.StatusServiceUnavailable, err)
		return
	}
	ackStatus(c, http.StatusOK, "sent")
}

// AgentCertStats godoc
// GET /agent-cert-stats
//
// 返回 agent 证书迁移进度，供部署脚本在升级 AgentCenter 前做闸门判断。
//
// 新版 AgentCenter 强制客户端证书 CN == AgentID。still_shared > 0 时升级，
// 那些 agent 会在升级瞬间全部被拒且不会自愈（agent 侧无重新 enroll 的逻辑）。
// deploy.sh 的 check_agent_trust_migration 读的就是这个接口。
func (h *Handler) AgentCertStats(c *gin.Context) {
	c.JSON(http.StatusOK, h.transfer.CertMigrationProgress())
}
