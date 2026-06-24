package api

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// DependencyHandler 处理依赖管理相关 API
type DependencyHandler struct {
	db           *gorm.DB
	logger       *zap.Logger
	acDispatcher *sd.ACDispatcher
}

// NewDependencyHandler 创建 DependencyHandler
func NewDependencyHandler(db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) *DependencyHandler {
	return &DependencyHandler{db: db, logger: logger, acDispatcher: acDispatcher}
}

// depInstallRequest 是批量安装依赖的请求体
type depInstallRequest struct {
	HostIDs    []string `json:"host_ids" binding:"required,min=1"`
	Dependency string   `json:"dependency" binding:"required"`
	Version    string   `json:"version"`
	Action     string   `json:"action"` // install / uninstall / status，默认 install
}

// depInstallResult 是单个主机的安装结果
type depInstallResult struct {
	HostID    string `json:"host_id"`
	RequestID string `json:"request_id,omitempty"`
	Status    string `json:"status"` // sent / failed
	Error     string `json:"error,omitempty"`
}

// Install godoc
// POST /api/v1/hosts/dependency/install
// 向指定主机批量安装/卸载/查询依赖状态
func (h *DependencyHandler) Install(c *gin.Context) {
	var req depInstallRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	allowedActions := map[string]bool{"install": true, "uninstall": true, "status": true, "": true}
	if !allowedActions[req.Action] {
		BadRequest(c, fmt.Sprintf("不支持的操作: %s", req.Action))
		return
	}

	h.doInstall(c, req)
}

// depStatusRequest 是查询依赖状态的请求体
type depStatusRequest struct {
	HostIDs    []string `json:"host_ids" binding:"required,min=1"`
	Dependency string   `json:"dependency" binding:"required"`
}

// Status godoc
// POST /api/v1/hosts/dependency/status
// 向指定主机查询依赖状态（通过 Agent 执行 status 命令）
func (h *DependencyHandler) Status(c *gin.Context) {
	var req depStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	h.doInstall(c, depInstallRequest{
		HostIDs:    req.HostIDs,
		Dependency: req.Dependency,
		Action:     "status",
	})
}

// doInstall 是 Install 的核心逻辑，供 Install 和 Status 复用
func (h *DependencyHandler) doInstall(c *gin.Context, req depInstallRequest) {
	allowedDeps := map[string]bool{}
	if !allowedDeps[req.Dependency] {
		BadRequest(c, fmt.Sprintf("不支持的依赖: %s", req.Dependency))
		return
	}

	action := req.Action
	if action == "" {
		action = "install"
	}

	// 验证主机存在（host_id 即 agent_id）
	var hosts []model.Host
	if err := h.db.Where("host_id IN ?", req.HostIDs).Find(&hosts).Error; err != nil {
		InternalError(c, "查询主机失败")
		return
	}

	hostSet := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		hostSet[host.HostID] = true
	}

	// 获取后台下载地址
	downloadURL := h.getBackendURL()

	results := make([]depInstallResult, 0, len(req.HostIDs))
	for _, hostID := range req.HostIDs {
		if !hostSet[hostID] {
			results = append(results, depInstallResult{
				HostID: hostID,
				Status: "failed",
				Error:  "主机不存在",
			})
			continue
		}

		requestID := uuid.New().String()
		err := h.acDispatcher.SendDependencyInstall(hostID, req.Dependency, action, req.Version, requestID, downloadURL)
		if err != nil {
			h.logger.Warn("依赖命令下发失败",
				zap.String("host_id", hostID),
				zap.Error(err))
			results = append(results, depInstallResult{
				HostID: hostID,
				Status: "failed",
				Error:  err.Error(),
			})
		} else {
			results = append(results, depInstallResult{
				HostID:    hostID,
				RequestID: requestID,
				Status:    "sent",
			})
		}
	}

	sentCount := 0
	for _, r := range results {
		if r.Status == "sent" {
			sentCount++
		}
	}

	SuccessWithMessage(c, fmt.Sprintf("已向 %d/%d 台主机下发 %s %s 命令", sentCount, len(req.HostIDs), req.Dependency, action), results)
}

// getBackendURL 从系统配置获取后台下载地址
func (h *DependencyHandler) getBackendURL() string {
	var cfg model.SystemConfig
	if err := h.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&cfg).Error; err != nil {
		return ""
	}
	var siteConfig model.SiteConfig
	if err := json.Unmarshal([]byte(cfg.Value), &siteConfig); err != nil {
		return ""
	}
	return siteConfig.BackendURL
}
