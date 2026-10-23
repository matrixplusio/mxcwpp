// Package api 提供 HTTP API 处理器
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// InspectionHandler 运维巡检 API 处理器
type InspectionHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewInspectionHandler 创建巡检处理器
func NewInspectionHandler(db *gorm.DB, logger *zap.Logger) *InspectionHandler {
	return &InspectionHandler{db: db, logger: logger}
}

// InspectionHostItem 巡检主机项
type InspectionHostItem struct {
	HostID         string            `json:"host_id"`
	Hostname       string            `json:"hostname"`
	IPv4           model.StringArray `json:"ipv4"`
	Status         model.HostStatus  `json:"status"`
	AgentVersion   string            `json:"agent_version"`
	AgentStartTime *model.LocalTime  `json:"agent_start_time"`
	SystemBootTime *model.LocalTime  `json:"system_boot_time"`
	LastHeartbeat  *model.LocalTime  `json:"last_heartbeat"`
	OSFamily       string            `json:"os_family"`
	OSVersion      string            `json:"os_version"`
	Arch           string            `json:"arch"`
	RuntimeType    string            `json:"runtime_type"`
	BusinessLine   string            `json:"business_line"`
	Plugins        []PluginStatus    `json:"plugins"`
}

// PluginStatus 插件状态
type PluginStatus struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	LatestVersion string `json:"latest_version"`
	NeedUpdate    bool   `json:"need_update"`
}

// InspectionSummary 巡检统计摘要
type InspectionSummary struct {
	TotalHosts          int `json:"total_hosts"`
	OnlineHosts         int `json:"online_hosts"`
	OfflineHosts        int `json:"offline_hosts"`
	AgentOutdatedCount  int `json:"agent_outdated_count"`
	PluginErrorCount    int `json:"plugin_error_count"`
	PluginOutdatedCount int `json:"plugin_outdated_count"`
}

// InspectionOverviewResponse 巡检概览响应
type InspectionOverviewResponse struct {
	Summary              InspectionSummary    `json:"summary"`
	LatestAgentVersion   string               `json:"latest_agent_version"`
	LatestPluginVersions map[string]string    `json:"latest_plugin_versions"`
	Hosts                []InspectionHostItem `json:"hosts"`
}

// GetOverview 获取巡检概览
// GET /api/v1/inspection/overview
func (h *InspectionHandler) GetOverview(c *gin.Context) {
	// 1. 查询所有主机
	var hosts []model.Host
	if err := h.db.Order("status ASC, hostname ASC").Find(&hosts).Error; err != nil {
		h.logger.Error("查询主机列表失败", zap.Error(err))
		InternalError(c, "查询主机列表失败")
		return
	}

	// 2. 查询所有主机插件状态
	var hostPlugins []model.HostPlugin
	if err := h.db.Find(&hostPlugins).Error; err != nil {
		h.logger.Error("查询主机插件状态失败", zap.Error(err))
		InternalError(c, "查询主机插件状态失败")
		return
	}

	// 3. 查询最新插件版本（从 plugin_configs 表）
	var pluginConfigs []model.PluginConfig
	if err := h.db.Where("enabled = ?", true).Find(&pluginConfigs).Error; err != nil {
		h.logger.Error("查询插件配置失败", zap.Error(err))
		InternalError(c, "查询插件配置失败")
		return
	}

	// 4. 查询最新 Agent 版本（从 component_versions 表）
	latestAgentVersion := ""
	var agentVersion model.ComponentVersion
	err := h.db.Joins("JOIN components ON components.id = component_versions.component_id").
		Where("components.name = ? AND component_versions.is_latest = ?", "agent", true).
		First(&agentVersion).Error
	if err == nil {
		latestAgentVersion = agentVersion.Version
	}

	// 构建插件最新版本映射
	pluginLatestVersions := make(map[string]string)
	for _, pc := range pluginConfigs {
		pluginLatestVersions[pc.Name] = pc.Version
	}

	// 构建主机插件映射
	hostPluginMap := make(map[string][]model.HostPlugin)
	for _, hp := range hostPlugins {
		hostPluginMap[hp.HostID] = append(hostPluginMap[hp.HostID], hp)
	}

	// 5. 组装结果
	summary := InspectionSummary{}
	items := make([]InspectionHostItem, 0, len(hosts))

	for _, host := range hosts {
		summary.TotalHosts++
		if host.Status == model.HostStatusOnline {
			summary.OnlineHosts++
		} else {
			summary.OfflineHosts++
		}

		// Agent 版本检查
		if latestAgentVersion != "" && host.AgentVersion != "" && host.AgentVersion != latestAgentVersion {
			summary.AgentOutdatedCount++
		}

		// 插件状态
		plugins := make([]PluginStatus, 0)
		for _, hp := range hostPluginMap[host.HostID] {
			latestVer := pluginLatestVersions[hp.Name]
			needUpdate := latestVer != "" && hp.Version != "" && hp.Version != latestVer
			if needUpdate {
				summary.PluginOutdatedCount++
			}
			if hp.Status == model.HostPluginStatusError || hp.Status == model.HostPluginStatusStopped {
				summary.PluginErrorCount++
			}
			plugins = append(plugins, PluginStatus{
				Name:          hp.Name,
				Version:       hp.Version,
				Status:        string(hp.Status),
				LatestVersion: latestVer,
				NeedUpdate:    needUpdate,
			})
		}

		items = append(items, InspectionHostItem{
			HostID:         host.HostID,
			Hostname:       host.Hostname,
			IPv4:           host.IPv4,
			Status:         host.Status,
			AgentVersion:   host.AgentVersion,
			AgentStartTime: host.AgentStartTime,
			SystemBootTime: host.SystemBootTime,
			LastHeartbeat:  host.LastHeartbeat,
			OSFamily:       host.OSFamily,
			OSVersion:      host.OSVersion,
			Arch:           host.Arch,
			RuntimeType:    string(host.RuntimeType),
			BusinessLine:   host.BusinessLine,
			Plugins:        plugins,
		})
	}

	resp := InspectionOverviewResponse{
		Summary:              summary,
		LatestAgentVersion:   latestAgentVersion,
		LatestPluginVersions: pluginLatestVersions,
		Hosts:                items,
	}

	Success(c, resp)
}
