// Package api 提供 HTTP API 处理器
package api

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/common/tenant"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// HostsHandler 是主机管理 API 处理器
type HostsHandler struct {
	db             *gorm.DB
	logger         *zap.Logger
	scoreCache     *biz.BaselineScoreCache
	metricsService *biz.MetricsService
}

// NewHostsHandler 创建主机处理器
func NewHostsHandler(db *gorm.DB, logger *zap.Logger, scoreCache *biz.BaselineScoreCache, metricsService *biz.MetricsService) *HostsHandler {
	return &HostsHandler{
		db:             db,
		logger:         logger,
		scoreCache:     scoreCache,
		metricsService: metricsService,
	}
}

// HostListItem 主机列表项（包含基线得分）
type HostListItem struct {
	model.Host
	BaselineScore    int     `json:"baseline_score"`
	BaselinePassRate float64 `json:"baseline_pass_rate"`
}

// ListHosts 获取主机列表
// GET /api/v1/hosts
func (h *HostsHandler) ListHosts(c *gin.Context) {
	// 解析查询参数（ParsePagination 内置上限，防超大 page_size 拖垮 DB）
	page, pageSize := ParsePagination(c)
	osFamily := c.Query("os_family")
	status := c.Query("status")
	businessLine := c.Query("business_line")  // 业务线筛选
	search := c.Query("search")               // 搜索关键词
	isContainerStr := c.Query("is_container") // 容器/主机类型筛选（废弃，使用 runtime_type）
	runtimeType := c.Query("runtime_type")    // 运行环境类型筛选：vm/docker/k8s

	// 构建查询。Scopes(tenant.GinScope) 会自动追加 WHERE tenant_id = ?，
	// 实现行级多租户隔离；详见 docs/multi-tenant.md §3.3。
	query := h.db.Model(&model.Host{}).Scopes(tenant.GinScope(c))

	// 过滤条件
	if osFamily != "" {
		query = query.Where("os_family = ?", osFamily)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if businessLine != "" {
		if businessLine == "__unbound__" {
			// 筛选无业务线的主机
			query = query.Where("business_line = '' OR business_line IS NULL")
		} else {
			query = query.Where("business_line = ?", businessLine)
		}
	}
	// 运行环境类型筛选（优先使用新参数）
	if runtimeType != "" && model.IsValidRuntimeType(runtimeType) {
		query = query.Where("runtime_type = ?", runtimeType)
	} else if isContainerStr != "" {
		// 向后兼容：容器/主机类型筛选
		isContainer := isContainerStr == "true"
		query = query.Where("is_container = ?", isContainer)
	}
	// 搜索功能：支持按主机名、host_id、IP 地址搜索
	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where(
			"hostname LIKE ? OR host_id LIKE ? OR CAST(ipv4 AS CHAR) LIKE ? OR CAST(public_ipv4 AS CHAR) LIKE ?",
			searchPattern, searchPattern, searchPattern, searchPattern,
		)
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询主机总数失败", zap.Error(err))
		InternalError(c, "查询主机列表失败")
		return
	}

	// 分页查询
	var hosts []model.Host
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("last_heartbeat DESC").Find(&hosts).Error; err != nil {
		h.logger.Error("查询主机列表失败", zap.Error(err))
		InternalError(c, "查询主机列表失败")
		return
	}

	// 计算每个主机的基线得分
	items := make([]HostListItem, 0, len(hosts))
	for _, host := range hosts {
		item := HostListItem{
			Host:             host,
			BaselineScore:    0,
			BaselinePassRate: 0.0,
		}

		// 如果有得分缓存，使用缓存计算得分
		if h.scoreCache != nil {
			score, err := h.scoreCache.GetHostScore(host.HostID)
			if err != nil {
				h.logger.Warn("计算主机基线得分失败", zap.String("host_id", host.HostID), zap.Error(err))
				// 继续处理，使用默认值 0
			} else if score != nil {
				item.BaselineScore = score.BaselineScore
				item.BaselinePassRate = score.PassRate
			}
		}

		items = append(items, item)
	}

	SuccessPaginated(c, total, items)
}

// HostStatusDistribution 主机状态分布统计
type HostStatusDistribution struct {
	Running      int64 `json:"running"`       // 运行中
	Abnormal     int64 `json:"abnormal"`      // 运行异常
	Offline      int64 `json:"offline"`       // 离线
	NotInstalled int64 `json:"not_installed"` // 未安装
	Uninstalled  int64 `json:"uninstalled"`   // 已卸载
}

// HostRiskDistribution 主机基线风险分布统计（按严重程度）
type HostRiskDistribution struct {
	Critical int64 `json:"critical"` // 存在严重风险基线的主机数
	High     int64 `json:"high"`     // 存在高危风险基线的主机数
	Medium   int64 `json:"medium"`   // 存在中危风险基线的主机数
	Low      int64 `json:"low"`      // 存在低危风险基线的主机数
}

// GetHostStatusDistribution 获取主机状态分布
// GET /api/v1/hosts/status-distribution
func (h *HostsHandler) GetHostStatusDistribution(c *gin.Context) {
	var distribution HostStatusDistribution

	// 单次 GROUP BY 替代多条独立 COUNT
	var rows []struct {
		Status string
		Cnt    int64
	}
	h.db.Model(&model.Host{}).Select("status, COUNT(*) AS cnt").Group("status").Scan(&rows)
	for _, r := range rows {
		switch r.Status {
		case "online":
			distribution.Running = r.Cnt
		case "offline":
			distribution.Offline = r.Cnt
		}
	}

	Success(c, distribution)
}

// GetHostRiskDistribution 获取主机基线风险分布（按严重程度）
// GET /api/v1/hosts/risk-distribution
// 优化：单次 GROUP BY 替代 4 条 DISTINCT 查询
func (h *HostsHandler) GetHostRiskDistribution(c *gin.Context) {
	var distribution HostRiskDistribution

	var rows []struct {
		Severity string
		Cnt      int64
	}
	h.db.Raw(`
		SELECT severity, COUNT(DISTINCT host_id) AS cnt
		FROM scan_results
		WHERE status = 'fail'
		GROUP BY severity
	`).Scan(&rows)

	for _, r := range rows {
		switch r.Severity {
		case "critical":
			distribution.Critical = r.Cnt
		case "high":
			distribution.High = r.Cnt
		case "medium":
			distribution.Medium = r.Cnt
		case "low":
			distribution.Low = r.Cnt
		}
	}

	Success(c, distribution)
}

// GetHost 获取主机详情
// GET /api/v1/hosts/:host_id
func (h *HostsHandler) GetHost(c *gin.Context) {
	hostID := c.Param("host_id")

	var host model.Host
	if err := h.db.Where("host_id = ?", hostID).First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "主机不存在")
			return
		}
		h.logger.Error("查询主机失败", zap.Error(err))
		InternalError(c, "查询主机失败")
		return
	}

	// 查询基线结果（按 rule_id 去重，只返回每个规则的最新结果，仅保留有效规则）
	var results []model.ScanResult
	if err := h.db.Raw(`
		SELECT sr.* FROM scan_results sr
		INNER JOIN rules ON sr.rule_id = rules.rule_id
		WHERE sr.host_id = ?
		AND sr.checked_at = (
			SELECT MAX(sr2.checked_at) FROM scan_results sr2
			WHERE sr2.host_id = sr.host_id AND sr2.rule_id = sr.rule_id
		)
		ORDER BY sr.checked_at DESC
	`, hostID).Scan(&results).Error; err != nil {
		h.logger.Error("查询基线结果失败", zap.Error(err))
	}

	// 查询最新监控数据（只取需要的字段，避免 SELECT * 回表开销）
	// 必须用 Take() 不能用 First()：First 会隐式追加 `ORDER BY id ASC`，
	// 与 collected_at DESC 形成混合排序 → MySQL 放弃 (host_id, collected_at) 复合索引 → filesort 全表扫
	// 实测 prod 7.99M 行表 24.9s → 改 Take() 走索引后毫秒级
	var latestMetric model.HostMetric
	if err := h.db.Select("id, cpu_usage, mem_usage").
		Where("host_id = ?", hostID).
		Order("collected_at DESC").
		Limit(1).
		Take(&latestMetric).Error; err != nil && err != gorm.ErrRecordNotFound {
		h.logger.Error("查询主机监控数据失败", zap.Error(err))
	}

	// 构建响应数据（扁平化结构，符合前端 HostDetail 接口）
	responseData := gin.H{
		"host_id":          host.HostID,
		"hostname":         host.Hostname,
		"os_family":        host.OSFamily,
		"os_version":       host.OSVersion,
		"kernel_version":   host.KernelVersion,
		"arch":             host.Arch,
		"ipv4":             host.IPv4,
		"ipv6":             host.IPv6,
		"public_ipv4":      host.PublicIPv4,
		"public_ipv6":      host.PublicIPv6,
		"status":           string(host.Status),
		"last_heartbeat":   host.LastHeartbeat,
		"agent_version":    host.AgentVersion, // Agent 版本号
		"created_at":       host.CreatedAt,
		"updated_at":       host.UpdatedAt,
		"baseline_results": results,
	}

	// 添加监控数据
	if latestMetric.ID > 0 {
		if latestMetric.CPUUsage != nil {
			responseData["cpu_usage"] = formatPercent(*latestMetric.CPUUsage)
		}
		if latestMetric.MemUsage != nil {
			responseData["memory_usage"] = formatPercent(*latestMetric.MemUsage)
		}
	}

	// 添加硬件和系统信息（从 Host 模型获取）
	if host.DeviceModel != "" {
		responseData["device_model"] = host.DeviceModel
	}
	if host.Manufacturer != "" {
		responseData["manufacturer"] = host.Manufacturer
	}
	if host.DeviceSerial != "" {
		responseData["device_serial"] = host.DeviceSerial
	}
	if host.DeviceID != "" {
		responseData["device_id"] = host.DeviceID
	} else {
		// 如果 device_id 为空，使用 host_id
		responseData["device_id"] = host.HostID
	}
	if host.CPUInfo != "" {
		responseData["cpu_info"] = host.CPUInfo
	}
	if host.MemorySize != "" {
		responseData["memory_size"] = host.MemorySize
	}
	if host.SystemLoad != "" {
		responseData["system_load"] = host.SystemLoad
	}
	if host.DefaultGateway != "" {
		responseData["default_gateway"] = host.DefaultGateway
	}
	if host.NetworkMode != "" {
		responseData["network_mode"] = host.NetworkMode
	}
	if len(host.DNSServers) > 0 {
		responseData["dns_servers"] = host.DNSServers
	}
	if host.BusinessLine != "" {
		responseData["business_line"] = host.BusinessLine
	}
	// 时间字段：始终返回，即使为空也返回 nil（让前端处理显示）
	responseData["system_boot_time"] = host.SystemBootTime
	responseData["agent_start_time"] = host.AgentStartTime
	if host.LastActiveTime != nil {
		responseData["last_active_time"] = host.LastActiveTime
	} else {
		// 如果 last_active_time 为空，使用 last_heartbeat
		responseData["last_active_time"] = host.LastHeartbeat
	}
	if len(host.Tags) > 0 {
		responseData["tags"] = host.Tags
	}
	// 添加磁盘和网卡信息（JSON 字符串）
	if host.DiskInfo != "" {
		responseData["disk_info"] = host.DiskInfo
	}
	if host.NetworkInterfaces != "" {
		responseData["network_interfaces"] = host.NetworkInterfaces
	}
	// 添加容器标识
	responseData["is_container"] = host.IsContainer
	if host.ContainerID != "" {
		responseData["container_id"] = host.ContainerID
	}

	Success(c, responseData)
}

// UpdateHostTags 更新主机标签
// PUT /api/v1/hosts/:host_id/tags
func (h *HostsHandler) UpdateHostTags(c *gin.Context) {
	hostID := c.Param("host_id")

	var req struct {
		Tags []string `json:"tags" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 验证标签数量（最多10个）
	if len(req.Tags) > 10 {
		BadRequest(c, "标签数量不能超过10个")
		return
	}

	// 验证标签长度（每个标签最多50个字符）
	for _, tag := range req.Tags {
		if len(tag) > 50 {
			BadRequest(c, "标签长度不能超过50个字符")
			return
		}
	}

	// 更新数据库
	tags := model.StringArray(req.Tags)
	if err := h.db.Model(&model.Host{}).Where("host_id = ?", hostID).Update("tags", tags).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "主机不存在")
			return
		}
		h.logger.Error("更新主机标签失败", zap.Error(err), zap.String("host_id", hostID))
		InternalError(c, "更新主机标签失败")
		return
	}

	SuccessMessage(c, "标签更新成功")
}

// formatPercent 格式化百分比
func formatPercent(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64) + "%"
}

// GetHostMetrics 获取主机监控数据
// GET /api/v1/hosts/:host_id/metrics
func (h *HostsHandler) GetHostMetrics(c *gin.Context) {
	hostID := c.Param("host_id")

	// 解析查询参数（可选的时间范围）
	var startTime, endTime *time.Time
	if startStr := c.Query("start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			startTime = &t
		}
	}
	if endStr := c.Query("end_time"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			endTime = &t
		}
	}

	// range 快捷参数：1h / 6h / 24h，优先于 start_time / end_time
	if rangeParam := c.Query("range"); rangeParam != "" && startTime == nil {
		var dur time.Duration
		switch rangeParam {
		case "6h":
			dur = 6 * time.Hour
		case "24h":
			dur = 24 * time.Hour
		default:
			dur = time.Hour
		}
		now := time.Now()
		ago := now.Add(-dur)
		startTime = &ago
		endTime = &now
	}

	// 默认最近 1 小时
	if startTime == nil {
		now := time.Now()
		oneHourAgo := now.Add(-1 * time.Hour)
		startTime = &oneHourAgo
		endTime = &now
	}

	// 查询监控数据
	metrics, err := h.metricsService.GetHostMetrics(c.Request.Context(), hostID, startTime, endTime)
	if err != nil {
		h.logger.Error("查询主机监控数据失败", zap.String("host_id", hostID), zap.Error(err))
		message := "Prometheus 数据源查询失败，请检查 Prometheus 服务和配置"
		if errors.Is(err, biz.ErrPrometheusDatasourceNotConfigured) {
			message = err.Error()
		}
		InternalError(c, message)
		return
	}

	Success(c, metrics)
}

// HostRiskStatistics 主机风险统计
type HostRiskStatistics struct {
	// 安全告警统计
	Alerts struct {
		Total    int64 `json:"total"`    // 未处理告警总数
		Critical int64 `json:"critical"` // 严重
		High     int64 `json:"high"`     // 高危
		Medium   int64 `json:"medium"`   // 中危
		Low      int64 `json:"low"`      // 低危
	} `json:"alerts"`
	// 漏洞风险统计
	Vulnerabilities struct {
		Total    int64 `json:"total"`    // 未处理高可利用漏洞总数
		Critical int64 `json:"critical"` // 严重
		High     int64 `json:"high"`     // 高危
		Medium   int64 `json:"medium"`   // 中危
		Low      int64 `json:"low"`      // 低危
	} `json:"vulnerabilities"`
	// 基线风险统计
	Baseline struct {
		Total    int64 `json:"total"`    // 待加固基线总数
		Critical int64 `json:"critical"` // 严重（基线中通常没有critical，但保留字段）
		High     int64 `json:"high"`     // 高危
		Medium   int64 `json:"medium"`   // 中危
		Low      int64 `json:"low"`      // 低危
	} `json:"baseline"`
}

// GetHostRiskStatistics 获取主机风险统计
// GET /api/v1/hosts/:host_id/risk-statistics
func (h *HostsHandler) GetHostRiskStatistics(c *gin.Context) {
	hostID := c.Param("host_id")

	var stats HostRiskStatistics

	// 查询基线风险统计（从 scan_results 表）
	var baselineResults []struct {
		Severity string
		Count    int64
	}
	h.db.Model(&model.ScanResult{}).
		Select("severity, COUNT(*) as count").
		Where("host_id = ? AND status = ?", hostID, "fail").
		Group("severity").
		Scan(&baselineResults)

	for _, r := range baselineResults {
		switch r.Severity {
		case "critical":
			stats.Baseline.Critical = r.Count
		case "high":
			stats.Baseline.High = r.Count
		case "medium":
			stats.Baseline.Medium = r.Count
		case "low":
			stats.Baseline.Low = r.Count
		}
		stats.Baseline.Total += r.Count
	}

	// 安全告警统计（从 alerts 表查询）
	var alertResults []struct {
		Severity string
		Count    int64
	}
	h.db.Model(&model.Alert{}).
		Select("severity, COUNT(*) as count").
		Where("host_id = ? AND status = ? AND source = ?", hostID, model.AlertStatusActive, model.AlertSourceBaseline).
		Group("severity").
		Scan(&alertResults)

	for _, r := range alertResults {
		switch r.Severity {
		case "critical":
			stats.Alerts.Critical = r.Count
		case "high":
			stats.Alerts.High = r.Count
		case "medium":
			stats.Alerts.Medium = r.Count
		case "low":
			stats.Alerts.Low = r.Count
		}
		stats.Alerts.Total += r.Count
	}

	// 漏洞风险统计（从 host_vulnerabilities JOIN vulnerabilities）
	var vulnResults []struct {
		Severity string
		Count    int64
	}
	h.db.Raw(`
		SELECT v.severity, COUNT(*) as count
		FROM host_vulnerabilities hv
		JOIN vulnerabilities v ON v.id = hv.vuln_id
		WHERE hv.host_id = ? AND hv.status = 'unpatched'
		GROUP BY v.severity
	`, hostID).Scan(&vulnResults)

	for _, r := range vulnResults {
		switch r.Severity {
		case "critical":
			stats.Vulnerabilities.Critical = r.Count
		case "high":
			stats.Vulnerabilities.High = r.Count
		case "medium":
			stats.Vulnerabilities.Medium = r.Count
		case "low":
			stats.Vulnerabilities.Low = r.Count
		}
		stats.Vulnerabilities.Total += r.Count
	}

	Success(c, stats)
}

// UpdateHostBusinessLineRequest 更新主机业务线请求
type UpdateHostBusinessLineRequest struct {
	BusinessLine string `json:"business_line"` // 业务线代码（空字符串表示取消绑定）
}

// UpdateHostBusinessLine 更新主机业务线
// PUT /api/v1/hosts/:host_id/business-line
func (h *HostsHandler) UpdateHostBusinessLine(c *gin.Context) {
	hostID := c.Param("host_id")

	var req UpdateHostBusinessLineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 查询主机
	var host model.Host
	if err := h.db.First(&host, "host_id = ?", hostID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "主机不存在")
			return
		}
		h.logger.Error("查询主机失败", zap.Error(err))
		InternalError(c, "查询主机失败")
		return
	}

	// 如果指定了业务线，验证业务线是否存在（使用 code 查询）
	if req.BusinessLine != "" {
		var businessLine model.BusinessLine
		if err := h.db.Where("code = ? AND enabled = ?", req.BusinessLine, true).First(&businessLine).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				BadRequest(c, "业务线不存在或已禁用")
				return
			}
			h.logger.Error("查询业务线失败", zap.Error(err))
			InternalError(c, "查询业务线失败")
			return
		}
		// 使用业务线代码（code）而不是名称（name）
		host.BusinessLine = businessLine.Code
	} else {
		// 取消绑定
		host.BusinessLine = ""
	}

	// 更新业务线
	if err := h.db.Save(&host).Error; err != nil {
		h.logger.Error("更新主机业务线失败", zap.Error(err))
		InternalError(c, "更新主机业务线失败")
		return
	}

	SuccessWithMessage(c, "更新成功", host)
}

// HostPluginResponse 主机插件响应
type HostPluginResponse struct {
	ID            uint   `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	StartTime     string `json:"start_time,omitempty"`
	UpdatedAt     string `json:"updated_at"`
	LatestVersion string `json:"latest_version"`
	NeedUpdate    bool   `json:"need_update"`
}

// GetHostPlugins 获取主机插件列表
// GET /api/v1/hosts/:host_id/plugins
func (h *HostsHandler) GetHostPlugins(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		BadRequest(c, "host_id 不能为空")
		return
	}

	// 检查主机是否存在
	var host model.Host
	if err := h.db.Where("host_id = ?", hostID).First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "主机不存在")
			return
		}
		h.logger.Error("查询主机失败", zap.String("host_id", hostID), zap.Error(err))
		InternalError(c, "查询主机失败")
		return
	}

	// 查询主机插件（排除软删除的记录）
	var hostPlugins []model.HostPlugin
	if err := h.db.Where("host_id = ? AND deleted_at IS NULL", hostID).Find(&hostPlugins).Error; err != nil {
		h.logger.Error("查询主机插件失败", zap.String("host_id", hostID), zap.Error(err))
		InternalError(c, "查询主机插件失败")
		return
	}

	// 查询最新插件版本（从 plugin_configs 表）
	var pluginConfigs []model.PluginConfig
	if err := h.db.Where("enabled = ?", true).Find(&pluginConfigs).Error; err != nil {
		h.logger.Warn("查询插件配置失败", zap.Error(err))
	}

	// 构建插件名称到最新版本的映射
	latestVersions := make(map[string]string)
	for _, pc := range pluginConfigs {
		latestVersions[pc.Name] = pc.Version
	}

	// 构建响应
	var response []HostPluginResponse
	for _, hp := range hostPlugins {
		latestVersion := latestVersions[hp.Name]
		needUpdate := latestVersion != "" && hp.Version != latestVersion

		item := HostPluginResponse{
			ID:            hp.ID,
			Name:          hp.Name,
			Version:       hp.Version,
			Status:        string(hp.Status),
			UpdatedAt:     hp.UpdatedAt.Time().Format("2006-01-02 15:04:05"),
			LatestVersion: latestVersion,
			NeedUpdate:    needUpdate,
		}
		if hp.StartTime != nil {
			item.StartTime = hp.StartTime.Time().Format("2006-01-02 15:04:05")
		}
		response = append(response, item)
	}

	// 如果主机没有插件记录，但有可用的插件配置，显示为未安装
	for name, latestVersion := range latestVersions {
		found := false
		for _, hp := range hostPlugins {
			if hp.Name == name {
				found = true
				break
			}
		}
		if !found {
			response = append(response, HostPluginResponse{
				Name:          name,
				Version:       "-",
				Status:        "not_installed",
				LatestVersion: latestVersion,
				NeedUpdate:    true,
			})
		}
	}

	Success(c, response)
}

// deleteHostByID 删除单台主机及其所有关联数据（事务内执行）
func (h *HostsHandler) deleteHostByID(tx *gorm.DB, hostID string) error {
	var host model.Host
	if err := tx.Where("host_id = ?", hostID).First(&host).Error; err != nil {
		return err
	}

	// 1. 删除扫描结果
	if err := tx.Where("host_id = ?", hostID).Delete(&model.ScanResult{}).Error; err != nil {
		return err
	}
	// 2. 删除告警
	if err := tx.Where("host_id = ?", hostID).Delete(&model.Alert{}).Error; err != nil {
		return err
	}
	// 3. 删除主机监控数据
	if err := tx.Where("host_id = ?", hostID).Delete(&model.HostMetric{}).Error; err != nil {
		return err
	}
	// 4. 删除主机插件信息
	if err := tx.Where("host_id = ?", hostID).Delete(&model.HostPlugin{}).Error; err != nil {
		return err
	}
	// 5. 删除资产数据（进程、端口、软件、容器等）
	for _, m := range []any{
		&model.Process{}, &model.Port{}, &model.Software{}, &model.Container{},
		&model.AssetUser{}, &model.Cron{}, &model.Service{},
		&model.NetInterface{}, &model.Volume{}, &model.Kmod{}, &model.App{},
	} {
		if err := tx.Where("host_id = ?", hostID).Delete(m).Error; err != nil {
			return err
		}
	}
	// 6. 删除主机漏洞关联数据
	if err := tx.Where("host_id = ?", hostID).Delete(&model.HostVulnerability{}).Error; err != nil {
		return err
	}
	// 7. 清除基线得分缓存
	if h.scoreCache != nil {
		h.scoreCache.InvalidateHostScore(hostID)
	}
	// 8. 最后删除主机记录
	return tx.Delete(&host).Error
}

// DeleteHost 删除主机
// DELETE /api/v1/hosts/:host_id
func (h *HostsHandler) DeleteHost(c *gin.Context) {
	hostID := c.Param("host_id")

	// 安全校验：在线主机不允许直接删除
	var host model.Host
	if err := h.db.Where("host_id = ?", hostID).First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "主机不存在")
			return
		}
		h.logger.Error("查询主机失败", zap.Error(err))
		InternalError(c, "查询主机失败")
		return
	}
	if host.Status == model.HostStatusOnline {
		BadRequest(c, "在线主机不允许删除，请先确认主机已离线")
		return
	}

	err := h.db.Transaction(func(tx *gorm.DB) error {
		return h.deleteHostByID(tx, hostID)
	})

	if err != nil {
		h.logger.Error("删除主机失败", zap.String("host_id", hostID), zap.Error(err))
		InternalError(c, "删除主机失败")
		return
	}

	h.logger.Info("主机已删除", zap.String("host_id", hostID))
	SuccessMessage(c, "主机删除成功")
}

// BatchDeleteHost 批量删除主机
// POST /api/v1/hosts/batch-delete
func (h *HostsHandler) BatchDeleteHost(c *gin.Context) {
	var req struct {
		HostIDs []string `json:"host_ids" binding:"required,min=1"`
		Force   bool     `json:"force"` // 强制删除（包括在线主机）
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误：host_ids 不能为空")
		return
	}

	if len(req.HostIDs) > 100 {
		BadRequest(c, "单次最多删除 100 台主机")
		return
	}

	// 单次查询获取所有请求主机的状态
	var hosts []model.Host
	if err := h.db.Where("host_id IN ?", req.HostIDs).Select("host_id, status").Find(&hosts).Error; err != nil {
		h.logger.Error("查询主机状态失败", zap.Error(err))
		InternalError(c, "查询主机状态失败")
		return
	}

	existSet := make(map[string]string, len(hosts)) // host_id -> status
	for _, host := range hosts {
		existSet[host.HostID] = string(host.Status)
	}

	// 分类：待删除 / 跳过 / 不存在
	var deleteIDs []string
	var skipped, failed int
	for _, id := range req.HostIDs {
		status, exists := existSet[id]
		if !exists {
			failed++
		} else if !req.Force && status == string(model.HostStatusOnline) {
			skipped++
		} else {
			deleteIDs = append(deleteIDs, id)
		}
	}

	if len(deleteIDs) == 0 {
		Success(c, gin.H{"deleted": 0, "failed": failed, "skipped": skipped, "total": len(req.HostIDs)})
		return
	}

	// P2-7: 拆批 500 / 事务, 防 1w 主机单事务锁 16 关联表 +100ms
	const batchSize = 500
	for start := 0; start < len(deleteIDs); start += batchSize {
		end := start + batchSize
		if end > len(deleteIDs) {
			end = len(deleteIDs)
		}
		batch := deleteIDs[start:end]
		if err := h.db.Transaction(func(tx *gorm.DB) error {
			return h.deleteHostsByIDs(tx, batch)
		}); err != nil {
			h.logger.Error("批量删除主机失败",
				zap.Error(err),
				zap.Int("batch_start", start),
				zap.Int("batch_size", len(batch)))
			InternalError(c, "批量删除主机失败")
			return
		}
	}

	deleted := len(deleteIDs)
	h.logger.Info("批量删除主机完成", zap.Int("deleted", deleted), zap.Int("failed", failed), zap.Int("skipped", skipped))
	Success(c, gin.H{"deleted": deleted, "failed": failed, "skipped": skipped, "total": len(req.HostIDs)})
}

// deleteHostsByIDs 批量删除主机及其关联数据（单事务内执行，WHERE host_id IN 批量操作）
func (h *HostsHandler) deleteHostsByIDs(tx *gorm.DB, hostIDs []string) error {
	if len(hostIDs) == 0 {
		return nil
	}

	// 按依赖顺序批量删除所有关联表
	relatedModels := []any{
		&model.ScanResult{}, &model.Alert{}, &model.HostMetric{}, &model.HostPlugin{},
		&model.Process{}, &model.Port{}, &model.Software{}, &model.Container{},
		&model.AssetUser{}, &model.Cron{}, &model.Service{},
		&model.NetInterface{}, &model.Volume{}, &model.Kmod{}, &model.App{},
		&model.HostVulnerability{},
	}
	for _, m := range relatedModels {
		if err := tx.Where("host_id IN ?", hostIDs).Delete(m).Error; err != nil {
			return fmt.Errorf("删除关联数据失败: %w", err)
		}
	}

	// 清除基线得分缓存
	if h.scoreCache != nil {
		for _, id := range hostIDs {
			h.scoreCache.InvalidateHostScore(id)
		}
	}

	// 最后删除主机记录
	if err := tx.Where("host_id IN ?", hostIDs).Delete(&model.Host{}).Error; err != nil {
		return fmt.Errorf("删除主机记录失败: %w", err)
	}

	return nil
}

// RestartAgentRequest Agent 重启请求
type RestartAgentRequest struct {
	HostIDs []string `json:"host_ids"` // 为空表示全部在线主机
}

// RestartAgent 重启 Agent
// POST /api/v1/hosts/restart-agent
func (h *HostsHandler) RestartAgent(c *gin.Context) {
	var req RestartAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 查询目标在线主机数量
	query := h.db.Model(&model.Host{}).Where("status = ?", model.HostStatusOnline)
	if len(req.HostIDs) > 0 {
		query = query.Where("host_id IN ?", req.HostIDs)
	}

	var totalCount int64
	if err := query.Count(&totalCount).Error; err != nil {
		h.logger.Error("查询在线主机数量失败", zap.Error(err))
		InternalError(c, "查询在线主机数量失败")
		return
	}

	if totalCount == 0 {
		BadRequest(c, "没有在线的目标主机")
		return
	}

	// 确定 target_type
	targetType := "all"
	if len(req.HostIDs) > 0 {
		targetType = "selected"
	}

	// 创建重启记录
	record := model.AgentRestartRecord{
		TargetType:  targetType,
		TargetHosts: model.StringArray(req.HostIDs),
		Status:      model.AgentRestartStatusPending,
		TotalCount:  int(totalCount),
	}
	if err := h.db.Create(&record).Error; err != nil {
		h.logger.Error("创建重启记录失败", zap.Error(err))
		InternalError(c, "创建重启记录失败")
		return
	}

	h.logger.Info("创建 Agent 重启记录",
		zap.Uint("record_id", record.ID),
		zap.String("target_type", targetType),
		zap.Int64("total_count", totalCount),
	)

	SuccessWithMessage(c, "重启命令已提交", gin.H{
		"record_id":   record.ID,
		"total_count": totalCount,
	})
}

// GetRestartRecords 获取 Agent 重启记录
// GET /api/v1/hosts/restart-records
func (h *HostsHandler) GetRestartRecords(c *gin.Context) {
	var records []model.AgentRestartRecord
	if err := h.db.Order("created_at DESC").Limit(20).Find(&records).Error; err != nil {
		h.logger.Error("查询重启记录失败", zap.Error(err))
		InternalError(c, "查询重启记录失败")
		return
	}

	Success(c, records)
}

// BatchUpdateTags 批量更新主机标签
// POST /api/v1/hosts/batch-update-tags
func (h *HostsHandler) BatchUpdateTags(c *gin.Context) {
	var req struct {
		HostIDs []string `json:"host_ids" binding:"required,min=1"`
		Tags    []string `json:"tags" binding:"required"`
		Mode    string   `json:"mode" binding:"required,oneof=append replace"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误：host_ids、tags、mode(append/replace) 必填")
		return
	}

	if len(req.HostIDs) > 100 {
		BadRequest(c, "单次最多操作 100 台主机")
		return
	}

	// 校验标签
	for _, tag := range req.Tags {
		if len(tag) > 50 {
			BadRequest(c, "标签长度不能超过50个字符")
			return
		}
	}

	var updated, failed int
	for _, hostID := range req.HostIDs {
		var finalTags model.StringArray

		if req.Mode == "append" {
			// 追加模式：读取现有标签，合并去重
			var host model.Host
			if err := h.db.Where("host_id = ?", hostID).First(&host).Error; err != nil {
				failed++
				continue
			}
			tagSet := make(map[string]struct{})
			for _, t := range host.Tags {
				tagSet[t] = struct{}{}
			}
			for _, t := range req.Tags {
				tagSet[t] = struct{}{}
			}
			for t := range tagSet {
				finalTags = append(finalTags, t)
			}
		} else {
			// 替换模式
			finalTags = model.StringArray(req.Tags)
		}

		// 校验合并后标签总数
		if len(finalTags) > 10 {
			failed++
			continue
		}

		if err := h.db.Model(&model.Host{}).Where("host_id = ?", hostID).Update("tags", finalTags).Error; err != nil {
			failed++
			h.logger.Warn("批量更新标签失败", zap.String("host_id", hostID), zap.Error(err))
			continue
		}
		updated++
	}

	h.logger.Info("批量更新标签完成", zap.Int("updated", updated), zap.Int("failed", failed))
	Success(c, gin.H{"updated": updated, "failed": failed})
}

// BatchUpdateBusinessLine 批量更新主机业务线
// POST /api/v1/hosts/batch-update-business-line
func (h *HostsHandler) BatchUpdateBusinessLine(c *gin.Context) {
	var req struct {
		HostIDs      []string `json:"host_ids" binding:"required,min=1"`
		BusinessLine string   `json:"business_line"` // 空字符串表示取消绑定
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("批量更新业务线参数绑定失败", zap.Error(err))
		BadRequest(c, "请求参数错误：host_ids 不能为空")
		return
	}

	if len(req.HostIDs) > 100 {
		BadRequest(c, "单次最多操作 100 台主机")
		return
	}

	// 如果指定了业务线，验证其存在且启用
	if req.BusinessLine != "" {
		var businessLine model.BusinessLine
		if err := h.db.Where("code = ? AND enabled = ?", req.BusinessLine, true).First(&businessLine).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				BadRequest(c, "业务线不存在或已禁用")
				return
			}
			h.logger.Error("查询业务线失败", zap.Error(err))
			InternalError(c, "查询业务线失败")
			return
		}
	}

	// 单事务批量更新
	result := h.db.Model(&model.Host{}).Where("host_id IN ?", req.HostIDs).Update("business_line", req.BusinessLine)
	if result.Error != nil {
		h.logger.Error("批量更新业务线失败", zap.Error(result.Error))
		InternalError(c, "批量更新业务线失败")
		return
	}

	h.logger.Info("批量更新业务线完成", zap.Int64("updated", result.RowsAffected))
	Success(c, gin.H{"updated": result.RowsAffected})
}
