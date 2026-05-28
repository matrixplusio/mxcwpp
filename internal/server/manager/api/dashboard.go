// Package api 提供 HTTP API 处理器
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
	"github.com/imkerbos/mxsec-platform/internal/server/prometheus"
)

const (
	dashboardCacheKey = "mxsec:cache:dashboard:stats"
	dashboardCacheTTL = 30 * time.Second
)

// DashboardHandler 是 Dashboard API 处理器
type DashboardHandler struct {
	db          *gorm.DB
	logger      *zap.Logger
	chConn      chdriver.Conn      // 可为 nil（ClickHouse 未启用时降级为 0）
	redisClient *redis.Client      // 可为 nil（Redis 未启用时不缓存）
	acRegistry  *sd.Registry       // 可为 nil（单机部署降级为始终 healthy）
	promClient  *prometheus.Client // 可为 nil；用于 Manager 自检（5xx 错误率）
	sfGroup     singleflight.Group
}

// NewDashboardHandler 创建 Dashboard 处理器
func NewDashboardHandler(db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn, redisClient *redis.Client, acRegistry *sd.Registry, promClient *prometheus.Client) *DashboardHandler {
	return &DashboardHandler{
		db:          db,
		logger:      logger,
		chConn:      chConn,
		redisClient: redisClient,
		acRegistry:  acRegistry,
		promClient:  promClient,
	}
}

// GetDashboardStats 获取 Dashboard 统计数据
// GET /api/v1/dashboard/stats
func (h *DashboardHandler) GetDashboardStats(c *gin.Context) {
	ctx := c.Request.Context()

	// 尝试从 Redis 缓存读取
	if h.redisClient != nil {
		if cached, err := h.redisClient.Get(ctx, dashboardCacheKey).Bytes(); err == nil {
			c.Data(http.StatusOK, "application/json; charset=utf-8", cached)
			return
		}
	}

	// singleflight：同一时刻只有一个 goroutine 计算，其余等待复用结果
	// 防止缓存过期瞬间的惊群效应
	jsonBytes, err, _ := h.sfGroup.Do(dashboardCacheKey, func() (interface{}, error) {
		return h.computeStats()
	})
	if err != nil {
		h.logger.Error("计算 Dashboard 统计失败", zap.Error(err))
		InternalError(c, "统计数据查询失败")
		return
	}

	data := jsonBytes.([]byte)

	// 写入 Redis 缓存
	if h.redisClient != nil {
		h.redisClient.Set(ctx, dashboardCacheKey, data, dashboardCacheTTL)
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

// computeStats 计算所有 Dashboard 统计数据并序列化为 JSON
func (h *DashboardHandler) computeStats() ([]byte, error) {
	stats := gin.H{}

	// 1. 资产概览（单次 GROUP BY 替代 6 条独立 COUNT）
	type hostCountRow struct {
		IsContainer bool
		Status      string
		Cnt         int64
	}
	var hostCountRows []hostCountRow
	h.db.Model(&model.Host{}).
		Select("is_container, status, COUNT(*) AS cnt").
		Group("is_container, status").
		Scan(&hostCountRows)

	var hostCount, containerCount, onlineHostCount, onlineContainerCount, offlineHostCount, offlineContainerCount int64
	for _, r := range hostCountRows {
		if !r.IsContainer {
			hostCount += r.Cnt
			if r.Status == "online" {
				onlineHostCount = r.Cnt
			} else if r.Status == "offline" {
				offlineHostCount += r.Cnt
			}
		} else {
			containerCount += r.Cnt
			if r.Status == "online" {
				onlineContainerCount = r.Cnt
			} else if r.Status == "offline" {
				offlineContainerCount += r.Cnt
			}
		}
	}

	stats["hosts"] = hostCount
	var clusterCount int64
	h.db.Model(&model.KubeCluster{}).Count(&clusterCount)
	stats["clusters"] = clusterCount
	stats["containers"] = containerCount
	stats["onlineAgents"] = onlineHostCount + onlineContainerCount
	stats["offlineAgents"] = offlineHostCount + offlineContainerCount

	// 计算Agent数量变化（较昨日）
	onlineChange, offlineChange := h.calculateAgentChanges()
	stats["onlineAgentsChange"] = onlineChange
	stats["offlineAgentsChange"] = offlineChange

	// 2. 入侵告警统计（简化实现，后续扩展）
	var pendingAlerts int64
	h.db.Model(&model.Alert{}).Where("status = ?", model.AlertStatusActive).Count(&pendingAlerts)
	stats["pendingAlerts"] = pendingAlerts

	// 3. 漏洞风险统计
	var pendingVulns int64
	h.db.Model(&model.Vulnerability{}).Where("status = ?", "unpatched").Count(&pendingVulns)
	stats["pendingVulnerabilities"] = pendingVulns

	var latestVuln model.Vulnerability
	if err := h.db.Order("discovered_at DESC").First(&latestVuln).Error; err == nil {
		stats["vulnDbUpdateTime"] = latestVuln.DiscoveredAt
	} else {
		stats["vulnDbUpdateTime"] = ""
	}

	var hotPatchCount int64
	h.db.Model(&model.Vulnerability{}).Where("status = ?", "patched").Count(&hotPatchCount)
	stats["hotPatchCount"] = hotPatchCount

	// 4. 基线风险统计（单次聚合查询替代 5 条独立 COUNT）
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	var baselineFailCount int64
	h.db.Model(&model.ScanResult{}).
		Where("status = ? AND checked_at >= ?", "fail", sevenDaysAgo).
		Count(&baselineFailCount)
	stats["baselineFailCount"] = baselineFailCount

	baselineHardeningPercent, baselineHostPercent := h.calculateBaselinePercentages()
	stats["baselineHardeningPercent"] = baselineHardeningPercent
	stats["baselineHostPercent"] = baselineHostPercent

	// 5. 基线风险 Top 3（单次 JOIN + GROUP BY 替代 N+1 查询）
	baselineRisks := h.getBaselineRisksTop3()
	stats["baselineRisks"] = baselineRisks

	// 6. Agent 资源使用统计（从 ClickHouse host_metrics_hourly 物化视图查询）
	avgCPU, avgMem := h.queryAvgMetrics()
	stats["avgCpuUsage"] = avgCPU
	stats["avgMemoryUsage"] = avgMem
	// CPU/内存同比变化：对比 24 小时前同时段
	yesterdayCPU, yesterdayMem := h.queryAvgMetricsYesterday()
	if yesterdayCPU > 0 {
		stats["avgCpuUsageChange"] = math.Round((avgCPU-yesterdayCPU)*10) / 10
	} else {
		stats["avgCpuUsageChange"] = 0.0
	}
	if yesterdayMem > 0 {
		stats["avgMemoryUsageChange"] = math.Round((avgMem-yesterdayMem)*10) / 10
	} else {
		stats["avgMemoryUsageChange"] = 0.0
	}

	// 7. 主机风险分布百分比
	var alertHostCount int64
	h.db.Model(&model.Alert{}).Where("status = ?", model.AlertStatusActive).Distinct("host_id").Count(&alertHostCount)
	totalHosts := hostCount + containerCount
	if totalHosts > 0 {
		stats["hostAlertPercent"] = float64(alertHostCount) / float64(totalHosts) * 100.0
	} else {
		stats["hostAlertPercent"] = 0.0
	}
	var vulnHostCount int64
	h.db.Model(&model.HostVulnerability{}).Where("status = ?", "unpatched").Distinct("host_id").Count(&vulnHostCount)
	if totalHosts > 0 {
		stats["vulnHostPercent"] = float64(vulnHostCount) / float64(totalHosts) * 100.0
	} else {
		stats["vulnHostPercent"] = 0.0
	}
	// 检测告警：来自 CEL 规则引擎的告警（category = 'detection_rule'）
	var edrAlertHostCount int64
	h.db.Model(&model.Alert{}).Where("status = ? AND category = ?", model.AlertStatusActive, "detection_rule").Distinct("host_id").Count(&edrAlertHostCount)
	if totalHosts > 0 {
		stats["edrAlertPercent"] = math.Round(float64(edrAlertHostCount)/float64(totalHosts)*1000) / 10
	} else {
		stats["edrAlertPercent"] = 0.0
	}
	// 病毒主机百分比：扫描结果中有未处理威胁的主机
	var virusHostCount int64
	h.db.Model(&model.AntivirusScanResult{}).Where("action = ?", "detected").Distinct("host_id").Count(&virusHostCount)
	if totalHosts > 0 {
		stats["virusHostPercent"] = math.Round(float64(virusHostCount)/float64(totalHosts)*1000) / 10
	} else {
		stats["virusHostPercent"] = 0.0
	}

	// 8. 后端服务状态
	serviceStatus := gin.H{
		"database":    h.checkDatabaseStatus(),
		"agentcenter": h.checkAgentCenterStatus(),
		"manager":     h.checkManagerSelfStatus(), // 5xx 错误率自检，不再硬编码 healthy
	}
	stats["serviceStatus"] = serviceStatus

	// 9. 告警趋势（最近 30 天，按天 + 等级聚合；前端按 7d/30d 本地切片）
	stats["alertTrend"] = h.queryAlertTrend()

	// 10. 最新告警（最近 5 条 active 告警，精简字段）
	stats["latestAlerts"] = h.queryLatestAlerts()

	// 11. 安全态势综合评分
	// 替代 UI 端硬编码的 82 默认值；综合 critical/high 告警 + 漏洞 + 受影响主机比例 + 合规率
	criticalAlertCount, highAlertCount := h.countAlertsBySeverity()
	criticalVulnCount, highVulnCount := h.countVulnsBySeverity()
	stats["criticalAlerts"] = criticalAlertCount
	stats["highAlerts"] = highAlertCount
	stats["securityScore"] = h.computeSecurityScore(
		criticalAlertCount, highAlertCount,
		criticalVulnCount, highVulnCount,
		vulnHostCount, totalHosts,
		baselineHardeningPercent,
	)

	stats = sanitizeDashboardValue(stats).(gin.H)

	return json.Marshal(gin.H{"code": 0, "data": stats})
}

// countAlertsBySeverity 按 severity 统计活跃告警数（仅 critical/high）
func (h *DashboardHandler) countAlertsBySeverity() (critical, high int64) {
	var rows []struct {
		Severity string `gorm:"column:severity"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	h.db.Model(&model.Alert{}).
		Select("severity, COUNT(*) as cnt").
		Where("status = ?", model.AlertStatusActive).
		Group("severity").
		Scan(&rows)
	for _, r := range rows {
		switch r.Severity {
		case "critical":
			critical = r.Cnt
		case "high":
			high = r.Cnt
		}
	}
	return
}

// countVulnsBySeverity 按 severity 统计未修复漏洞数（仅 critical/high）
func (h *DashboardHandler) countVulnsBySeverity() (critical, high int64) {
	var rows []struct {
		Severity string `gorm:"column:severity"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	h.db.Model(&model.Vulnerability{}).
		Select("severity, COUNT(*) as cnt").
		Where("status = ?", "unpatched").
		Group("severity").
		Scan(&rows)
	for _, r := range rows {
		switch r.Severity {
		case "critical":
			critical = r.Cnt
		case "high":
			high = r.Cnt
		}
	}
	return
}

// computeSecurityScore 计算安全态势综合评分（0-100）
//
// 维度（基础 100 分，按权重扣分；最后用合规率修正 ±）：
//
//	告警：critical × 2（封顶 -30），high × 0.5（封顶 -20）
//	漏洞：critical × 0.05（封顶 -20），high × 0.01（封顶 -10）
//	影响范围：受漏洞影响主机比例 × 20（最多 -20）
//	合规率：(baseline_hardening_percent - 80) × 0.1（范围 ±2）
//
// 设计目标：避免 UI 端硬编码"健康"误导；与漏洞/告警数量同向变化。
func (h *DashboardHandler) computeSecurityScore(
	criticalAlerts, highAlerts int64,
	criticalVulns, highVulns int64,
	vulnHosts, totalHosts int64,
	baselineCompliance float64,
) float64 {
	score := 100.0

	score -= math.Min(float64(criticalAlerts)*2.0, 30.0)
	score -= math.Min(float64(highAlerts)*0.5, 20.0)

	score -= math.Min(float64(criticalVulns)*0.05, 20.0)
	score -= math.Min(float64(highVulns)*0.01, 10.0)

	if totalHosts > 0 {
		affectedRatio := float64(vulnHosts) / float64(totalHosts)
		if affectedRatio > 1.0 {
			affectedRatio = 1.0
		}
		score -= affectedRatio * 20.0
	}

	score += (baselineCompliance - 80.0) * 0.1

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return math.Round(score*10) / 10
}

// calculateAgentChanges 计算Agent数量变化（较昨日）
// 较昨日 = 昨天结束时的数量 - 前天结束时的数量，展示昨天一整天的净变化
// 例：4/22 新增 100 台 → 4/22 显示 0 → 4/23 显示 +100 → 4/24 显示 0
func (h *DashboardHandler) calculateAgentChanges() (int, int) {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	yesterdayStart := todayStart.AddDate(0, 0, -1)
	dayBeforeStart := yesterdayStart.AddDate(0, 0, -1)

	// 昨天结束时的在线 Agent：昨天结束前已创建，且在昨天有心跳活动
	var yesterdayEndOnline int64
	h.db.Model(&model.Host{}).
		Where("created_at < ? AND last_heartbeat >= ?", todayStart, yesterdayStart).
		Count(&yesterdayEndOnline)

	// 昨天结束时的 Agent 总数
	var yesterdayEndTotal int64
	h.db.Model(&model.Host{}).
		Where("created_at < ?", todayStart).
		Count(&yesterdayEndTotal)

	// 前天结束时的在线 Agent：前天结束前已创建，且在前天有心跳活动
	var dayBeforeEndOnline int64
	h.db.Model(&model.Host{}).
		Where("created_at < ? AND last_heartbeat >= ?", yesterdayStart, dayBeforeStart).
		Count(&dayBeforeEndOnline)

	// 前天结束时的 Agent 总数
	var dayBeforeEndTotal int64
	h.db.Model(&model.Host{}).
		Where("created_at < ?", yesterdayStart).
		Count(&dayBeforeEndTotal)

	// 昨天结束时的离线数
	yesterdayEndOffline := yesterdayEndTotal - yesterdayEndOnline
	if yesterdayEndOffline < 0 {
		yesterdayEndOffline = 0
	}

	// 前天结束时的离线数
	dayBeforeEndOffline := dayBeforeEndTotal - dayBeforeEndOnline
	if dayBeforeEndOffline < 0 {
		dayBeforeEndOffline = 0
	}

	onlineChange := int(yesterdayEndOnline) - int(dayBeforeEndOnline)
	offlineChange := int(yesterdayEndOffline) - int(dayBeforeEndOffline)

	return onlineChange, offlineChange
}

// calculateBaselinePercentages 计算基线合规率和存在高危基线问题的主机百分比
// 优化：单次聚合查询替代 5 条独立 COUNT
func (h *DashboardHandler) calculateBaselinePercentages() (float64, float64) {
	var result struct {
		PassCount           int64 `gorm:"column:pass_count"`
		FailCount           int64 `gorm:"column:fail_count"`
		MediumPlusFailCount int64 `gorm:"column:medium_plus_fail_count"`
	}
	h.db.Raw(`
		SELECT
			SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) AS pass_count,
			SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) AS fail_count,
			SUM(CASE WHEN status = 'fail' AND severity IN ('medium','high','critical') THEN 1 ELSE 0 END) AS medium_plus_fail_count
		FROM scan_results
	`).Scan(&result)

	totalResults := result.PassCount + result.FailCount
	if totalResults == 0 {
		return 100.0, 0.0
	}

	// 整体合规率 = 通过项 / 总检查项
	complianceRate := float64(result.PassCount) / float64(totalResults) * 100.0
	if complianceRate > 100.0 {
		complianceRate = 100.0
	}

	// 基线不合规率 = 中危及以上失败项 / 总检查项
	noncomplianceRate := float64(result.MediumPlusFailCount) / float64(totalResults) * 100.0

	return complianceRate, noncomplianceRate
}

// getBaselineRisksTop3 获取基线风险 Top 3
// 优化：单次 JOIN+GROUP BY 替代 N×3+1 条查询
func (h *DashboardHandler) getBaselineRisksTop3() []gin.H {
	var rows []struct {
		PolicyID      string `gorm:"column:policy_id"`
		Name          string `gorm:"column:name"`
		CriticalCount int64  `gorm:"column:critical_count"`
		HighCount     int64  `gorm:"column:high_count"`
		MediumCount   int64  `gorm:"column:medium_count"`
		LowCount      int64  `gorm:"column:low_count"`
	}

	h.db.Raw(`
		SELECT p.id AS policy_id, p.name,
			SUM(CASE WHEN sr.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
			SUM(CASE WHEN sr.severity = 'high'     THEN 1 ELSE 0 END) AS high_count,
			SUM(CASE WHEN sr.severity = 'medium'   THEN 1 ELSE 0 END) AS medium_count,
			SUM(CASE WHEN sr.severity = 'low'      THEN 1 ELSE 0 END) AS low_count
		FROM scan_results sr
		INNER JOIN policies p ON p.id = sr.policy_id
		WHERE sr.status = 'fail'
		GROUP BY p.id, p.name
		ORDER BY (SUM(CASE WHEN sr.severity = 'critical' THEN 4
		               WHEN sr.severity = 'high'     THEN 3
		               WHEN sr.severity = 'medium'   THEN 2
		               ELSE 1 END)) DESC
		LIMIT 3
	`).Scan(&rows)

	top3 := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		top3 = append(top3, gin.H{
			"name":     r.Name,
			"critical": r.CriticalCount,
			"high":     r.HighCount,
			"medium":   r.MediumCount,
			"low":      r.LowCount,
		})
	}
	return top3
}

// queryAvgMetrics 从 ClickHouse host_metrics_hourly 查询过去 1 小时全局平均 CPU/内存使用率
func (h *DashboardHandler) queryAvgMetrics() (float64, float64) {
	if h.chConn == nil {
		return 0, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	row := h.chConn.QueryRow(ctx,
		`SELECT round(avgMerge(cpu_avg), 1), round(avgMerge(mem_avg), 1)
		 FROM host_metrics_hourly
		 WHERE hour >= subtractHours(now(), 1)`)

	var avgCPU, avgMem float64
	if err := row.Scan(&avgCPU, &avgMem); err != nil {
		h.logger.Warn("ClickHouse 查询 host_metrics_hourly 失败", zap.Error(err))
		return 0, 0
	}
	if !isFiniteFloat(avgCPU) || !isFiniteFloat(avgMem) {
		h.logger.Debug("ClickHouse 返回了非有限 Dashboard 指标",
			zap.Float64("avg_cpu", avgCPU),
			zap.Float64("avg_mem", avgMem))
		return 0, 0
	}
	return avgCPU, avgMem
}

// queryAvgMetricsYesterday 查询 24 小时前同时段的平均 CPU/内存，用于计算同比变化
func (h *DashboardHandler) queryAvgMetricsYesterday() (float64, float64) {
	if h.chConn == nil {
		return 0, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	row := h.chConn.QueryRow(ctx,
		`SELECT round(avgMerge(cpu_avg), 1), round(avgMerge(mem_avg), 1)
		 FROM host_metrics_hourly
		 WHERE hour >= subtractHours(now(), 25) AND hour < subtractHours(now(), 24)`)

	var avgCPU, avgMem float64
	if err := row.Scan(&avgCPU, &avgMem); err != nil {
		return 0, 0
	}
	if !isFiniteFloat(avgCPU) || !isFiniteFloat(avgMem) {
		return 0, 0
	}
	return avgCPU, avgMem
}

func isFiniteFloat(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func sanitizeDashboardValue(v interface{}) interface{} {
	switch value := v.(type) {
	case float64:
		if !isFiniteFloat(value) {
			return 0.0
		}
		return value
	case float32:
		if !isFiniteFloat(float64(value)) {
			return float32(0)
		}
		return value
	case gin.H:
		sanitized := make(gin.H, len(value))
		for k, item := range value {
			sanitized[k] = sanitizeDashboardValue(item)
		}
		return sanitized
	case []gin.H:
		sanitized := make([]gin.H, len(value))
		for i, item := range value {
			sanitized[i] = sanitizeDashboardValue(item).(gin.H)
		}
		return sanitized
	case []interface{}:
		sanitized := make([]interface{}, len(value))
		for i, item := range value {
			sanitized[i] = sanitizeDashboardValue(item)
		}
		return sanitized
	default:
		return v
	}
}

// queryAlertTrend 查询最近 30 天告警趋势（按天+等级聚合）
func (h *DashboardHandler) queryAlertTrend() []gin.H {
	type trendRow struct {
		Date     string `gorm:"column:date"`
		Critical int64  `gorm:"column:critical"`
		High     int64  `gorm:"column:high"`
		Medium   int64  `gorm:"column:medium"`
		Low      int64  `gorm:"column:low"`
	}
	var rows []trendRow
	h.db.Raw(`
		SELECT DATE(last_seen_at) AS date,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
			SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
			SUM(CASE WHEN severity = 'medium'   THEN 1 ELSE 0 END) AS medium,
			SUM(CASE WHEN severity = 'low'      THEN 1 ELSE 0 END) AS low
		FROM alerts
		WHERE last_seen_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
		GROUP BY DATE(last_seen_at)
		ORDER BY date
	`).Scan(&rows)

	trend := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		trend = append(trend, gin.H{
			"date":     r.Date,
			"critical": r.Critical,
			"high":     r.High,
			"medium":   r.Medium,
			"low":      r.Low,
		})
	}
	return trend
}

// queryLatestAlerts 查询最近 5 条未处理告警（精简字段 + 主机名）
func (h *DashboardHandler) queryLatestAlerts() []gin.H {
	type alertRow struct {
		ID         uint      `gorm:"column:id"`
		Title      string    `gorm:"column:title"`
		Severity   string    `gorm:"column:severity"`
		Hostname   string    `gorm:"column:hostname"`
		LastSeenAt time.Time `gorm:"column:last_seen_at"`
	}
	var rows []alertRow
	h.db.Table("alerts").
		Select("alerts.id, alerts.title, alerts.severity, hosts.hostname, alerts.last_seen_at").
		Joins("LEFT JOIN hosts ON hosts.host_id = alerts.host_id").
		Where("alerts.status = ?", model.AlertStatusActive).
		Order("alerts.last_seen_at DESC").
		Limit(5).
		Scan(&rows)

	latest := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		latest = append(latest, gin.H{
			"id":           r.ID,
			"title":        r.Title,
			"severity":     r.Severity,
			"hostname":     r.Hostname,
			"last_seen_at": r.LastSeenAt.Format(model.TimeFormat),
		})
	}
	return latest
}

// checkDatabaseStatus 检查数据库连接状态
func (h *DashboardHandler) checkDatabaseStatus() string {
	if h.db == nil {
		return "error"
	}

	sqlDB, err := h.db.DB()
	if err != nil {
		return "error"
	}

	done := make(chan error, 1)
	go func() {
		done <- sqlDB.Ping()
	}()

	select {
	case err := <-done:
		if err != nil {
			return "error"
		}
		return "healthy"
	case <-time.After(2 * time.Second):
		return "warning"
	}
}

// checkManagerSelfStatus Manager 自身健康自检（不再硬编码 "healthy"）。
//
// 自检逻辑：
//  1. 本进程在跑 → 进程级 alive（默认前提）
//  2. 若已注入 Prometheus 客户端，查 1 分钟 HTTP 5xx 错误率：
//     - 错误率 > 5% → "warning"
//     - 否则 → "healthy"
//  3. Prom 未配置时 → "healthy"（无数据等价于无异常）
//
// 真正的"挂了"由外部探针检测（Prometheus blackbox / k8s liveness probe），
// 这里只能反映"运行中但不健康"的灰色状态。
func (h *DashboardHandler) checkManagerSelfStatus() string {
	if h.promClient == nil {
		return "healthy"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	totalRes, err := h.promClient.QueryInstant(ctx, `sum(rate(mxsec_http_requests_total[1m]))`, nil)
	if err != nil || totalRes == nil || len(totalRes.Data.Result) == 0 {
		return "healthy"
	}
	totalVal := parsePromScalar(totalRes.Data.Result[0].Value)
	if totalVal <= 0 {
		return "healthy" // 无流量
	}

	errRes, err := h.promClient.QueryInstant(ctx, `sum(rate(mxsec_http_requests_total{status_code=~"5.."}[1m]))`, nil)
	if err != nil || errRes == nil || len(errRes.Data.Result) == 0 {
		return "healthy"
	}
	errVal := parsePromScalar(errRes.Data.Result[0].Value)
	if errVal/totalVal > 0.05 {
		return "warning"
	}
	return "healthy"
}

// parsePromScalar 从 PromQL 即时查询的 Value（[timestamp, value]）解析 float。
// 无法解析时返回 0。
func parsePromScalar(v []interface{}) float64 {
	if len(v) < 2 {
		return 0
	}
	switch val := v[1].(type) {
	case string:
		var f float64
		if _, err := fmt.Sscanf(val, "%f", &f); err != nil {
			return 0
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0
		}
		return f
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return 0
		}
		return val
	}
	return 0
}

// checkAgentCenterStatus 检查 AgentCenter 服务状态
// 通过 SD registry 查询 AC 实例心跳健康状态（取代原 TCP 端口探测，避免硬编码 hostname）
func (h *DashboardHandler) checkAgentCenterStatus() string {
	if h.acRegistry == nil {
		// 未注入 registry（理论上不会出现，兜底）
		return "warning"
	}

	healthy := h.acRegistry.ListHealthy()
	if len(healthy) > 0 {
		return "healthy"
	}

	// 区分"无任何 AC 注册"和"全部 AC 不健康"
	all := h.acRegistry.ListAll()
	if len(all) == 0 {
		return "warning"
	}
	return "error"
}
