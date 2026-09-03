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

	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/prometheus"
)

const (
	dashboardCacheKey = "mxcwpp:cache:dashboard:stats"
	// TTL 远大于刷新间隔：后台 warmer 每 dashboardWarmInterval 重算并续期，
	// 用户请求始终命中热缓存（~1ms）。即便某次 warmer 失败，旧值仍可服务到 TTL，
	// 不让用户撞上 2-3s 冷查询（computeStats 扫 scan_results 等大表）。
	dashboardCacheTTL     = 5 * time.Minute
	dashboardWarmInterval = 60 * time.Second
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
	h := &DashboardHandler{
		db:          db,
		logger:      logger,
		chConn:      chConn,
		redisClient: redisClient,
		acRegistry:  acRegistry,
		promClient:  promClient,
	}
	// 后台缓存预热：仅在 Redis 可用时启动。把 2-3s 的 computeStats 移出请求路径，
	// 用户始终命中热缓存。进程级生命周期（退出即随进程结束）。
	if redisClient != nil {
		go h.cacheWarmLoop(context.Background())
	}
	return h
}

// cacheWarmLoop 周期性重算 Dashboard 统计并写入 Redis，使前端请求始终命中热缓存。
func (h *DashboardHandler) cacheWarmLoop(ctx context.Context) {
	warm := func() {
		data, err := h.computeStats()
		if err != nil {
			h.logger.Warn("Dashboard 缓存预热失败", zap.Error(err))
			return
		}
		h.redisClient.Set(ctx, dashboardCacheKey, data, dashboardCacheTTL)
	}
	warm() // 启动即预热一次，避免首请求冷查询
	ticker := time.NewTicker(dashboardWarmInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			warm()
		}
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

	// 3. 漏洞风险统计:数"真实可修 OS 主机漏洞"(host_vulnerabilities 实例,dnf/apt 系统包 + pre-check 确认
	// 已装有修复),与漏洞列表(默认 OS)+雷达口径一致。
	// 不用 vulnerabilities.status='unpatched'——那是 CVE 级 advisory rollup(含全源目录 + 不可信 rollup)，
	// 会把待修数虚报成 2w+(实际真实待修仅数百)。
	var pendingVulns int64
	h.db.Table("host_vulnerabilities AS hv").
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Where("hv.status = ? AND v.source <> ? AND hv.precheck_status IN ?",
			"unpatched", "osv", []string{"available", "outdated_repo"}).
		Count(&pendingVulns)
	stats["pendingVulnerabilities"] = pendingVulns

	var latestVuln model.Vulnerability
	if err := h.db.Order("discovered_at DESC").First(&latestVuln).Error; err == nil {
		stats["vulnDbUpdateTime"] = latestVuln.DiscoveredAt
	} else {
		stats["vulnDbUpdateTime"] = ""
	}

	// 已修复数:数 host_vulnerabilities 实例级 patched(舰队真实已修实例),与 pendingVulnerabilities/
	// countVulnsBySeverity 的 host_vuln 口径对齐。
	// 不用 vulnerabilities.status='patched'——那是 CVE 级 advisory rollup(仅当某 CVE 全舰队主机都修才置
	// patched),绝大多数恒 unpatched,计数长期近 0 失真。
	var hotPatchCount int64
	h.db.Model(&model.HostVulnerability{}).Where("status = ?", "patched").Count(&hotPatchCount)
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
	// 主机告警维：按"有 active incident 的主机"算，而非任意 active 告警。
	// CEL 检测流被未治理的 behavior 规则(fork/内核模块/SSH配置等 high/critical)刷满全舰队,
	// 任意告警口径下几乎每台都命中→比例恒 ~100%、雷达该维恒塌陷。incident 是经关联 + 流行度
	// 过滤后的真实威胁信号(见 scheduler.incident_correlation prevalence filter),口径如实。
	var alertHostCount int64
	h.db.Model(&model.Incident{}).Where("status = ?", model.IncidentStatusActive).Distinct("host_id").Count(&alertHostCount)
	totalHosts := hostCount + containerCount
	if totalHosts > 0 {
		// clamp 100：incident host_id 可能含已下线/容器等非当前主机集，比例 >100 会让雷达该维越界塌陷
		p := float64(alertHostCount) / float64(totalHosts) * 100.0
		if p > 100 {
			p = 100
		}
		stats["hostAlertPercent"] = math.Round(p*10) / 10
	} else {
		stats["hostAlertPercent"] = 0.0
	}
	// vulnHostCount 只算"真实可修 OS 漏洞"的受影响主机(dnf/apt 系统包+precheck 已装有修复)，
	// 不是"有任意 unpatched 漏洞"——否则 osv 应用依赖 + 未核查项让几乎每台都命中，比例恒 ~100%、雷达恒 0。
	var vulnHostCount int64
	h.db.Table("host_vulnerabilities AS hv").
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Where("hv.status = ? AND v.source <> ? AND hv.precheck_status IN ?",
			"unpatched", "osv", []string{"available", "outdated_repo"}).
		Distinct("hv.host_id").Count(&vulnHostCount)
	if totalHosts > 0 {
		stats["vulnHostPercent"] = math.Round(float64(vulnHostCount)/float64(totalHosts)*1000) / 10
	} else {
		stats["vulnHostPercent"] = 0.0
	}
	// 检测维：CEL 检测引擎归因的真实威胁——有 active incident 且成员含 detection 源告警的主机。
	// 原口径 category='detection_rule' 恒空(CEL 告警 category 是 persistence/impact 等语义分类,
	// 从不写 'detection_rule')→ 该维恒 0;且前端读 detectionAlertPercent 而后端旧发 edrAlertPercent,
	// 键名不匹配→ NaN 无数据。改挂 incident + detection 源,与主机告警维同源(经关联/流行度过滤)但限 CEL 归因。
	var detectionAlertHostCount int64
	h.db.Model(&model.Incident{}).
		Joins("JOIN alerts a ON a.host_id = incidents.host_id AND a.status = ? AND a.source = ?",
			model.AlertStatusActive, model.AlertSourceDetection).
		Where("incidents.status = ?", model.IncidentStatusActive).
		Distinct("incidents.host_id").Count(&detectionAlertHostCount)
	if totalHosts > 0 {
		stats["detectionAlertPercent"] = math.Round(float64(detectionAlertHostCount)/float64(totalHosts)*1000) / 10
	} else {
		stats["detectionAlertPercent"] = 0.0
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

	// 10b. 攻击故事线 TopN + 总数
	storylineTop, storylineCount := h.queryStorylineTop()
	stats["storylineTop"] = storylineTop
	stats["storylineCount"] = storylineCount

	// 10c. 告警严重等级分布 (medium/low 补充 Dashboard 饼图)
	mediumAlertCount, lowAlertCount := h.countAlertsBySeverityLow()
	stats["mediumAlerts"] = mediumAlertCount
	stats["lowAlerts"] = lowAlertCount

	// 11. 安全态势综合评分
	// 替代 UI 端硬编码的 82 默认值；综合 critical/high 告警 + 漏洞 + 受影响主机比例 + 合规率
	criticalAlertCount, highAlertCount := h.countAlertsBySeverity()
	criticalVulnCount, highVulnCount := h.countVulnsBySeverity()
	stats["criticalAlerts"] = criticalAlertCount
	stats["highAlerts"] = highAlertCount
	stats["totalAgents"] = onlineHostCount + offlineHostCount + onlineContainerCount + offlineContainerCount
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
// countAlertsBySeverityLow 仿 countAlertsBySeverity 统计 medium / low active 告警.
func (h *DashboardHandler) countAlertsBySeverityLow() (medium, low int64) {
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
		case "medium":
			medium = r.Cnt
		case "low":
			low = r.Cnt
		}
	}
	return
}

// queryStorylineTop 返回最近 5 条高风险攻击故事线 + 总数 (用于 Dashboard 攻击故事线卡).
func (h *DashboardHandler) queryStorylineTop() ([]gin.H, int64) {
	var total int64
	h.db.Model(&model.Storyline{}).Where("status = ?", "active").Count(&total)

	var rows []model.Storyline
	h.db.Model(&model.Storyline{}).
		Where("status = ?", "active").
		Order("risk_score DESC, last_seen_at DESC").
		Limit(5).
		Find(&rows)

	out := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		title := r.Summary
		if title == "" {
			title = r.Phase
		}
		if title == "" {
			title = r.StoryID
		}
		out = append(out, gin.H{
			"story_id":      r.StoryID,
			"host_id":       r.HostID,
			"hostname":      r.Hostname,
			"title":         title,
			"phase":         r.Phase,
			"severity":      r.Severity,
			"risk_score":    r.RiskScore,
			"event_count":   r.EventCount,
			"alert_count":   r.AlertCount,
			"last_seen_at":  r.LastSeenAt,
			"first_seen_at": r.FirstSeenAt,
		})
	}
	return out, total
}

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

// countVulnsBySeverity 按 severity 统计"真实可修 OS 漏洞"的唯一 CVE 数（仅 critical/high）。
//
// 只计 dnf/apt 系统包(source<>osv) 且 pre-check 确认主机已装+有修复(available/outdated_repo)的项，
// 排除 osv 应用依赖、未适用(not_applicable)、已对账关闭项——否则评分被应用依赖 + 陈旧噪声拉爆恒为 0。
func (h *DashboardHandler) countVulnsBySeverity() (critical, high int64) {
	var rows []struct {
		Severity string `gorm:"column:severity"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	h.db.Table("host_vulnerabilities AS hv").
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Select("v.severity AS severity, COUNT(DISTINCT v.cve_id) AS cnt").
		Where("hv.status = ? AND v.source <> ? AND hv.precheck_status IN ?",
			"unpatched", "osv", []string{"available", "outdated_repo"}).
		Group("v.severity").
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
// 旧公式问题：
//  1. 绝对数封顶过低（15 个 critical 就触顶 -30），同 host 数下 dev 20642
//     告警 vs prod 278 评分一样，无法区分严重程度。
//  2. 不按集群规模归一化：单 host 与 226 hosts 用同一阈值。
//  3. 基线权重过小（±2），prod baseline 65% 反而被扣分。
//  4. 任一维度爆表整体易归零，丧失"局部好 + 整体差"的辨识度。
//
// 新公式：4 维度各占 25 分，加分制（每维度 0~25），最后求和。
//
//   - 告警维度（25 分）：按 per-100-host 密度算扣分，log10 缓增长
//     0 个 → 25 分；100 个/100host → 12.5 分；10000 个/100host → 0 分
//   - 漏洞维度（25 分）：同上，critical 权重 5×、high 权重 1×
//   - 基线维度（25 分）：合规率 ÷ 100 × 25（直接折算）
//   - 暴露维度（25 分）：(1 - vulnHosts/totalHosts) × 25
//
// totalHosts=0 时回退到绝对数（避免除零）。
func (h *DashboardHandler) computeSecurityScore(
	criticalAlerts, highAlerts int64,
	criticalVulns, highVulns int64,
	vulnHosts, totalHosts int64,
	baselineCompliance *float64,
) float64 {
	const dimMax = 25.0

	// 1. 告警维度：critical 权重 4× high
	alertWeighted := float64(criticalAlerts)*4 + float64(highAlerts)
	alertScore := dimScoreFromDensity(alertWeighted, totalHosts, dimMax)

	// 2. 漏洞维度：critical 权重 5× high
	vulnWeighted := float64(criticalVulns)*5 + float64(highVulns)
	vulnScore := dimScoreFromDensity(vulnWeighted, totalHosts, dimMax)

	// 3. 基线维度：合规率直接折算。
	//
	// 合规率未知（从未扫过基线，或查询失败）时**不计入该维度**，
	// 并把总分按剩余维度归一化。给一个没扫过基线的环境记满分，
	// 与合规率显示 100% 是同一个欺骗换了个位置——总分会因为「没测过」而更高。
	baselineScore := 0.0
	dims := 3.0 // 告警 / 漏洞 / 暴露
	if baselineCompliance != nil {
		baseline := *baselineCompliance
		if baseline < 0 {
			baseline = 0
		}
		if baseline > 100 {
			baseline = 100
		}
		baselineScore = baseline / 100.0 * dimMax
		dims = 4.0
	}

	// 4. 暴露维度：1 - 受影响主机比例
	exposureScore := dimMax
	if totalHosts > 0 {
		ratio := float64(vulnHosts) / float64(totalHosts)
		if ratio > 1.0 {
			ratio = 1.0
		}
		exposureScore = (1.0 - ratio) * dimMax
	}

	score := alertScore + vulnScore + baselineScore + exposureScore
	// 缺维度时按实际计入的维度数归一化回百分制，
	// 否则少一个维度就凭空少 25 分，看起来像安全状况恶化了。
	score = score * 4.0 / dims
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return math.Round(score*10) / 10
}

// dimScoreFromDensity 把"加权告警/漏洞数"按 per-100-host 密度换算成 0~max 分。
//
// 模型：
//
//	density = weightedCount * 100 / max(totalHosts, 1)
//	score = max * (1 - log10(1+density) / log10(10001))
//
// 边界：
//
//	density=0     → score=max
//	density=100   → score≈max*0.5（中等）
//	density>=10000 → score≈0（爆表）
//
// log10(10001) ≈ 4 用作归一化常数，density 上限 10000 = 每 host 平均 100 条
// 高危条目，超出仍 clamp 到 0。
func dimScoreFromDensity(weightedCount float64, totalHosts int64, dimMax float64) float64 {
	if weightedCount <= 0 {
		return dimMax
	}
	hosts := float64(totalHosts)
	if hosts < 1 {
		hosts = 1
	}
	density := weightedCount * 100.0 / hosts
	const norm = 4.0 // log10(10001)
	ratio := math.Log10(1+density) / norm
	if ratio > 1.0 {
		ratio = 1.0
	}
	score := dimMax * (1.0 - ratio)
	if score < 0 {
		score = 0
	}
	return score
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

// calculateBaselinePercentages 计算基线合规率和存在高危基线问题的主机百分比。
//
// 返回 nil 表示**无法计算**——一条基线扫描结果都没有，或查询失败。
// 此前这两种情况都返回 100%，于是新部署、扫描从未跑过、表被清空，
// 大屏统统显示「完全合规」。零数据与全部通过在界面上无法区分，
// 而这两者要做的事完全相反：前者该去查为什么没扫，后者不用管。
//
// 用指针而非 0 或 -1：调用方无法把 nil 误当成一个数字，
// 而哨兵值迟早会被某处忘记判断，然后当成真实百分比渲染出去。
func (h *DashboardHandler) calculateBaselinePercentages() (*float64, *float64) {
	var result struct {
		PassCount           int64 `gorm:"column:pass_count"`
		FailCount           int64 `gorm:"column:fail_count"`
		MediumPlusFailCount int64 `gorm:"column:medium_plus_fail_count"`
	}
	// 合规率反映「当前状态」：每主机每规则只取最新一次扫描结果，避免历史复扫被重复计数
	// （复合主键含 task_id，每次复扫追加整套新行；全表 SUM 会把同一主机扫 N 次算 N 倍）。
	// 查询错误必须区别于「查到 0 条」：忽略 err 会让 result 保持零值，
	// 与空库走进同一个分支，数据库故障因而被呈现为「合规率 100%」。
	if err := h.db.Raw(`
		SELECT
			SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) AS pass_count,
			SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) AS fail_count,
			SUM(CASE WHEN status = 'fail' AND severity IN ('medium','high','critical') THEN 1 ELSE 0 END) AS medium_plus_fail_count
		FROM (
			SELECT status, severity,
				ROW_NUMBER() OVER (PARTITION BY host_id, rule_id ORDER BY checked_at DESC) AS rn
			FROM scan_results
		) ranked
		WHERE rn = 1
	`).Scan(&result).Error; err != nil {
		h.logger.Error("查询基线合规率失败，返回未知而非数字", zap.Error(err))
		return nil, nil
	}

	totalResults := result.PassCount + result.FailCount
	if totalResults == 0 {
		// 没有任何扫描结果 ≠ 全部通过。
		return nil, nil
	}

	// 整体合规率 = 通过项 / 总检查项
	complianceRate := float64(result.PassCount) / float64(totalResults) * 100.0
	if complianceRate > 100.0 {
		complianceRate = 100.0
	}

	// 基线不合规率 = 中危及以上失败项 / 总检查项
	noncomplianceRate := float64(result.MediumPlusFailCount) / float64(totalResults) * 100.0

	return &complianceRate, &noncomplianceRate
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

	// Top3 反映「当前失败状态」：每主机每规则取最新结果后过滤 fail，避免同一主机多次复扫
	// 把同一失败项重复累加（旧实现按 7 天窗口 SUM 所有 fail 行，复扫越频繁数字越虚高）。
	h.db.Raw(`
		SELECT p.id AS policy_id, p.name,
			SUM(CASE WHEN t.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
			SUM(CASE WHEN t.severity = 'high'     THEN 1 ELSE 0 END) AS high_count,
			SUM(CASE WHEN t.severity = 'medium'   THEN 1 ELSE 0 END) AS medium_count,
			SUM(CASE WHEN t.severity = 'low'      THEN 1 ELSE 0 END) AS low_count
		FROM (
			SELECT policy_id, severity, status,
				ROW_NUMBER() OVER (PARTITION BY host_id, rule_id ORDER BY checked_at DESC) AS rn
			FROM scan_results
		) t
		INNER JOIN policies p ON p.id = t.policy_id
		WHERE t.rn = 1 AND t.status = 'fail'
		GROUP BY p.id, p.name
		ORDER BY (SUM(CASE WHEN t.severity = 'critical' THEN 4
		               WHEN t.severity = 'high'     THEN 3
		               WHEN t.severity = 'medium'   THEN 2
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

	totalRes, err := h.promClient.QueryInstant(ctx, `sum(rate(mxcwpp_http_requests_total[1m]))`, nil)
	if err != nil || totalRes == nil || len(totalRes.Data.Result) == 0 {
		return "healthy"
	}
	totalVal := parsePromScalar(totalRes.Data.Result[0].Value)
	if totalVal <= 0 {
		return "healthy" // 无流量
	}

	errRes, err := h.promClient.QueryInstant(ctx, `sum(rate(mxcwpp_http_requests_total{status_code=~"5.."}[1m]))`, nil)
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
