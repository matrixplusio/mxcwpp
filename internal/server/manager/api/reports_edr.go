// Package api 提供 HTTP API 处理器
//
// reports_edr.go 实现 EDR 模块的报告聚合 + 高管摘要 endpoint。
// 与 reports.go 中其他模块同样模式，独立文件避免污染 monolithic reports.go。
//
// 数据源：
//   - MySQL alerts (source=detection/agent, category 维度告警)
//   - MySQL storylines + storyline_events (攻击故事线)
//   - 后续可注入 ClickHouse 查询 ebpf_events 原始事件量
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// mitreTacticByCategory 把 alerts.category 映射到 MITRE ATT&CK Tactic。
// 与 configs/agent-rules/*.yaml 中 mitre.tactic 字段对齐。
var mitreTacticByCategory = map[string]string{
	"reverse_shell":        "initial_access",
	"execution":            "execution",
	"persistence":          "persistence",
	"privilege_escalation": "privilege_escalation",
	"defense_evasion":      "defense_evasion",
	"credential_access":    "credential_access",
	"discovery":            "discovery",
	"lateral_movement":     "lateral_movement",
	"collection":           "collection",
	"exfiltration":         "exfiltration",
	"c2_communication":     "command_and_control",
	"cryptomining":         "impact",
	"impact":               "impact",
	"port_scan":            "discovery",
	"behavior_anomaly":     "discovery",
}

// GetEDRReport 生成 EDR 模块聚合报告
// GET /api/v1/reports/edr?start_time=&end_time=
//
// 报告含 13 个章节，覆盖告警概览、严重程度分布、规则/主机 Top N、
// MITRE 矩阵、故事线统计、误报抑制统计、周期趋势对比等。
// 加 60s Redis cache:报表数据 1 分钟内不变,降低 13 章节 query 重复成本。
func (h *ReportsHandler) GetEDRReport(c *gin.Context) {
	startTime, endTime, ok := parseReportTimeRange(c)
	if !ok {
		return
	}

	// Redis cache lookup。
	// 注意:startTime/endTime 默认含 time.Now() → 每次 unix 不同,直接用会让 cache 永远 miss。
	// 规整到分钟级精度(60s TTL 同期内同分钟落同 key),保证 cache 真命中。
	cacheKey := fmt.Sprintf(reportsEDRCacheKey,
		startTime.Truncate(time.Minute).Unix(),
		endTime.Truncate(time.Minute).Unix(),
	)
	if h.redisClient != nil && c.Query("nocache") != "1" {
		if cached, err := h.redisClient.Get(c.Request.Context(), cacheKey).Bytes(); err == nil {
			c.Data(200, "application/json; charset=utf-8", cached)
			return
		}
	}

	reportData := h.BuildEDRReportData(startTime, endTime)
	reportID, _ := reportData["meta"].(gin.H)["reportID"].(string)
	period, _ := reportData["meta"].(gin.H)["period"].(string)
	h.saveGeneratedReport(model.ReportTypeEDR, "EDR 检测专项报告", reportID, period, reportData)

	// 写 cache(完整 response body)
	if h.redisClient != nil {
		if body, err := json.Marshal(gin.H{"code": 0, "data": reportData}); err == nil {
			h.redisClient.Set(c.Request.Context(), cacheKey, body, reportsCacheTTL)
		}
	}
	Success(c, reportData)
}

// BuildEDRReportData 装配 EDR 报告原始数据。
// PDF 渲染路径与 JSON API 共享同一份装配函数，避免数据漂移。
//
// 性能:13 个 block 串行约 11s,并发后 ~ max(各 block) ≈ 2-3s。
// 顶层 errgroup 让 MySQL/CH 各自调度,大幅减少端到端 latency。
func (h *ReportsHandler) BuildEDRReportData(startTime, endTime time.Time) gin.H {
	// === 1. 总览(7 个 COUNT 合 1 GROUP BY 减少 round trip)===
	type summary struct {
		TotalAlerts     int64
		ActiveAlerts    int64
		ResolvedAlerts  int64
		IgnoredAlerts   int64
		AffectedHosts   int64
		TotalStories    int64
		HighRiskStories int64
	}
	var s summary

	// errgroup 顶层并发所有数据装配 block
	g := new(errgroup.Group)

	// Block 1a: alert summary - 4 COUNT (TotalAlerts/Active/Resolved/Ignored) 合 1 个 SUM CASE GROUP BY
	g.Go(func() error {
		type alertCntRow struct {
			Status string
			Cnt    int64
		}
		var rows []alertCntRow
		h.db.Model(&model.Alert{}).
			Select("status, COUNT(*) as cnt").
			Where("created_at >= ? AND created_at <= ?", startTime, endTime).
			Where("source IN ?", []string{"detection", "agent"}).
			Group("status").
			Scan(&rows)
		for _, r := range rows {
			s.TotalAlerts += r.Cnt
			switch r.Status {
			case string(model.AlertStatusActive):
				s.ActiveAlerts = r.Cnt
			case string(model.AlertStatusResolved):
				s.ResolvedAlerts = r.Cnt
			case string(model.AlertStatusIgnored):
				s.IgnoredAlerts = r.Cnt
			}
		}
		return nil
	})

	// Block 1b: 受影响主机数 (DISTINCT)
	g.Go(func() error {
		h.db.Model(&model.Alert{}).
			Where("created_at >= ? AND created_at <= ?", startTime, endTime).
			Where("source IN ?", []string{"detection", "agent"}).
			Distinct("host_id").
			Count(&s.AffectedHosts)
		return nil
	})

	// Block 1c: storylines COUNT(2 query 合 1 GROUP BY 也行,但 severity IN 复杂,直接 2 query 并发)
	g.Go(func() error {
		h.db.Model(&model.Storyline{}).
			Where("created_at >= ? AND created_at <= ?", startTime, endTime).
			Count(&s.TotalStories)
		return nil
	})
	g.Go(func() error {
		h.db.Model(&model.Storyline{}).
			Where("created_at >= ? AND created_at <= ? AND severity IN ?", startTime, endTime, []string{"critical", "high"}).
			Count(&s.HighRiskStories)
		return nil
	})

	// === 2. 严重程度分布(并发) ===
	severityDistribution := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var severityMu sync.Mutex
	g.Go(func() error {
		var severityRows []struct {
			Severity string
			Count    int64
		}
		h.db.Model(&model.Alert{}).
			Select("severity, COUNT(*) as count").
			Where("created_at >= ? AND created_at <= ?", startTime, endTime).
			Where("source IN ?", []string{"detection", "agent"}).
			Group("severity").
			Scan(&severityRows)
		severityMu.Lock()
		for _, r := range severityRows {
			if r.Severity != "" {
				severityDistribution[r.Severity] = r.Count
			}
		}
		severityMu.Unlock()
		return nil
	})

	// === 3. Category 分布(并发,同时支撑 4. MITRE Tactic) ===
	type categoryRow struct {
		Category string
		Count    int64
	}
	var categoryRows []categoryRow
	g.Go(func() error {
		h.db.Model(&model.Alert{}).
			Select("category, COUNT(*) as count").
			Where("created_at >= ? AND created_at <= ? AND category <> ''", startTime, endTime).
			Where("source IN ?", []string{"detection", "agent"}).
			Group("category").
			Order("count DESC").
			Scan(&categoryRows)
		return nil
	})

	// === 5. Top 10 触发规则(并发) ===
	type ruleRow struct {
		Title    string
		Category string
		Severity string
		Count    int64
	}
	var ruleRows []ruleRow
	g.Go(func() error {
		h.db.Model(&model.Alert{}).
			Select("title, category, severity, SUM(hit_count) as count").
			Where("created_at >= ? AND created_at <= ?", startTime, endTime).
			Where("source IN ?", []string{"detection", "agent"}).
			Where("status = ?", model.AlertStatusActive).
			Group("title, category, severity").
			Order("count DESC").
			Limit(10).
			Scan(&ruleRows)
		return nil
	})

	// === 6. Top 10 受影响主机(并发) ===
	type hostRow struct {
		HostID   string
		Hostname string
		Count    int64
	}
	var hostRows []hostRow
	g.Go(func() error {
		h.db.Raw(`
			SELECT a.host_id, h.hostname, COUNT(*) as count
			FROM alerts a LEFT JOIN hosts h ON a.host_id = h.host_id
			WHERE a.created_at >= ? AND a.created_at <= ?
			  AND a.source IN ('detection','agent')
			  AND a.status = 'active'
			GROUP BY a.host_id, h.hostname
			ORDER BY count DESC LIMIT 10
		`, startTime, endTime).Scan(&hostRows)
		return nil
	})

	// === 7. Top 5 高风险故事线(并发) ===
	type storyRow struct {
		StoryID    string
		HostID     string
		Hostname   string
		Phase      string
		Severity   string
		EventCount int
		AlertCount int
		// storylines.risk_score 是 decimal(5,1) → MySQL 返回字符串 "80.0",必须 float64 Scan
		RiskScore float64
	}
	var storyRows []storyRow
	g.Go(func() error {
		h.db.Raw(`
			SELECT s.story_id, s.host_id, h.hostname, s.phase, s.severity,
			       s.event_count, s.alert_count, s.risk_score
			FROM storylines s LEFT JOIN hosts h ON s.host_id = h.host_id
			WHERE s.created_at >= ? AND s.created_at <= ?
			ORDER BY s.risk_score DESC LIMIT 5
		`, startTime, endTime).Scan(&storyRows)
		return nil
	})

	// === 8. 误报抑制统计(并发) ===
	type suppressRow struct {
		Reason string
		Count  int64
	}
	var suppressRows []suppressRow
	g.Go(func() error {
		h.db.Model(&model.Alert{}).
			Select("resolve_reason as reason, COUNT(*) as count").
			Where("created_at >= ? AND created_at <= ?", startTime, endTime).
			Where("status = ?", model.AlertStatusIgnored).
			Where("resolve_reason <> ''").
			Group("resolve_reason").
			Order("count DESC").
			Limit(10).
			Scan(&suppressRows)
		return nil
	})

	// === 9. 周期趋势对比(并发) ===
	period := endTime.Sub(startTime)
	prevStart := startTime.Add(-period)
	prevEnd := startTime
	var prevTotal int64
	g.Go(func() error {
		h.db.Model(&model.Alert{}).
			Where("created_at >= ? AND created_at <= ?", prevStart, prevEnd).
			Where("source IN ?", []string{"detection", "agent"}).
			Count(&prevTotal)
		return nil
	})

	// === 10. Agent / 规则元数据(3 COUNT 并发) ===
	var totalRules, enabledRules, onlineHosts int64
	g.Go(func() error {
		h.db.Model(&model.DetectionRule{}).Count(&totalRules)
		return nil
	})
	g.Go(func() error {
		h.db.Model(&model.DetectionRule{}).Where("enabled = ?", true).Count(&enabledRules)
		return nil
	})
	g.Go(func() error {
		h.db.Model(&model.Host{}).Where("status = ?", "online").Count(&onlineHosts)
		return nil
	})

	// === 11-14. CH + autoResp + IOC + ruleEfficacy(各内部已包含多 query,并发执行)===
	var chStats edrEventStats
	var autoResponseStats edrAutoResponseStats
	var iocStats edrIOCStats
	var ruleEfficacy edrRuleEfficacy
	g.Go(func() error { chStats = h.queryEDREventStatsCH(startTime, endTime); return nil })
	g.Go(func() error { autoResponseStats = h.queryAutoResponseStats(startTime, endTime); return nil })
	g.Go(func() error { iocStats = h.queryIOCStats(startTime, endTime); return nil })
	g.Go(func() error { ruleEfficacy = h.queryRuleEfficacy(startTime, endTime); return nil })

	// 等所有并发完成
	_ = g.Wait()

	// === 后处理(单线程,依赖上面结果)===
	categoryDistribution := make([]gin.H, 0, len(categoryRows))
	for _, r := range categoryRows {
		categoryDistribution = append(categoryDistribution, gin.H{
			"category": r.Category,
			"count":    r.Count,
		})
	}

	// === 4. MITRE ATT&CK Tactic 分布(纯计算,无 query)
	tacticDistribution := map[string]int64{}
	for _, r := range categoryRows {
		t, ok := mitreTacticByCategory[r.Category]
		if !ok {
			t = "other"
		}
		tacticDistribution[t] += r.Count
	}

	topRules := make([]gin.H, 0, len(ruleRows))
	for _, r := range ruleRows {
		topRules = append(topRules, gin.H{
			"title":    r.Title,
			"category": r.Category,
			"severity": r.Severity,
			"count":    r.Count,
		})
	}

	topHosts := make([]gin.H, 0, len(hostRows))
	for _, r := range hostRows {
		topHosts = append(topHosts, gin.H{
			"host_id":  r.HostID,
			"hostname": r.Hostname,
			"count":    r.Count,
		})
	}

	topStories := make([]gin.H, 0, len(storyRows))
	for _, r := range storyRows {
		topStories = append(topStories, gin.H{
			"story_id":    r.StoryID,
			"host_id":     r.HostID,
			"hostname":    r.Hostname,
			"phase":       r.Phase,
			"severity":    r.Severity,
			"event_count": r.EventCount,
			"alert_count": r.AlertCount,
			"risk_score":  r.RiskScore,
		})
	}

	suppressionStats := make([]gin.H, 0, len(suppressRows))
	for _, r := range suppressRows {
		suppressionStats = append(suppressionStats, gin.H{
			"reason": r.Reason,
			"count":  r.Count,
		})
	}

	growthPct := 0.0
	if prevTotal > 0 {
		growthPct = float64(s.TotalAlerts-prevTotal) / float64(prevTotal) * 100
	}

	// === 15. 自动改进建议(纯计算,依赖前面 stats) ===
	improvements := generateEDRImprovements(s, autoResponseStats, ruleEfficacy, chStats)

	// === 组装 ===
	reportID := fmt.Sprintf("edr-%d", time.Now().Unix())
	periodStr := fmt.Sprintf("%s ~ %s",
		startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))

	reportData := gin.H{
		"meta": gin.H{
			"reportID":     reportID,
			"period":       periodStr,
			"generatedAt":  time.Now(),
			"onlineHosts":  onlineHosts,
			"totalRules":   totalRules,
			"enabledRules": enabledRules,
		},
		"summary": gin.H{
			"totalAlerts":     s.TotalAlerts,
			"activeAlerts":    s.ActiveAlerts,
			"resolvedAlerts":  s.ResolvedAlerts,
			"ignoredAlerts":   s.IgnoredAlerts,
			"affectedHosts":   s.AffectedHosts,
			"totalStories":    s.TotalStories,
			"highRiskStories": s.HighRiskStories,
		},
		"severityDistribution": severityDistribution,
		"categoryDistribution": categoryDistribution,
		"tacticDistribution":   tacticDistribution,
		"topRules":             topRules,
		"topHosts":             topHosts,
		"topStories":           topStories,
		"suppressionStats":     suppressionStats,
		"trend": gin.H{
			"prevPeriodAlerts": prevTotal,
			"growthPercent":    growthPct,
			"direction":        directionLabel(growthPct),
		},
		"rawEventStats": gin.H{
			"available":       chStats.Available,
			"totalEvents":     chStats.TotalEvents,
			"uniqueHosts":     chStats.UniqueHosts,
			"eventsByType":    chStats.EventsByType,
			"eventsByHour":    chStats.EventsByHour,
			"topHostsByEvent": chStats.TopHostsByEvent,
			"topExe":          chStats.TopExe,
		},
		"autoResponseStats": gin.H{
			"networkBlocks":  autoResponseStats.NetworkBlocks,
			"hostIsolations": autoResponseStats.HostIsolations,
			"processKills":   autoResponseStats.ProcessKills,
			"total":          autoResponseStats.Total,
		},
		"iocStats": gin.H{
			"iocSnapshots":  iocStats.IOCSnapshots,
			"memoryThreats": iocStats.MemoryThreats,
			"topIOCTypes":   iocStats.TopIOCTypes,
		},
		"ruleEfficacy": gin.H{
			"totalRules":   ruleEfficacy.TotalRules,
			"enabledRules": ruleEfficacy.EnabledRules,
			"hitRules":     ruleEfficacy.HitRules,
			"zeroHitRules": ruleEfficacy.ZeroHitRules,
			"hitRate":      ruleEfficacy.HitRate,
			"topZeroHit":   ruleEfficacy.TopZeroHit,
		},
		"improvements": improvements,
	}

	return reportData
}

// edrEventStats 是 CH 端 ebpf_events 维度聚合结果。
type edrEventStats struct {
	TotalEvents     uint64  `json:"totalEvents"`
	UniqueHosts     uint64  `json:"uniqueHosts"`
	EventsByType    []gin.H `json:"eventsByType"`    // [{event_type, count}]
	EventsByHour    []gin.H `json:"eventsByHour"`    // [{hour, count}] 时序
	TopHostsByEvent []gin.H `json:"topHostsByEvent"` // [{host_id, count}]
	TopExe          []gin.H `json:"topExe"`          // [{exe, count}]
	Available       bool    `json:"available"`       // CH 不可用时返回 false
}

// queryEDREventStatsCH 从 ClickHouse 聚合报告周期内的原始 EDR 事件。
//
// 这是真"事件量"维度，与 alerts 表的"规则命中数"互补：
//   - alerts 反映"检出能力"（规则覆盖 + 命中频率）
//   - ebpf_events 反映"数据采集量"（agent 上报基线 + 主机活跃度）
//
// 5 个 CH 聚合查询并发执行(原串行最慢 stats_top_hosts 1.9s,串行总 ~3s)
// 并发后总延迟 ≈ max ≈ 1.9s,省 1s+。
func (h *ReportsHandler) queryEDREventStatsCH(startTime, endTime time.Time) edrEventStats {
	stats := edrEventStats{
		EventsByType:    []gin.H{},
		EventsByHour:    []gin.H{},
		TopHostsByEvent: []gin.H{},
		TopExe:          []gin.H{},
	}
	if h.chConn == nil {
		return stats
	}
	stats.Available = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	g, _ := errgroup.WithContext(ctx)

	// 1. 总事件 + 唯一主机数
	g.Go(func() error {
		if err := h.chConn.QueryRow(ctx, `
			SELECT count(), uniq(host_id) FROM ebpf_events WHERE timestamp >= ? AND timestamp <= ?
		`, startTime, endTime).Scan(&stats.TotalEvents, &stats.UniqueHosts); err != nil {
			h.logger.Warn("CH ebpf_events 总量查询失败", zap.Error(err))
		}
		return nil
	})

	// 2. 按 event_type 分布
	g.Go(func() error {
		rows, err := h.chConn.Query(ctx, `
			SELECT event_type, count() AS c FROM ebpf_events
			WHERE timestamp >= ? AND timestamp <= ?
			GROUP BY event_type ORDER BY c DESC
		`, startTime, endTime)
		if err != nil {
			return nil
		}
		defer rows.Close()
		tmp := make([]gin.H, 0)
		for rows.Next() {
			var et string
			var c uint64
			if err := rows.Scan(&et, &c); err == nil {
				tmp = append(tmp, gin.H{"event_type": et, "count": c})
			}
		}
		stats.EventsByType = tmp
		return nil
	})

	// 3. 按小时分布(趋势图)
	g.Go(func() error {
		rows, err := h.chConn.Query(ctx, `
			SELECT toStartOfHour(timestamp) AS h, count() AS c FROM ebpf_events
			WHERE timestamp >= ? AND timestamp <= ?
			GROUP BY h ORDER BY h
		`, startTime, endTime)
		if err != nil {
			return nil
		}
		defer rows.Close()
		tmp := make([]gin.H, 0)
		for rows.Next() {
			var hour time.Time
			var c uint64
			if err := rows.Scan(&hour, &c); err == nil {
				tmp = append(tmp, gin.H{
					"hour":  hour.Format("2006-01-02 15:00"),
					"count": c,
				})
			}
		}
		stats.EventsByHour = tmp
		return nil
	})

	// 4. Top 10 主机 by 原始事件量
	g.Go(func() error {
		rows, err := h.chConn.Query(ctx, `
			SELECT host_id, count() AS c FROM ebpf_events
			WHERE timestamp >= ? AND timestamp <= ?
			GROUP BY host_id ORDER BY c DESC LIMIT 10
		`, startTime, endTime)
		if err != nil {
			return nil
		}
		defer rows.Close()
		tmp := make([]gin.H, 0, 10)
		for rows.Next() {
			var hostID string
			var c uint64
			if err := rows.Scan(&hostID, &c); err == nil {
				tmp = append(tmp, gin.H{"host_id": hostID, "count": c})
			}
		}
		stats.TopHostsByEvent = tmp
		return nil
	})

	// 5. Top 10 exe(最活跃进程)
	g.Go(func() error {
		rows, err := h.chConn.Query(ctx, `
			SELECT exe, count() AS c FROM ebpf_events
			WHERE timestamp >= ? AND timestamp <= ? AND exe != ''
			GROUP BY exe ORDER BY c DESC LIMIT 10
		`, startTime, endTime)
		if err != nil {
			return nil
		}
		defer rows.Close()
		tmp := make([]gin.H, 0, 10)
		for rows.Next() {
			var exe string
			var c uint64
			if err := rows.Scan(&exe, &c); err == nil {
				tmp = append(tmp, gin.H{"exe": exe, "count": c})
			}
		}
		stats.TopExe = tmp
		return nil
	})

	_ = g.Wait()
	// hostname 补齐放并发外(避免与 CH 查询冲突,MySQL 调用)
	if len(stats.TopHostsByEvent) > 0 {
		h.attachHostnames(stats.TopHostsByEvent)
	}
	return stats
}

// attachHostnames 给 [{host_id, count}] 列表附加 hostname (从 MySQL hosts 表查)。
func (h *ReportsHandler) attachHostnames(rows []gin.H) {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if id, ok := r["host_id"].(string); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	type hostRow struct {
		HostID   string
		Hostname string
	}
	var hosts []hostRow
	h.db.Model(&model.Host{}).Select("host_id, hostname").Where("host_id IN ?", ids).Scan(&hosts)
	nameByID := make(map[string]string, len(hosts))
	for _, h := range hosts {
		nameByID[h.HostID] = h.Hostname
	}
	for _, r := range rows {
		if id, ok := r["host_id"].(string); ok {
			r["hostname"] = nameByID[id]
		}
	}
}

// GetEDRExecutiveReport 生成 EDR 高管摘要（精简 1 页）
// GET /api/v1/reports/edr/executive?start_time=&end_time=
func (h *ReportsHandler) GetEDRExecutiveReport(c *gin.Context) {
	startTime, endTime, ok := parseReportTimeRange(c)
	if !ok {
		return
	}

	var (
		totalAlerts, criticalAlerts, highAlerts int64
		totalStories, highRiskStories           int64
		affectedHosts, onlineHosts              int64
	)
	timeRange := h.db.Model(&model.Alert{}).
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Where("source IN ?", []string{"detection", "agent"})
	timeRange.Count(&totalAlerts)
	timeRange.Session(&gorm.Session{}).Where("severity = ?", "critical").Count(&criticalAlerts)
	timeRange.Session(&gorm.Session{}).Where("severity = ?", "high").Count(&highAlerts)
	timeRange.Session(&gorm.Session{}).Distinct("host_id").Count(&affectedHosts)
	h.db.Model(&model.Host{}).Where("status = ?", "online").Count(&onlineHosts)
	h.db.Model(&model.Storyline{}).
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Count(&totalStories)
	h.db.Model(&model.Storyline{}).
		Where("created_at >= ? AND created_at <= ? AND severity IN ?", startTime, endTime, []string{"critical", "high"}).
		Count(&highRiskStories)

	// 综合风险评分（0-100，简单加权）
	coverage := 100.0
	if onlineHosts > 0 {
		coverage = float64(affectedHosts) / float64(onlineHosts) * 100
	}
	riskScore := scoreEDR(criticalAlerts, highAlerts, highRiskStories, affectedHosts, onlineHosts)

	// 自动结论
	conclusion := edrConclusion(riskScore, criticalAlerts, highRiskStories)
	suggestions := edrSuggestions(criticalAlerts, highAlerts, highRiskStories, affectedHosts, onlineHosts)

	reportID := fmt.Sprintf("edr-exec-%d", time.Now().Unix())
	periodStr := fmt.Sprintf("%s ~ %s",
		startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))

	reportData := gin.H{
		"meta": gin.H{
			"reportID":    reportID,
			"period":      periodStr,
			"generatedAt": time.Now(),
		},
		"keyMetrics": gin.H{
			"totalAlerts":     totalAlerts,
			"criticalAlerts":  criticalAlerts,
			"highAlerts":      highAlerts,
			"totalStories":    totalStories,
			"highRiskStories": highRiskStories,
			"affectedHosts":   affectedHosts,
			"onlineHosts":     onlineHosts,
			"coverage":        coverage,
		},
		"riskScore":   riskScore,
		"conclusion":  conclusion,
		"suggestions": suggestions,
	}

	h.saveGeneratedReport(model.ReportTypeEDR, "EDR 高管摘要报告", reportID, periodStr, reportData)
	Success(c, reportData)
}

// directionLabel 返回趋势方向（涨/跌/持平）的人类可读标签。
func directionLabel(growthPct float64) string {
	if growthPct > 5 {
		return "up"
	}
	if growthPct < -5 {
		return "down"
	}
	return "stable"
}

// scoreEDR 计算 EDR 综合风险评分（0-100，越高越糟）。
func scoreEDR(critical, high, highStories, affected, online int64) int {
	score := 0.0
	score += float64(critical) * 5
	score += float64(high) * 2
	score += float64(highStories) * 8
	if online > 0 {
		score += float64(affected) / float64(online) * 30
	}
	if score > 100 {
		score = 100
	}
	return int(score)
}

// edrConclusion 自动生成结论文案。
func edrConclusion(riskScore int, critical, highStories int64) string {
	switch {
	case riskScore >= 80 || critical > 50:
		return fmt.Sprintf("当前 EDR 风险等级：严重。报告周期内产生 %d 条严重告警 + %d 条高危故事线，存在活跃攻击迹象，建议立即启动应急响应。", critical, highStories)
	case riskScore >= 50 || critical > 10:
		return fmt.Sprintf("当前 EDR 风险等级：高。报告周期内产生 %d 条严重告警，存在多起需排查事件，建议安全团队 24h 内完成研判。", critical)
	case riskScore >= 25:
		return fmt.Sprintf("当前 EDR 风险等级：中。报告周期内 EDR 检测能力正常运行，发现 %d 条高风险故事线，建议定期复核。", highStories)
	default:
		return "当前 EDR 风险等级：低。报告周期内未发现明显异常活动，EDR 检测覆盖正常。"
	}
}

// edrSuggestions 自动生成行动建议清单。
func edrSuggestions(critical, high, highStories, affected, online int64) []string {
	tips := []string{}
	if critical > 0 {
		tips = append(tips, fmt.Sprintf("处置 %d 条严重告警，确认是否为真实攻击并执行响应动作。", critical))
	}
	if highStories > 0 {
		tips = append(tips, fmt.Sprintf("调查 %d 条高危攻击故事线，关联各阶段事件复盘攻击链。", highStories))
	}
	if online > 0 && float64(affected)/float64(online) > 0.5 {
		tips = append(tips, "受影响主机比例 > 50%，建议复核检测规则是否过度敏感或存在面级威胁。")
	}
	if high > 100 {
		tips = append(tips, "高危告警量较大，建议使用告警白名单 / 频率节流功能减少噪音。")
	}
	if len(tips) == 0 {
		tips = append(tips, "持续监控 EDR 告警，保持规则与威胁情报同步更新。")
	}
	return tips
}

// edrAutoResponseStats 自动响应执行汇总。
type edrAutoResponseStats struct {
	NetworkBlocks  int64 `json:"networkBlocks"`  // network_block_rules source=auto_response
	HostIsolations int64 `json:"hostIsolations"` // host_isolations source=auto_response
	ProcessKills   int64 `json:"processKills"`   // alerts.resolve_reason 含 kill
	Total          int64 `json:"total"`
}

// queryAutoResponseStats 汇总报告周期内自动响应动作。
//
// 数据源:
//   - network_block_rules WHERE source='auto_response' (自动 IP 封禁)
//   - host_isolations WHERE source='auto_response' (自动主机隔离)
//   - alerts.resolve_reason LIKE '%kill%' (kill_process 响应记录在 alert 上)
func (h *ReportsHandler) queryAutoResponseStats(startTime, endTime time.Time) edrAutoResponseStats {
	var stats edrAutoResponseStats
	h.db.Table("network_block_rules").
		Where("source = ? AND created_at >= ? AND created_at <= ?", "auto_response", startTime, endTime).
		Count(&stats.NetworkBlocks)
	h.db.Table("host_isolations").
		Where("source = ? AND created_at >= ? AND created_at <= ?", "auto_response", startTime, endTime).
		Count(&stats.HostIsolations)
	h.db.Model(&model.Alert{}).
		Where("resolve_reason LIKE ? AND resolved_at >= ? AND resolved_at <= ?", "%kill%", startTime, endTime).
		Count(&stats.ProcessKills)
	stats.Total = stats.NetworkBlocks + stats.HostIsolations + stats.ProcessKills
	return stats
}

// edrIOCStats IOC / 内存威胁 / 情报命中统计。
type edrIOCStats struct {
	IOCSnapshots  int64   `json:"iocSnapshots"`  // ioc_snapshots 数（情报快照次数）
	MemoryThreats int64   `json:"memoryThreats"` // memory_threats 检测条数
	TopIOCTypes   []gin.H `json:"topIOCTypes"`   // memory_threats by technique
}

// queryIOCStats 报告周期内 IOC / memory threat 维度。
func (h *ReportsHandler) queryIOCStats(startTime, endTime time.Time) edrIOCStats {
	stats := edrIOCStats{TopIOCTypes: []gin.H{}}
	h.db.Table("ioc_snapshots").
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Count(&stats.IOCSnapshots)
	h.db.Table("memory_threats").
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Count(&stats.MemoryThreats)
	type rowT struct {
		Technique string
		Cnt       int64
	}
	var rows []rowT
	// memory_threats 表用 threat_type (memfd_exec / deleted_exe / anonymous_exec),不存 MITRE technique
	// 之前 SQL 写错列名 → "Unknown column 'technique' in field list" 静默吞掉,Top IOC 一直为空
	h.db.Raw(`
		SELECT threat_type AS technique, COUNT(*) AS cnt FROM memory_threats
		WHERE created_at >= ? AND created_at <= ? AND threat_type <> ''
		GROUP BY threat_type ORDER BY cnt DESC LIMIT 5
	`, startTime, endTime).Scan(&rows)
	for _, r := range rows {
		stats.TopIOCTypes = append(stats.TopIOCTypes, gin.H{"technique": r.Technique, "count": r.Cnt})
	}
	return stats
}

// edrRuleEfficacy 规则有效性指标。
type edrRuleEfficacy struct {
	TotalRules   int64   `json:"totalRules"`
	EnabledRules int64   `json:"enabledRules"`
	HitRules     int64   `json:"hitRules"`     // 周期内有命中的规则数
	ZeroHitRules int64   `json:"zeroHitRules"` // 启用但零命中（建议下线）
	HitRate      float64 `json:"hitRate"`      // hit/enabled 百分比
	TopZeroHit   []gin.H `json:"topZeroHit"`   // 列举部分 0 命中规则 (id, name)
}

// queryRuleEfficacy 周期内规则命中分布 + 0 命中规则列表。
func (h *ReportsHandler) queryRuleEfficacy(startTime, endTime time.Time) edrRuleEfficacy {
	var ef edrRuleEfficacy
	h.db.Model(&model.DetectionRule{}).Count(&ef.TotalRules)
	h.db.Model(&model.DetectionRule{}).Where("enabled = ?", true).Count(&ef.EnabledRules)

	// 周期内有命中的规则数（alerts.title 与 detection_rules.name 对应）
	h.db.Raw(`
		SELECT COUNT(DISTINCT r.id)
		FROM detection_rules r
		INNER JOIN alerts a ON a.title = r.name
		WHERE r.enabled = 1
		  AND a.created_at >= ? AND a.created_at <= ?
		  AND a.source IN ('detection','agent')
	`, startTime, endTime).Scan(&ef.HitRules)
	ef.ZeroHitRules = ef.EnabledRules - ef.HitRules
	if ef.EnabledRules > 0 {
		ef.HitRate = float64(ef.HitRules) / float64(ef.EnabledRules) * 100
	}

	// 列出部分 0 命中规则
	type zeroRow struct {
		ID       uint
		Name     string
		Category string
	}
	var zeros []zeroRow
	h.db.Raw(`
		SELECT r.id, r.name, r.category
		FROM detection_rules r
		WHERE r.enabled = 1
		  AND NOT EXISTS (
		    SELECT 1 FROM alerts a
		    WHERE a.title = r.name
		      AND a.created_at >= ? AND a.created_at <= ?
		      AND a.source IN ('detection','agent')
		  )
		ORDER BY r.id
		LIMIT 10
	`, startTime, endTime).Scan(&zeros)
	ef.TopZeroHit = make([]gin.H, 0, len(zeros))
	for _, z := range zeros {
		ef.TopZeroHit = append(ef.TopZeroHit, gin.H{
			"id": z.ID, "name": z.Name, "category": z.Category,
		})
	}
	return ef
}

// generateEDRImprovements 基于聚合数据自动产出改进建议。
// 这是规则化建议（非 LLM），按已知 best practice 给出可操作项。
func generateEDRImprovements(
	s struct {
		TotalAlerts     int64
		ActiveAlerts    int64
		ResolvedAlerts  int64
		IgnoredAlerts   int64
		AffectedHosts   int64
		TotalStories    int64
		HighRiskStories int64
	},
	autoResp edrAutoResponseStats,
	ef edrRuleEfficacy,
	ch edrEventStats,
) []string {
	out := make([]string, 0, 8)

	if ef.ZeroHitRules > 20 {
		out = append(out, fmt.Sprintf(
			"已启用 %d 条规则但仅 %d 条命中（覆盖率 %.1f%%），%d 条规则周期内零命中，建议下线或调整阈值。",
			ef.EnabledRules, ef.HitRules, ef.HitRate, ef.ZeroHitRules))
	}
	if s.IgnoredAlerts > s.ActiveAlerts && s.IgnoredAlerts > 50 {
		out = append(out, fmt.Sprintf(
			"忽略告警 %d 条多于活跃告警 %d 条，建议复盘高频忽略原因并将稳定模式落地为白名单。",
			s.IgnoredAlerts, s.ActiveAlerts))
	}
	if autoResp.Total == 0 && s.HighRiskStories > 5 {
		out = append(out, "存在多条高危故事线但本期无自动响应执行，建议配置自动 kill/隔离策略以缩短 MTTR。")
	}
	if ch.Available && ch.TotalEvents > 0 && s.TotalAlerts > 0 {
		conv := float64(s.TotalAlerts) / float64(ch.TotalEvents) * 100
		switch {
		case conv > 5:
			out = append(out, fmt.Sprintf(
				"告警转化率 %.2f%% 偏高（健康范围 < 1%%），疑似规则过度敏感，建议结合 BDE 基线收敛。", conv))
		case conv < 0.001 && ch.TotalEvents > 100000:
			out = append(out, fmt.Sprintf(
				"事件量 %d 条但告警转化率仅 %.4f%%，规则覆盖可能不足，建议复核 ATT&CK 矩阵关键 tactic。",
				ch.TotalEvents, conv))
		}
	}
	if s.HighRiskStories > 0 && s.ResolvedAlerts == 0 {
		out = append(out, fmt.Sprintf(
			"本期 %d 条高危故事线未关闭，建议建立 SOC 值班机制确保 MTTR < 24h。", s.HighRiskStories))
	}
	if len(out) == 0 {
		out = append(out, "EDR 检测体系运行正常，规则覆盖率与误报抑制均处于合理区间，保持定期 IOC 与规则同步即可。")
	}
	return out
}
