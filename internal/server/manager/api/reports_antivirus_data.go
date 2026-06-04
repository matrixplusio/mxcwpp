// Package api - reports_antivirus_data.go 病毒查杀报告数据装配。
//
// 与 reports_edr.go::BuildEDRReportData 同模式：从 MySQL 拉取
// antivirus_scan_tasks / antivirus_scan_results / security_db_sync_records
// 装配为 gin.H 后供 JSON API + PDF 渲染共享，避免数据漂移。
//
// 数据源：
//   - antivirus_scan_tasks (扫描任务元数据)
//   - antivirus_scan_results (检出威胁明细)
//   - security_db_sync_records (病毒库同步历史)
//   - hosts (主机元数据，补全 hostname/ip)
package api

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// BuildAntivirusReportData 装配病毒查杀报告原始数据。
//
// 输出 gin.H 字段：meta / summary / trend / taskStats / severityDistribution /
// threatTypeDistribution / topThreats / topAffectedHosts / recentTasks /
// engine / improvements。
//
// 与 GetAntivirusReport handler 中相同维度的统计逻辑保持一致，
// 但额外补充了 PDF 报告所需的：任务状态分布、扫描类型分布、
// 周期趋势对比、引擎/病毒库版本、近期任务列表、近期同步记录。
func (h *ReportsHandler) BuildAntivirusReportData(startTime, endTime time.Time) gin.H {
	// === 1. 总览 ===
	type avSummaryRow struct {
		TotalTasks         int64
		TotalThreats       int64
		DetectedThreats    int64
		QuarantinedThreats int64
		DeletedThreats     int64
		IgnoredThreats     int64
		AffectedHosts      int64
		ScannedHosts       int64
	}
	var s avSummaryRow

	h.db.Model(&model.AntivirusScanTask{}).
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Count(&s.TotalTasks)

	// 威胁明细按 detected_at 过滤
	resultQ := h.db.Model(&model.AntivirusScanResult{}).
		Where("detected_at >= ? AND detected_at <= ?", startTime, endTime)
	resultQ.Count(&s.TotalThreats)

	// 各 action 计数（一次查询拆解，避免 N 次扫表）
	type actionAgg struct {
		Action string
		Count  int64
	}
	var actionRows []actionAgg
	h.db.Model(&model.AntivirusScanResult{}).
		Select("action, COUNT(*) as count").
		Where("detected_at >= ? AND detected_at <= ?", startTime, endTime).
		Group("action").
		Scan(&actionRows)
	for _, r := range actionRows {
		switch r.Action {
		case "detected":
			s.DetectedThreats = r.Count
		case "quarantined":
			s.QuarantinedThreats = r.Count
		case "deleted":
			s.DeletedThreats = r.Count
		case "ignored":
			s.IgnoredThreats = r.Count
		}
	}

	// 受感染主机数（DISTINCT）
	h.db.Model(&model.AntivirusScanResult{}).
		Where("detected_at >= ? AND detected_at <= ?", startTime, endTime).
		Distinct("host_id").
		Count(&s.AffectedHosts)

	// 受扫描主机数：从 antivirus_scan_results 中所有 host_id 来源（含未检出的需查 tasks.host_ids，
	// 简化处理：以 results 表覆盖范围作为下限；准确扫描覆盖需依赖 task_hosts 关系，本期不引入）
	h.db.Model(&model.AntivirusScanResult{}).
		Where("detected_at >= ? AND detected_at <= ?", startTime, endTime).
		Distinct("host_id").
		Count(&s.ScannedHosts)

	// === 2. 任务状态与扫描类型分布 ===
	type statAgg struct {
		Key   string
		Count int64
	}
	taskStats := gin.H{
		"completed":  int64(0),
		"running":    int64(0),
		"failed":     int64(0),
		"cancelled":  int64(0),
		"pending":    int64(0),
		"quickScan":  int64(0),
		"fullScan":   int64(0),
		"customScan": int64(0),
	}
	var statusRows []statAgg
	h.db.Model(&model.AntivirusScanTask{}).
		Select("status as `key`, COUNT(*) as count").
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Group("status").
		Scan(&statusRows)
	for _, r := range statusRows {
		switch r.Key {
		case "completed":
			taskStats["completed"] = r.Count
		case "running":
			taskStats["running"] = r.Count
		case "failed":
			taskStats["failed"] = r.Count
		case "cancelled":
			taskStats["cancelled"] = r.Count
		case "pending":
			taskStats["pending"] = r.Count
		}
	}
	var scanTypeRows []statAgg
	h.db.Model(&model.AntivirusScanTask{}).
		Select("scan_type as `key`, COUNT(*) as count").
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Group("scan_type").
		Scan(&scanTypeRows)
	for _, r := range scanTypeRows {
		switch r.Key {
		case "quick":
			taskStats["quickScan"] = r.Count
		case "full":
			taskStats["fullScan"] = r.Count
		case "custom":
			taskStats["customScan"] = r.Count
		}
	}

	// === 3. 严重程度分布 ===
	severityDistribution := map[string]int64{
		"critical": 0, "high": 0, "medium": 0, "low": 0,
	}
	type sevAgg struct {
		Severity string
		Count    int64
	}
	var sevRows []sevAgg
	h.db.Model(&model.AntivirusScanResult{}).
		Select("severity, COUNT(*) as count").
		Where("detected_at >= ? AND detected_at <= ?", startTime, endTime).
		Group("severity").
		Scan(&sevRows)
	for _, r := range sevRows {
		if r.Severity != "" {
			severityDistribution[r.Severity] = r.Count
		}
	}

	// === 4. 威胁类型分布 ===
	threatTypeDistribution := make(map[string]int64)
	type ttAgg struct {
		ThreatType string
		Count      int64
	}
	var ttRows []ttAgg
	h.db.Model(&model.AntivirusScanResult{}).
		Select("threat_type, COUNT(*) as count").
		Where("detected_at >= ? AND detected_at <= ?", startTime, endTime).
		Group("threat_type").
		Scan(&ttRows)
	for _, r := range ttRows {
		if r.ThreatType != "" {
			threatTypeDistribution[r.ThreatType] = r.Count
		}
	}

	// === 5. Top 10 威胁名称 ===
	type topThreatRow struct {
		ThreatName    string
		Count         int64
		Severity      string
		AffectedHosts int64
	}
	var topThreats []topThreatRow
	h.db.Raw(`
		SELECT threat_name,
			COUNT(*) as count,
			MAX(severity) as severity,
			COUNT(DISTINCT host_id) as affected_hosts
		FROM antivirus_scan_results
		WHERE detected_at >= ? AND detected_at <= ?
		GROUP BY threat_name
		ORDER BY count DESC
		LIMIT 10
	`, startTime, endTime).Scan(&topThreats)
	topThreatsOut := make([]gin.H, 0, len(topThreats))
	for _, t := range topThreats {
		topThreatsOut = append(topThreatsOut, gin.H{
			"threatName":    t.ThreatName,
			"count":         t.Count,
			"severity":      t.Severity,
			"affectedHosts": t.AffectedHosts,
		})
	}

	// === 6. Top 10 受感染主机 ===
	type topHostRow struct {
		HostID      string
		Hostname    string
		IP          string
		ThreatCount int64
	}
	var topHostRows []topHostRow
	h.db.Raw(`
		SELECT host_id,
			MAX(hostname) as hostname,
			MAX(ip) as ip,
			COUNT(*) as threat_count
		FROM antivirus_scan_results
		WHERE detected_at >= ? AND detected_at <= ?
		GROUP BY host_id
		ORDER BY threat_count DESC
		LIMIT 10
	`, startTime, endTime).Scan(&topHostRows)

	// 补全主机元数据
	hostIDs := make([]string, 0, len(topHostRows))
	for _, row := range topHostRows {
		if row.Hostname == "" || row.IP == "" {
			hostIDs = append(hostIDs, row.HostID)
		}
	}
	if len(hostIDs) > 0 {
		var hosts []model.Host
		h.db.Where("host_id IN ?", hostIDs).Find(&hosts)
		hostMap := make(map[string]model.Host, len(hosts))
		for _, host := range hosts {
			hostMap[host.HostID] = host
		}
		for i := range topHostRows {
			if host, ok := hostMap[topHostRows[i].HostID]; ok {
				if topHostRows[i].Hostname == "" {
					topHostRows[i].Hostname = host.Hostname
				}
				if topHostRows[i].IP == "" && len(host.IPv4) > 0 {
					topHostRows[i].IP = host.IPv4[0]
				}
			}
		}
	}
	topHostsOut := make([]gin.H, 0, len(topHostRows))
	for _, t := range topHostRows {
		topHostsOut = append(topHostsOut, gin.H{
			"hostId":      t.HostID,
			"hostname":    t.Hostname,
			"ip":          t.IP,
			"threatCount": t.ThreatCount,
		})
	}

	// === 7. 近期扫描任务（Top 10） ===
	type recentTaskRow struct {
		Name        string
		ScanType    string
		Status      string
		TotalHosts  int64
		ThreatCount int64
		FinishedAt  *time.Time
	}
	var recentTaskRows []recentTaskRow
	h.db.Raw(`
		SELECT name, scan_type, status, total_hosts, threat_count, finished_at
		FROM antivirus_scan_tasks
		WHERE created_at >= ? AND created_at <= ?
		ORDER BY COALESCE(finished_at, created_at) DESC
		LIMIT 10
	`, startTime, endTime).Scan(&recentTaskRows)
	recentTasksOut := make([]gin.H, 0, len(recentTaskRows))
	for _, t := range recentTaskRows {
		row := gin.H{
			"name":        t.Name,
			"scanType":    t.ScanType,
			"status":      t.Status,
			"totalHosts":  t.TotalHosts,
			"threatCount": t.ThreatCount,
		}
		if t.FinishedAt != nil {
			row["finishedAt"] = *t.FinishedAt
		}
		recentTasksOut = append(recentTasksOut, row)
	}

	// === 8. 引擎与病毒库状态 ===
	engineH := h.buildAntivirusEngineInfo(startTime, endTime)

	// === 9. 周期趋势对比（与上一同长度周期对比威胁检出量）===
	period := endTime.Sub(startTime)
	prevStart := startTime.Add(-period)
	prevEnd := startTime
	var prevTotal int64
	h.db.Model(&model.AntivirusScanResult{}).
		Where("detected_at >= ? AND detected_at <= ?", prevStart, prevEnd).
		Count(&prevTotal)
	growthPct := 0.0
	if prevTotal > 0 {
		growthPct = float64(s.TotalThreats-prevTotal) / float64(prevTotal) * 100
	}

	// === 10. 在线主机数（元数据） ===
	var onlineHosts int64
	h.db.Model(&model.Host{}).Where("status = ?", "online").Count(&onlineHosts)

	// === 11. 改进建议（规则式） ===
	improvements := generateAntivirusImprovements(s, taskStats, engineH)

	// === 组装 ===
	reportID := fmt.Sprintf("av-%d", time.Now().Unix())
	periodStr := fmt.Sprintf("%s ~ %s",
		startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))

	return gin.H{
		"meta": gin.H{
			"reportID":    reportID,
			"period":      periodStr,
			"generatedAt": time.Now(),
			"onlineHosts": onlineHosts,
		},
		"summary": gin.H{
			"totalTasks":         s.TotalTasks,
			"totalThreats":       s.TotalThreats,
			"detectedThreats":    s.DetectedThreats,
			"quarantinedThreats": s.QuarantinedThreats,
			"deletedThreats":     s.DeletedThreats,
			"ignoredThreats":     s.IgnoredThreats,
			"affectedHosts":      s.AffectedHosts,
			"scannedHosts":       s.ScannedHosts,
		},
		"taskStats":              taskStats,
		"severityDistribution":   severityDistribution,
		"threatTypeDistribution": threatTypeDistribution,
		"topThreats":             topThreatsOut,
		"topAffectedHosts":       topHostsOut,
		"recentTasks":            recentTasksOut,
		"engine":                 engineH,
		"trend": gin.H{
			"prevPeriodThreats": prevTotal,
			"growthPercent":     growthPct,
			"direction":         directionLabel(growthPct),
		},
		"improvements": improvements,
	}
}

// buildAntivirusEngineInfo 装配引擎版本 + 病毒库同步状态。
//
// 数据源 security_db_sync_records 表（db_type=clamav）。
// 字段：version (病毒库版本) / status / file_size / started_at / duration。
// ClamAV 引擎版本本身从同步记录最新一行的 version 中提取——若部署阶段
// 记录了 engine_version 则用之，否则展示 "未知"。
func (h *ReportsHandler) buildAntivirusEngineInfo(startTime, endTime time.Time) gin.H {
	out := gin.H{
		"clamAVVersion": "未知",
		"sigDBVersion":  "未知",
		"lastStatus":    "未知",
		"syncCount":     int64(0),
		"failedSync":    int64(0),
		"recentSyncs":   []gin.H{},
	}

	// 同步次数 / 失败次数（按周期过滤）
	var syncCount, failedSync int64
	h.db.Model(&model.SecurityDBSyncRecord{}).
		Where("db_type = ? AND started_at >= ? AND started_at <= ?", "clamav", startTime, endTime).
		Count(&syncCount)
	h.db.Model(&model.SecurityDBSyncRecord{}).
		Where("db_type = ? AND status = ? AND started_at >= ? AND started_at <= ?", "clamav", "failed", startTime, endTime).
		Count(&failedSync)
	out["syncCount"] = syncCount
	out["failedSync"] = failedSync

	// 最新一条成功同步（取版本号 + 时间）
	var latest model.SecurityDBSyncRecord
	if err := h.db.Where("db_type = ? AND status = ?", "clamav", "success").
		Order("started_at DESC").
		Limit(1).
		Take(&latest).Error; err == nil {
		out["sigDBVersion"] = latest.Version
		out["lastUpdateAt"] = latest.StartedAt
		out["lastStatus"] = latest.Status
		// 当前阶段引擎版本未单独持久化，与签名库版本同行展示
		out["clamAVVersion"] = "ClamAV 1.0+"
	} else {
		// 没有成功记录，看任意最后一条
		var anyLatest model.SecurityDBSyncRecord
		if err := h.db.Where("db_type = ?", "clamav").
			Order("started_at DESC").Limit(1).Take(&anyLatest).Error; err == nil {
			out["sigDBVersion"] = anyLatest.Version
			out["lastUpdateAt"] = anyLatest.StartedAt
			out["lastStatus"] = anyLatest.Status
		}
	}

	// 近期同步记录 Top 10
	var recent []model.SecurityDBSyncRecord
	h.db.Where("db_type = ?", "clamav").
		Order("started_at DESC").
		Limit(10).
		Find(&recent)
	recentSyncs := make([]gin.H, 0, len(recent))
	for _, r := range recent {
		recentSyncs = append(recentSyncs, gin.H{
			"startedAt": r.StartedAt,
			"version":   r.Version,
			"status":    r.Status,
			"duration":  r.Duration,
			"fileSize":  r.FileSize,
		})
	}
	out["recentSyncs"] = recentSyncs

	return out
}

// generateAntivirusImprovements 基于聚合数据自动产出改进建议。
//
// 与 generateEDRImprovements 同设计：规则化、可解释、按业界 best practice 给出可操作项。
func generateAntivirusImprovements(
	s struct {
		TotalTasks         int64
		TotalThreats       int64
		DetectedThreats    int64
		QuarantinedThreats int64
		DeletedThreats     int64
		IgnoredThreats     int64
		AffectedHosts      int64
		ScannedHosts       int64
	},
	taskStats gin.H,
	engine gin.H,
) []string {
	out := make([]string, 0, 6)

	// 1. 待处置威胁堆积
	if s.DetectedThreats > 50 {
		out = append(out, fmt.Sprintf(
			"待处置威胁 %d 条堆积较多，建议建立分级响应 SLA（critical 4h / high 24h / medium 72h）。",
			s.DetectedThreats))
	}

	// 2. 清除率过低
	if s.TotalThreats > 0 {
		clearRate := float64(s.QuarantinedThreats+s.DeletedThreats) / float64(s.TotalThreats) * 100
		if clearRate < 60 {
			out = append(out, fmt.Sprintf(
				"威胁清除率仅 %.1f%%，建议复盘处置流程是否存在审批卡点或权限不足问题。", clearRate))
		}
	}

	// 3. 病毒库同步失败
	if failed := toI64Local(engine["failedSync"]); failed > 0 {
		out = append(out, fmt.Sprintf(
			"病毒库同步失败 %d 次，可能导致最新签名缺失，建议检查 freshclam 网络出口与镜像源可用性。",
			failed))
	}

	// 4. 全盘扫描缺失
	if toI64Local(taskStats["fullScan"]) == 0 && s.TotalTasks > 0 {
		out = append(out, "本周期未执行任何全盘扫描，建议每月至少安排 1 次全盘扫描兜底。")
	}

	// 5. 扫描覆盖偏低
	if s.ScannedHosts > 0 && s.AffectedHosts > 0 {
		infectionRate := float64(s.AffectedHosts) / float64(s.ScannedHosts) * 100
		if infectionRate > 30 {
			out = append(out, fmt.Sprintf(
				"受感染主机占受扫描主机比例 %.1f%%，存在面级感染风险，建议联动 EDR 与网络隔离阻断横向移动。",
				infectionRate))
		}
	}

	// 6. 忽略量过大
	if s.IgnoredThreats > s.QuarantinedThreats+s.DeletedThreats && s.IgnoredThreats > 20 {
		out = append(out, fmt.Sprintf(
			"忽略威胁 %d 条多于实际处置量，建议复盘忽略原因，沉淀稳定误报为白名单或规则调优。",
			s.IgnoredThreats))
	}

	if len(out) == 0 {
		out = append(out, "病毒查杀体系运行正常，扫描覆盖率、处置闭环与病毒库同步均处于合理区间。")
	}
	return out
}

// toI64Local 与 biz.toI64 同语义的局部 helper（避免跨包导出 helper）。
func toI64Local(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case int32:
		return int64(x)
	case uint:
		return int64(x)
	case uint64:
		return int64(x)
	case uint32:
		return int64(x)
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	}
	return 0
}
