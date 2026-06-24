// Package api 提供 HTTP API 处理器
//
// reports_vuln_data.go 为「漏洞管理 PDF 报告」装配原始数据。
//
// 与 reports.go 的 GetVulnerabilityReport (JSON API) 互补：
//   - JSON API 仅返回 UI 列表所需精简字段
//   - PDF 报告需要 8 章节维度（修复进度 / SLA / 情报源 / KEV / 组件 Top 等）
//
// 本文件仅装配数据，不修改 reports.go / reports_pdf.go / pdf_render.go。
// PDF endpoint 后续在 reports_pdf.go 增加 ExportVulnReportPDF 调用 BuildVulnReportData + RenderVulnReportHTML。
package api

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// vulnSLAWindow 严重程度 → 修复 SLA 时长。
// 与社区主流（PCI-DSS / 等保 2.0 三级）默认值对齐：
//
//	critical 24h / high 72h / medium 14d / low 30d
var vulnSLAWindow = map[string]time.Duration{
	"critical": 24 * time.Hour,
	"high":     72 * time.Hour,
	"medium":   14 * 24 * time.Hour,
	"low":      30 * 24 * time.Hour,
}

var vulnSLAWindowLabel = map[string]string{
	"critical": "24h",
	"high":     "72h",
	"medium":   "14d",
	"low":      "30d",
}

// BuildVulnReportData 装配漏洞管理报告原始数据，供 PDF 渲染消费。
//
// PDF / JSON / 后台调度可复用同一份装配函数避免数据漂移。
// 内部所有 query 失败均给安全默认值，不抛错。
func (h *ReportsHandler) BuildVulnReportData(startTime, endTime time.Time) gin.H {
	// === 1. 总览（CVE / 主机 / 状态分布） ===
	type summary struct {
		TotalVulns     int64
		UnpatchedVulns int64
		FixedVulns     int64
		IgnoredVulns   int64
		AffectedHosts  int64
		CriticalVulns  int64
		HighVulns      int64
		MediumVulns    int64
		LowVulns       int64
		WithExploit    int64
		InKEV          int64
	}
	var s summary

	timeRange := h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ?", startTime, endTime)
	timeRange.Count(&s.TotalVulns)

	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND status = ?", startTime, endTime, "unpatched").
		Count(&s.UnpatchedVulns)
	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND status = ?", startTime, endTime, "fixed").
		Count(&s.FixedVulns)
	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND status = ?", startTime, endTime, "ignored").
		Count(&s.IgnoredVulns)

	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND severity = ?", startTime, endTime, "critical").
		Count(&s.CriticalVulns)
	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND severity = ?", startTime, endTime, "high").
		Count(&s.HighVulns)
	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND severity = ?", startTime, endTime, "medium").
		Count(&s.MediumVulns)
	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND severity = ?", startTime, endTime, "low").
		Count(&s.LowVulns)

	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND has_exploit = ?", startTime, endTime, true).
		Count(&s.WithExploit)
	h.db.Model(&model.Vulnerability{}).
		Where("discovered_at >= ? AND discovered_at <= ? AND in_kev = ?", startTime, endTime, true).
		Count(&s.InKEV)

	// 影响主机数（join 周期内 vuln 后 DISTINCT host）
	h.db.Model(&model.HostVulnerability{}).
		Joins("LEFT JOIN vulnerabilities ON host_vulnerabilities.vuln_id = vulnerabilities.id").
		Where("vulnerabilities.discovered_at >= ? AND vulnerabilities.discovered_at <= ?", startTime, endTime).
		Distinct("host_vulnerabilities.host_id").
		Count(&s.AffectedHosts)

	// === 2. 严重程度分布 map ===
	severityDistribution := map[string]int64{
		"critical": s.CriticalVulns,
		"high":     s.HighVulns,
		"medium":   s.MediumVulns,
		"low":      s.LowVulns,
	}

	// === 3. 组件分布 Top 15 ===
	type componentRow struct {
		Component string
		Count     int64
	}
	var componentRows []componentRow
	h.db.Raw(`
		SELECT component, COUNT(*) as count
		FROM vulnerabilities
		WHERE discovered_at >= ? AND discovered_at <= ? AND component <> ''
		GROUP BY component
		ORDER BY count DESC
		LIMIT 15
	`, startTime, endTime).Scan(&componentRows)
	componentDistribution := make([]gin.H, 0, len(componentRows))
	for _, r := range componentRows {
		componentDistribution = append(componentDistribution, gin.H{
			"component": r.Component,
			"count":     r.Count,
		})
	}

	// === 4. Top 10 高危 CVE ===
	type topVulnRow struct {
		CveID         string
		Severity      string
		CvssScore     float64
		Component     string
		AffectedHosts int
		HasExploit    bool
		InKEV         bool
		Status        string
	}
	var topVulns []topVulnRow
	h.db.Raw(`
		SELECT cve_id, severity, cvss_score, component, affected_hosts, has_exploit, in_kev, status
		FROM vulnerabilities
		WHERE discovered_at >= ? AND discovered_at <= ?
		ORDER BY (CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) DESC,
		         cvss_score DESC, affected_hosts DESC
		LIMIT 10
	`, startTime, endTime).Scan(&topVulns)
	topVulnsOut := make([]gin.H, 0, len(topVulns))
	for _, v := range topVulns {
		topVulnsOut = append(topVulnsOut, gin.H{
			"cveId":         v.CveID,
			"severity":      v.Severity,
			"cvssScore":     v.CvssScore,
			"component":     v.Component,
			"affectedHosts": v.AffectedHosts,
			"hasExploit":    v.HasExploit,
			"inKev":         v.InKEV,
			"status":        v.Status,
		})
	}

	// === 5. Top 10 受影响主机 ===
	type topVulnHostRow struct {
		HostID        string
		Hostname      string
		IP            string
		VulnCount     int64
		CriticalCount int64
		HighCount     int64
	}
	var topVulnHosts []topVulnHostRow
	h.db.Raw(`
		SELECT hv.host_id,
			MAX(hv.hostname) as hostname,
			MAX(hv.ip) as ip,
			COUNT(*) as vuln_count,
			SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
			SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count
		FROM host_vulnerabilities hv
		LEFT JOIN vulnerabilities v ON hv.vuln_id = v.id
		WHERE v.discovered_at >= ? AND v.discovered_at <= ?
		GROUP BY hv.host_id
		ORDER BY vuln_count DESC
		LIMIT 10
	`, startTime, endTime).Scan(&topVulnHosts)

	// 补全主机信息（hosts 表）
	vhIDs := make([]string, 0, len(topVulnHosts))
	for _, row := range topVulnHosts {
		if row.Hostname == "" || row.IP == "" {
			vhIDs = append(vhIDs, row.HostID)
		}
	}
	if len(vhIDs) > 0 {
		var hosts []model.Host
		h.db.Where("host_id IN ?", vhIDs).Find(&hosts)
		hostMap := make(map[string]model.Host, len(hosts))
		for _, host := range hosts {
			hostMap[host.HostID] = host
		}
		for i := range topVulnHosts {
			if host, ok := hostMap[topVulnHosts[i].HostID]; ok {
				if topVulnHosts[i].Hostname == "" {
					topVulnHosts[i].Hostname = host.Hostname
				}
				if topVulnHosts[i].IP == "" && len(host.IPv4) > 0 {
					topVulnHosts[i].IP = host.IPv4[0]
				}
			}
		}
	}
	topHostsOut := make([]gin.H, 0, len(topVulnHosts))
	for _, t := range topVulnHosts {
		topHostsOut = append(topHostsOut, gin.H{
			"hostId":        t.HostID,
			"hostname":      t.Hostname,
			"ip":            t.IP,
			"vulnCount":     t.VulnCount,
			"criticalCount": t.CriticalCount,
			"highCount":     t.HighCount,
		})
	}

	// === 6. 修复进度（remediation_tasks 统计）===
	fixProgress := h.queryVulnFixProgress(startTime, endTime)

	// === 7. SLA 达成（按严重程度分桶）===
	slaStats := h.queryVulnSLAStats(startTime, endTime)

	// === 8. CVE 情报源（vuln_data_sources）+ 来源分布 ===
	sources, totalSources, enabledSources := h.queryVulnSources()
	sourceDistribution := h.queryVulnSourceDistribution(startTime, endTime)

	// === 9. 在线主机数 ===
	var onlineHosts int64
	h.db.Model(&model.Host{}).Where("status = ?", "online").Count(&onlineHosts)

	// === 10. 改进建议 ===
	improvements := generateVulnImprovements(s, fixProgress, slaStats)

	// === 组装 ===
	reportID := fmt.Sprintf("vuln-%d", time.Now().Unix())
	periodStr := fmt.Sprintf("%s ~ %s",
		startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))

	return gin.H{
		"meta": gin.H{
			"reportID":       reportID,
			"period":         periodStr,
			"generatedAt":    time.Now(),
			"onlineHosts":    onlineHosts,
			"totalSources":   totalSources,
			"enabledSources": enabledSources,
		},
		"summary": gin.H{
			"totalVulns":     s.TotalVulns,
			"unpatchedVulns": s.UnpatchedVulns,
			"fixedVulns":     s.FixedVulns,
			"ignoredVulns":   s.IgnoredVulns,
			"affectedHosts":  s.AffectedHosts,
			"criticalVulns":  s.CriticalVulns,
			"highVulns":      s.HighVulns,
			"mediumVulns":    s.MediumVulns,
			"lowVulns":       s.LowVulns,
			"withExploit":    s.WithExploit,
			"inKev":          s.InKEV,
		},
		"severityDistribution":  severityDistribution,
		"componentDistribution": componentDistribution,
		"topVulns":              topVulnsOut,
		"topAffectedHosts":      topHostsOut,
		"fixProgress":           fixProgress,
		"slaStats":              slaStats,
		"sources":               sources,
		"sourceDistribution":    sourceDistribution,
		"improvements":          improvements,
	}
}

// queryVulnFixProgress 汇总 remediation_tasks 状态分布。
//
// 周期：以 task.created_at 落在 [startTime, endTime] 为准（与 vuln 披露周期解耦）。
func (h *ReportsHandler) queryVulnFixProgress(startTime, endTime time.Time) gin.H {
	type row struct {
		Status string
		Cnt    int64
	}
	var rows []row
	h.db.Raw(`
		SELECT status, COUNT(*) AS cnt FROM remediation_tasks
		WHERE created_at >= ? AND created_at <= ?
		GROUP BY status
	`, startTime, endTime).Scan(&rows)

	statusMap := make(map[string]int64, len(rows))
	var total int64
	for _, r := range rows {
		statusMap[r.Status] = r.Cnt
		total += r.Cnt
	}

	// 把多个 status 归并为 4 类：success(含 verified) / failed / running / pending_verify
	success := statusMap[model.RemTaskMainSuccess] + statusMap[model.RemTaskMainVerified]
	failed := statusMap["failed"] + statusMap[model.RemTaskMainVerifyFailed] + statusMap[model.RemTaskMainCancelled]
	running := statusMap[model.RemTaskMainRunning] + statusMap[model.RemTaskMainVerifying] + statusMap["pending"] + statusMap["confirmed"]
	pendingVerify := statusMap[model.RemTaskMainSuccessPendingVerify] + statusMap[model.RemTaskMainVerifyBlocked]

	return gin.H{
		"totalTasks":         total,
		"successTasks":       success,
		"failedTasks":        failed,
		"runningTasks":       running,
		"pendingVerifyTasks": pendingVerify,
	}
}

// queryVulnSLAStats 按严重程度分桶统计 SLA 达成率。
//
// 分母：周期内 status=fixed 且 patched_at 不为空的 CVE
// 分子：patched_at - discovered_at ≤ SLA window
func (h *ReportsHandler) queryVulnSLAStats(startTime, endTime time.Time) []gin.H {
	out := make([]gin.H, 0, 4)
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		var total, met int64
		h.db.Model(&model.Vulnerability{}).
			Where("discovered_at >= ? AND discovered_at <= ?", startTime, endTime).
			Where("severity = ? AND status = ? AND patched_at IS NOT NULL", sev, "fixed").
			Count(&total)
		window := vulnSLAWindow[sev]
		// MySQL TIMESTAMPDIFF 秒级精度即可
		h.db.Model(&model.Vulnerability{}).
			Where("discovered_at >= ? AND discovered_at <= ?", startTime, endTime).
			Where("severity = ? AND status = ? AND patched_at IS NOT NULL", sev, "fixed").
			Where("TIMESTAMPDIFF(SECOND, discovered_at, patched_at) <= ?", int64(window.Seconds())).
			Count(&met)
		out = append(out, gin.H{
			"severity": sev,
			"window":   vulnSLAWindowLabel[sev],
			"met":      met,
			"total":    total,
		})
	}
	return out
}

// queryVulnSources 列出所有情报源及其同步状态。
func (h *ReportsHandler) queryVulnSources() ([]gin.H, int64, int64) {
	var sources []model.VulnDataSource
	h.db.Model(&model.VulnDataSource{}).Order("region, category, name").Find(&sources)

	var totalSources, enabledSources int64
	totalSources = int64(len(sources))
	out := make([]gin.H, 0, len(sources))
	for _, src := range sources {
		if src.Enabled {
			enabledSources++
		}
		lastSync := "-"
		if src.LastSyncAt != nil {
			lastSync = time.Time(*src.LastSyncAt).Format("2006-01-02 15:04")
		}
		out = append(out, gin.H{
			"displayName": src.DisplayName,
			"region":      src.Region,
			"category":    src.Category,
			"enabled":     src.Enabled,
			"lastSyncAt":  lastSync,
			"lastCount":   src.LastCount,
			"lastStatus":  src.LastStatus,
		})
	}
	return out, totalSources, enabledSources
}

// queryVulnSourceDistribution 报告周期内 CVE 按 source 字段的分布。
func (h *ReportsHandler) queryVulnSourceDistribution(startTime, endTime time.Time) []gin.H {
	type row struct {
		Source string
		Cnt    int64
	}
	var rows []row
	h.db.Raw(`
		SELECT source, COUNT(*) AS cnt FROM vulnerabilities
		WHERE discovered_at >= ? AND discovered_at <= ?
		GROUP BY source ORDER BY cnt DESC
	`, startTime, endTime).Scan(&rows)
	out := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		src := r.Source
		if src == "" {
			src = "unknown"
		}
		out = append(out, gin.H{"source": src, "count": r.Cnt})
	}
	return out
}

// generateVulnImprovements 自动产出改进建议（规则化，非 LLM）。
func generateVulnImprovements(
	s struct {
		TotalVulns     int64
		UnpatchedVulns int64
		FixedVulns     int64
		IgnoredVulns   int64
		AffectedHosts  int64
		CriticalVulns  int64
		HighVulns      int64
		MediumVulns    int64
		LowVulns       int64
		WithExploit    int64
		InKEV          int64
	},
	fix gin.H,
	sla []gin.H,
) []string {
	out := make([]string, 0, 6)

	if s.CriticalVulns > 0 {
		out = append(out, fmt.Sprintf(
			"发现 %d 个严重 CVE，建议 24h 内启动应急修复流程，并优先纳入 SLA 看板。",
			s.CriticalVulns))
	}
	if s.InKEV > 0 {
		out = append(out, fmt.Sprintf(
			"命中 CISA KEV 名录 %d 个，存在已知活跃剥削链，应在 ITSM 中标记最高优先级。",
			s.InKEV))
	}
	if s.WithExploit > 5 {
		out = append(out, fmt.Sprintf(
			"%d 个 CVE 已公开剥削代码，攻击门槛低，建议优先匹配 IDS/IPS 规则做横向阻断。",
			s.WithExploit))
	}
	if s.TotalVulns > 0 {
		fixRate := float64(s.FixedVulns) / float64(s.TotalVulns) * 100
		if fixRate < 50 && s.UnpatchedVulns > 20 {
			out = append(out, fmt.Sprintf(
				"修复率 %.1f%% 偏低，仍 %d 个 CVE 未处置，建议加大运维资源投入或评估批量补丁窗口。",
				fixRate, s.UnpatchedVulns))
		}
	}
	// SLA 达成检查
	for _, r := range sla {
		sev, _ := r["severity"].(string)
		total, _ := r["total"].(int64)
		met, _ := r["met"].(int64)
		if total > 0 {
			rate := float64(met) / float64(total) * 100
			if (sev == "critical" || sev == "high") && rate < 80 {
				out = append(out, fmt.Sprintf(
					"%s 级 SLA 达成率仅 %.1f%%（%d / %d），建议复盘审批 / 维护窗口流程缩短 MTTR。",
					vulnSLAWindowLabel[sev], rate, met, total))
				break // 一条 SLA 建议足够
			}
		}
	}
	// 修复任务成功率
	if total, ok := fix["totalTasks"].(int64); ok && total > 10 {
		if success, ok := fix["successTasks"].(int64); ok {
			rate := float64(success) / float64(total) * 100
			if rate < 60 {
				out = append(out, fmt.Sprintf(
					"修复任务成功率 %.1f%%（%d / %d），建议结合 pre-check 状态完善命令模板，减少 outdated_repo / not_in_repo 失败。",
					rate, success, total))
			}
		}
	}
	if s.IgnoredVulns > s.FixedVulns && s.IgnoredVulns > 30 {
		out = append(out, fmt.Sprintf(
			"忽略 %d 个高于已修复 %d 个，建议复盘忽略原因，避免误把可修复 CVE 标记为豁免。",
			s.IgnoredVulns, s.FixedVulns))
	}

	if len(out) == 0 {
		out = append(out, "本周期漏洞管理运行正常，CVE 披露 / 修复 / SLA 均处于合理区间，保持定期情报源同步即可。")
	}
	return out
}
