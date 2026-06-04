// Package api - reports_task_data.go 任务报告 (按 task_id 维度) 数据装配。
//
// 与 reports.go 的 GetTaskReport / GetExecutiveTaskReport 共享同一份数据源
// (scan_tasks / scan_results / hosts / policies)，但产出结构面向 PDF 模板，
// 字段命名与 biz/pdf_render_task.go 中 taskReportView 严格对齐。
//
// PDF 渲染入口 (reports_pdf.go 中的新 handler) 调用本函数获取 gin.H，
// 然后传给 biz.RenderTaskReportHTML 完成 HTML 字符串渲染。
package api

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// BuildTaskReportData 装配任务报告原始数据。
//
// 参数 taskID 是 scan_tasks.task_id 主键。
// 返回 gin.H — 若任务不存在，返回 nil（调用方需判空后写错误响应）。
//
// PDF 渲染路径与 GetTaskReport JSON API 共享主体逻辑，避免数据漂移；
// 但此处额外计算了 PDF 模板需要的衍生字段（duration、failure_rate、
// host_status_classification、retry_hosts、critical_suggestions 等）。
func (h *ReportsHandler) BuildTaskReportData(taskID string) gin.H {
	if taskID == "" {
		return nil
	}

	// === 1. 任务基础信息 ===
	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		h.logger.Warn("任务报告：任务不存在", zap.String("task_id", taskID), zap.Error(err))
		return nil
	}

	// === 2. 策略名称（支持多策略）===
	policyName := h.resolvePolicyName(&task)

	// === 3. 检查结果总览 ===
	var stats struct {
		Total   int64
		Passed  int64
		Failed  int64
		Warning int64
		NA      int64
	}
	h.db.Model(&model.ScanResult{}).Where("task_id = ?", taskID).Count(&stats.Total)
	h.db.Model(&model.ScanResult{}).Where("task_id = ? AND status = ?", taskID, "pass").Count(&stats.Passed)
	h.db.Model(&model.ScanResult{}).Where("task_id = ? AND status = ?", taskID, "fail").Count(&stats.Failed)
	h.db.Model(&model.ScanResult{}).Where("task_id = ? AND status = ?", taskID, "error").Count(&stats.Warning)
	h.db.Model(&model.ScanResult{}).Where("task_id = ? AND status = ?", taskID, "na").Count(&stats.NA)

	passRate := 0.0
	if stats.Total > 0 {
		passRate = float64(stats.Passed) / float64(stats.Total) * 100.0
	}

	// === 4. 涉及主机数 / 规则数 ===
	var hostCount, ruleCount int64
	h.db.Model(&model.ScanResult{}).Where("task_id = ?", taskID).Distinct("host_id").Count(&hostCount)
	h.db.Model(&model.ScanResult{}).Where("task_id = ?", taskID).Distinct("rule_id").Count(&ruleCount)

	// === 5. 严重程度分布（仅失败项）===
	severityDistribution := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	{
		var rows []struct {
			Severity string
			Count    int64
		}
		h.db.Model(&model.ScanResult{}).
			Select("severity, COUNT(*) as count").
			Where("task_id = ? AND status = ?", taskID, "fail").
			Group("severity").Find(&rows)
		for _, r := range rows {
			if r.Severity != "" {
				severityDistribution[r.Severity] = r.Count
			}
		}
	}

	// === 6. 类别分布（仅失败项，附中文名）===
	categoryDistribution := make([]gin.H, 0)
	{
		var rows []struct {
			Category string
			Count    int64
		}
		h.db.Model(&model.ScanResult{}).
			Select("category, COUNT(*) as count").
			Where("task_id = ? AND status = ?", taskID, "fail").
			Where("category <> ''").
			Group("category").
			Order("count DESC").
			Find(&rows)
		for _, r := range rows {
			categoryDistribution = append(categoryDistribution, gin.H{
				"category": r.Category,
				"label":    getCategoryName(r.Category),
				"count":    r.Count,
			})
		}
	}

	// === 7. 主机执行明细 ===
	type hostStatRow struct {
		HostID        string
		PassedCount   int64
		FailedCount   int64
		WarningCount  int64
		NACount       int64
		CriticalFails int64
		HighFails     int64
	}
	var hostStats []hostStatRow
	h.db.Raw(`
		SELECT
			host_id,
			SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) as passed_count,
			SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) as failed_count,
			SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as warning_count,
			SUM(CASE WHEN status = 'na' THEN 1 ELSE 0 END) as na_count,
			SUM(CASE WHEN status = 'fail' AND severity = 'critical' THEN 1 ELSE 0 END) as critical_fails,
			SUM(CASE WHEN status = 'fail' AND severity = 'high' THEN 1 ELSE 0 END) as high_fails
		FROM scan_results WHERE task_id = ?
		GROUP BY host_id
	`, taskID).Scan(&hostStats)

	// 拉主机元信息
	hostIDs := make([]string, 0, len(hostStats))
	for _, hs := range hostStats {
		hostIDs = append(hostIDs, hs.HostID)
	}
	hostMap := make(map[string]model.Host, len(hostIDs))
	if len(hostIDs) > 0 {
		var hosts []model.Host
		h.db.Where("host_id IN ?", hostIDs).Find(&hosts)
		for _, host := range hosts {
			hostMap[host.HostID] = host
		}
	}

	hostDetails := make([]gin.H, 0, len(hostStats))
	var successHosts, failedHosts, warningHosts int64
	for _, hs := range hostStats {
		host := hostMap[hs.HostID]
		ip := ""
		if len(host.IPv4) > 0 {
			ip = host.IPv4[0]
		}
		totalChecks := hs.PassedCount + hs.FailedCount + hs.WarningCount
		score := 0.0
		if totalChecks > 0 {
			score = float64(hs.PassedCount) / float64(totalChecks) * 100.0
		}
		status := "pass"
		switch {
		case hs.CriticalFails > 0 || hs.HighFails > 0:
			status = "fail"
			failedHosts++
		case hs.FailedCount > 0 || hs.WarningCount > 0:
			status = "warning"
			warningHosts++
		default:
			successHosts++
		}
		hostname := host.Hostname
		if hostname == "" {
			hostname = hs.HostID
		}
		hostDetails = append(hostDetails, gin.H{
			"hostname":     hostname,
			"ip":           ip,
			"osFamily":     host.OSFamily,
			"status":       status,
			"passedCount":  hs.PassedCount,
			"failedCount":  hs.FailedCount,
			"warningCount": hs.WarningCount,
			"naCount":      hs.NACount,
			"score":        score,
		})
	}

	// 未响应主机数 = 已下发 - 已回传结果
	pendingHosts := int64(task.DispatchedHostCount) - hostCount
	if pendingHosts < 0 {
		pendingHosts = 0
	}

	// === 8. 高危失败规则（严重 + 高危）===
	type ruleStatRow struct {
		RuleID        string
		Title         string
		Severity      string
		Category      string
		FixSuggestion string
		AffectedCount int64
	}
	var ruleStats []ruleStatRow
	h.db.Raw(`
		SELECT
			rule_id, title, severity, category, fix_suggestion,
			COUNT(DISTINCT host_id) as affected_count
		FROM scan_results
		WHERE task_id = ? AND status = 'fail' AND severity IN ('critical','high')
		GROUP BY rule_id, title, severity, category, fix_suggestion
		ORDER BY
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
			affected_count DESC
		LIMIT 20
	`, taskID).Scan(&ruleStats)

	criticalRules := make([]gin.H, 0, len(ruleStats))
	criticalSuggestions := make([]gin.H, 0, 5)
	for i, r := range ruleStats {
		criticalRules = append(criticalRules, gin.H{
			"title":         r.Title,
			"category":      getCategoryName(r.Category),
			"severity":      r.Severity,
			"affectedCount": r.AffectedCount,
		})
		if i < 5 {
			suggestion := getRiskRecommendation(r.RuleID, r.FixSuggestion, r.Category)
			criticalSuggestions = append(criticalSuggestions, gin.H{
				"title":      r.Title,
				"suggestion": suggestion,
			})
		}
	}

	// === 9. 建议复测主机（status=fail 或 异常多）===
	retryHosts := make([]gin.H, 0)
	for _, hs := range hostStats {
		host := hostMap[hs.HostID]
		hostname := host.Hostname
		if hostname == "" {
			hostname = hs.HostID
		}
		ip := ""
		if len(host.IPv4) > 0 {
			ip = host.IPv4[0]
		}
		var reason string
		switch {
		case hs.WarningCount > 5:
			reason = fmt.Sprintf("执行异常 %d 条，疑似命令权限不足或主机连通性问题", hs.WarningCount)
		case hs.CriticalFails > 0:
			reason = fmt.Sprintf("存在 %d 项严重失败配置，整改后建议复测", hs.CriticalFails)
		}
		if reason != "" {
			retryHosts = append(retryHosts, gin.H{
				"hostname": hostname,
				"ip":       ip,
				"reason":   reason,
			})
			if len(retryHosts) >= 10 {
				break
			}
		}
	}

	// === 10. 改进建议（基于已聚合数据生成）===
	improvements := buildTaskImprovements(stats.Failed, severityDistribution, pendingHosts, stats.Warning, passRate)

	// === 11. Meta 字段装配 ===
	executedAt, completedAt := "-", "-"
	var duration string = "-"
	if task.ExecutedAt != nil {
		executedAt = time.Time(*task.ExecutedAt).Format("2006-01-02 15:04:05")
	}
	if task.CompletedAt != nil {
		completedAt = time.Time(*task.CompletedAt).Format("2006-01-02 15:04:05")
	}
	if task.ExecutedAt != nil && task.CompletedAt != nil {
		duration = formatTaskDuration(time.Time(*task.CompletedAt).Sub(time.Time(*task.ExecutedAt)))
	}
	// scheduledAt 暂用 created_at 作为「计划/创建时间」
	scheduledAt := time.Time(task.CreatedAt).Format("2006-01-02 15:04:05")

	targetDesc := h.describeTaskTarget(&task)

	reportID := fmt.Sprintf("TR-%s-%s", time.Now().Format("20060102"), shortIDForReport(task.TaskID))

	return gin.H{
		"meta": gin.H{
			"reportID":       reportID,
			"generatedAt":    time.Now().Format("2006-01-02 15:04:05"),
			"taskID":         task.TaskID,
			"taskName":       task.Name,
			"taskType":       string(task.Type),
			"policyName":     policyName,
			"status":         string(task.Status),
			"scheduledAt":    scheduledAt,
			"executedAt":     executedAt,
			"completedAt":    completedAt,
			"duration":       duration,
			"timeoutMinutes": task.TimeoutMinutes,
			"targetType":     string(task.TargetType),
			"targetDesc":     targetDesc,
			"failedReason":   task.FailedReason,
		},
		"summary": gin.H{
			"hostCount":           hostCount,
			"ruleCount":           ruleCount,
			"totalChecks":         stats.Total,
			"passedChecks":        stats.Passed,
			"failedChecks":        stats.Failed,
			"warningChecks":       stats.Warning,
			"naChecks":            stats.NA,
			"passRate":            passRate,
			"dispatchedHostCount": int64(task.DispatchedHostCount),
			"completedHostCount":  int64(task.CompletedHostCount),
			"successHosts":        successHosts,
			"failedHosts":         failedHosts,
			"warningHosts":        warningHosts,
			"pendingHosts":        pendingHosts,
		},
		"severityDistribution": severityDistribution,
		"categoryDistribution": categoryDistribution,
		"hostDetails":          hostDetails,
		"criticalRules":        criticalRules,
		"criticalSuggestions":  criticalSuggestions,
		"retryHosts":           retryHosts,
		"improvements":         improvements,
	}
}

// resolvePolicyName 解析任务关联策略名（兼容多策略）。
func (h *ReportsHandler) resolvePolicyName(task *model.ScanTask) string {
	policyIDs := task.GetPolicyIDs()
	if len(policyIDs) == 0 {
		return "-"
	}
	var names []string
	for _, pid := range policyIDs {
		var p model.Policy
		if err := h.db.Where("id = ?", pid).First(&p).Error; err == nil && p.Name != "" {
			names = append(names, p.Name)
		}
	}
	switch len(names) {
	case 0:
		return "-"
	case 1:
		return names[0]
	default:
		return fmt.Sprintf("%s 等 %d 个策略", names[0], len(names))
	}
}

// describeTaskTarget 把 TargetType + TargetConfig 翻译为人类可读描述。
func (h *ReportsHandler) describeTaskTarget(task *model.ScanTask) string {
	switch task.TargetType {
	case model.TargetTypeAll:
		return "全部主机"
	case model.TargetTypeHostIDs:
		n := len(task.TargetConfig.HostIDs)
		return fmt.Sprintf("指定主机 %d 台", n)
	case model.TargetTypeOSFamily:
		if len(task.TargetConfig.OSFamily) > 0 {
			s := ""
			for i, os := range task.TargetConfig.OSFamily {
				if i > 0 {
					s += "、"
				}
				s += os
			}
			return "OS 类型：" + s
		}
		return "按 OS 类型"
	}
	return "-"
}

// buildTaskImprovements 基于任务结果统计生成改进建议。
func buildTaskImprovements(failed int64, severity map[string]int64, pending int64, warning int64, passRate float64) []string {
	out := make([]string, 0, 5)
	if severity["critical"] > 0 {
		out = append(out, fmt.Sprintf(
			"立即处置 %d 项严重失败配置，这些问题可能允许攻击者完全控制主机。",
			severity["critical"]))
	}
	if severity["high"] > 0 {
		out = append(out, fmt.Sprintf(
			"24 小时内整改 %d 项高危失败配置，降低主机被入侵风险。",
			severity["high"]))
	}
	if pending > 0 {
		out = append(out, fmt.Sprintf(
			"%d 台主机未回传结果，建议核查 Agent 连通性后重新下发任务复测。", pending))
	}
	if warning > 10 {
		out = append(out, fmt.Sprintf(
			"任务执行过程中 %d 条检查异常（命令失败/超时），建议核查 Agent 权限与脚本兼容性。", warning))
	}
	if failed > 0 && passRate < 60 {
		out = append(out, "本次合规率低于 60%，建议安排集中整改周期并在整改后重新执行任务验证。")
	}
	if failed == 0 && warning == 0 {
		out = append(out, "本次任务全部检查通过，建议保持现有配置并定期执行复检。")
	}
	if len(out) == 0 {
		out = append(out, "本次任务整体执行正常，建议持续监控并定期复检。")
	}
	return out
}

// formatTaskDuration 把 time.Duration 渲染为人类可读字符串。
func formatTaskDuration(d time.Duration) string {
	if d < 0 {
		return "-"
	}
	if d < time.Minute {
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d 分 %d 秒", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d 小时 %d 分", int(d.Hours()), int(d.Minutes())%60)
}

// shortIDForReport 取 task_id 前 8 位作为报告编号片段。
func shortIDForReport(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}
