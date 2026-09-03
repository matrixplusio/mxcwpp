// Package api - reports_kube_data.go 装配 K8s 容器安全 PDF 报告原始数据。
//
// 与 reports_edr.go 同模式：纯数据装配函数，返回 gin.H，供 PDF 渲染层
// (biz.RenderKubeReportHTML) 与 JSON API 共享，避免数据漂移。
//
// 数据源 (MySQL):
//   - kube_clusters         (集群拓扑 / 节点 / Pod / Namespace)
//   - kube_alarms           (运行时告警: 类型 / 严重 / Namespace / Target)
//   - kube_baselines        (CIS 基线: RBAC / Network / Workload / Pod)
//   - kube_baseline_alerts  (基线告警: active / resolved / ignored)
//   - image_scans           (镜像扫描汇总: 高危镜像)
//   - image_vulnerabilities (镜像 CVE 详情)
package api

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// BuildKubeReportData 装配 K8s 容器安全报告原始数据。
//
// 不存盘、不写日志，纯数据组装；调用方负责 saveGeneratedReport / Success(c,…)。
// 与 GetKubeReport (reports.go) 共享数据源但格式适配 PDF 模板。
func (h *ReportsHandler) BuildKubeReportData(startTime, endTime time.Time) gin.H {
	// === 1. 集群汇总（拓扑 + 资源数）===
	var clusters []model.KubeCluster
	h.db.Order("id ASC").Find(&clusters)
	var (
		clusterCount   = int64(len(clusters))
		runningCount   int64
		offlineCount   int64
		totalNodes     int64
		totalPods      int64
		totalNs        int64
		avgHealthScore float64
	)
	for _, c := range clusters {
		if c.Status == model.KubeClusterStatusRunning {
			runningCount++
		} else if c.Status == model.KubeClusterStatusOffline {
			offlineCount++
		}
		totalNodes += int64(c.NodeCount)
		totalPods += int64(c.PodCount)
		totalNs += int64(c.NamespaceCount)
		avgHealthScore += float64(c.HealthScore)
	}
	if clusterCount > 0 {
		avgHealthScore /= float64(clusterCount)
	}

	// 集群列表（topology 章节）
	clusterRows := make([]gin.H, 0, len(clusters))
	for _, c := range clusters {
		clusterRows = append(clusterRows, gin.H{
			"name":           c.Name,
			"version":        c.Version,
			"status":         string(c.Status),
			"nodeCount":      c.NodeCount,
			"podCount":       c.PodCount,
			"namespaceCount": c.NamespaceCount,
			"healthScore":    c.HealthScore,
		})
	}

	// === 2. 告警概览 ===
	type alarmAgg struct {
		Total     int64
		Pending   int64
		Processed int64
		Ignored   int64
	}
	var aAgg alarmAgg
	h.db.Model(&model.KubeAlarm{}).
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Count(&aAgg.Total)
	h.db.Model(&model.KubeAlarm{}).
		Where("created_at >= ? AND created_at <= ? AND status = ?", startTime, endTime, "pending").
		Count(&aAgg.Pending)
	h.db.Model(&model.KubeAlarm{}).
		Where("created_at >= ? AND created_at <= ? AND status = ?", startTime, endTime, "processed").
		Count(&aAgg.Processed)
	h.db.Model(&model.KubeAlarm{}).
		Where("created_at >= ? AND created_at <= ? AND status = ?", startTime, endTime, "ignored").
		Count(&aAgg.Ignored)

	// 告警严重程度分布
	severityDistribution := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var sevRows []struct {
		Severity string
		Count    int64
	}
	h.db.Model(&model.KubeAlarm{}).
		Select("severity, COUNT(*) as count").
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Group("severity").
		Scan(&sevRows)
	for _, r := range sevRows {
		if r.Severity != "" {
			severityDistribution[r.Severity] = r.Count
		}
	}

	// === 3. 告警类型 Top（替代 EDR 的 MITRE tactic）===
	type alarmTypeRow struct {
		AlarmType string
		Count     int64
	}
	var alarmTypeRows []alarmTypeRow
	h.db.Model(&model.KubeAlarm{}).
		Select("alarm_type, COUNT(*) as count").
		Where("created_at >= ? AND created_at <= ? AND alarm_type <> ''", startTime, endTime).
		Group("alarm_type").
		Order("count DESC").
		Scan(&alarmTypeRows)
	alarmTypeDistribution := map[string]int64{}
	topAlarmTypes := make([]gin.H, 0, len(alarmTypeRows))
	for _, r := range alarmTypeRows {
		alarmTypeDistribution[r.AlarmType] = r.Count
		topAlarmTypes = append(topAlarmTypes, gin.H{
			"alarmType": r.AlarmType,
			"count":     r.Count,
		})
	}

	// === 4. Top 工作负载（按告警数）===
	type targetRow struct {
		Target      string
		Namespace   string
		ClusterName string
		AlarmType   string
		Count       int64
		Severity    string
	}
	var targetRows []targetRow
	h.db.Raw(`
		SELECT target,
		       MAX(namespace) AS namespace,
		       MAX(cluster_name) AS cluster_name,
		       MAX(alarm_type) AS alarm_type,
		       MAX(severity) AS severity,
		       COUNT(*) AS count
		FROM kube_alarms
		WHERE created_at >= ? AND created_at <= ? AND target <> ''
		GROUP BY target
		ORDER BY count DESC
		LIMIT 10
	`, startTime, endTime).Scan(&targetRows)
	topWorkloads := make([]gin.H, 0, len(targetRows))
	for _, r := range targetRows {
		topWorkloads = append(topWorkloads, gin.H{
			"target":      r.Target,
			"namespace":   r.Namespace,
			"clusterName": r.ClusterName,
			"alarmType":   r.AlarmType,
			"severity":    r.Severity,
			"count":       r.Count,
		})
	}

	// === 5. Top Namespace ===
	type nsRow struct {
		Namespace   string
		ClusterName string
		Count       int64
	}
	var nsRows []nsRow
	h.db.Raw(`
		SELECT namespace, MAX(cluster_name) AS cluster_name, COUNT(*) AS count
		FROM kube_alarms
		WHERE created_at >= ? AND created_at <= ? AND namespace <> ''
		GROUP BY namespace
		ORDER BY count DESC LIMIT 10
	`, startTime, endTime).Scan(&nsRows)
	topNamespaces := make([]gin.H, 0, len(nsRows))
	for _, r := range nsRows {
		topNamespaces = append(topNamespaces, gin.H{
			"namespace":   r.Namespace,
			"clusterName": r.ClusterName,
			"count":       r.Count,
		})
	}

	// === 6. 基线检查（当前状态，不按时间筛选）===
	var baselineTotal, baselinePass, baselineFail, baselineWarn int64
	h.db.Model(&model.KubeBaseline{}).Count(&baselineTotal)
	h.db.Model(&model.KubeBaseline{}).Where("result = ?", "pass").Count(&baselinePass)
	h.db.Model(&model.KubeBaseline{}).Where("result = ?", "fail").Count(&baselineFail)
	h.db.Model(&model.KubeBaseline{}).Where("result = ?", "warning").Count(&baselineWarn)

	baselinePassRate := 0.0
	if baselineTotal > 0 {
		baselinePassRate = float64(baselinePass) / float64(baselineTotal) * 100.0
	}

	// 基线分类（RBAC / Network / Workload / Pod / Cluster）通过率
	type baselineCatStat struct {
		Category string
		Total    int64
		Passed   int64
		Failed   int64
	}
	var catStats []baselineCatStat
	h.db.Raw(`
		SELECT category,
		       COUNT(*) AS total,
		       SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) AS passed,
		       SUM(CASE WHEN result = 'fail' THEN 1 ELSE 0 END) AS failed
		FROM kube_baselines
		WHERE category <> ''
		GROUP BY category
	`).Scan(&catStats)
	baselineByCategory := make([]gin.H, 0, len(catStats))
	for _, s := range catStats {
		rate := 0.0
		if s.Total > 0 {
			rate = float64(s.Passed) / float64(s.Total) * 100.0
		}
		baselineByCategory = append(baselineByCategory, gin.H{
			"category": s.Category,
			"total":    s.Total,
			"passed":   s.Passed,
			"failed":   s.Failed,
			"passRate": rate,
		})
	}

	// 基线失败项按严重级别
	baselineFailBySev := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var bslSevRows []struct {
		Severity string
		Count    int64
	}
	h.db.Model(&model.KubeBaseline{}).
		Select("severity, COUNT(*) as count").
		Where("result = ?", "fail").
		Group("severity").
		Scan(&bslSevRows)
	for _, r := range bslSevRows {
		if r.Severity != "" {
			baselineFailBySev[r.Severity] = r.Count
		}
	}

	// Top 失败基线项（按严重程度排）
	var failedItems []model.KubeBaseline
	h.db.Where("result = ?", "fail").
		Order("FIELD(severity, 'critical','high','medium','low'), id ASC").
		Limit(15).
		Find(&failedItems)
	topFailedBaselines := make([]gin.H, 0, len(failedItems))
	for _, it := range failedItems {
		topFailedBaselines = append(topFailedBaselines, gin.H{
			"checkId":     it.CheckID,
			"checkName":   it.CheckName,
			"category":    it.Category,
			"severity":    it.Severity,
			"clusterName": it.ClusterName,
			"description": it.Description,
			"remediation": it.Remediation,
		})
	}

	// === 7. 镜像扫描汇总 ===
	type imageSummary struct {
		TotalImages    int64
		ScannedImages  int64
		VulnerableImgs int64
		CriticalImgs   int64
		HighRiskImgs   int64
	}
	var img imageSummary
	h.db.Model(&model.ImageScan{}).Count(&img.TotalImages)
	h.db.Model(&model.ImageScan{}).Where("status = ?", "done").Count(&img.ScannedImages)
	h.db.Model(&model.ImageScan{}).Where("status = ? AND total_vulns > 0", "done").Count(&img.VulnerableImgs)
	h.db.Model(&model.ImageScan{}).Where("status = ? AND critical_cnt > 0", "done").Count(&img.CriticalImgs)
	h.db.Model(&model.ImageScan{}).Where("status = ? AND (critical_cnt > 0 OR high_cnt > 0)", "done").Count(&img.HighRiskImgs)

	// Top 10 高危镜像
	var riskyImages []model.ImageScan
	h.db.Where("status = ?", "done").
		Order("critical_cnt DESC, high_cnt DESC, total_vulns DESC").
		Limit(10).
		Find(&riskyImages)
	topRiskyImages := make([]gin.H, 0, len(riskyImages))
	for _, im := range riskyImages {
		if im.TotalVulns == 0 {
			continue
		}
		topRiskyImages = append(topRiskyImages, gin.H{
			"image":       im.Image,
			"os":          im.OS,
			"totalVulns":  im.TotalVulns,
			"criticalCnt": im.CriticalCnt,
			"highCnt":     im.HighCnt,
		})
	}

	// === 8. CVE 关联（按 CVE 出现次数 Top）===
	type cveRow struct {
		CveID    string
		Severity string
		Title    string
		Count    int64
	}
	var cveRows []cveRow
	h.db.Raw(`
		SELECT cve_id,
		       MAX(severity) AS severity,
		       MAX(title) AS title,
		       COUNT(*) AS count
		FROM image_vulnerabilities
		WHERE cve_id <> ''
		GROUP BY cve_id
		ORDER BY FIELD(MAX(severity), 'critical','high','medium','low'), count DESC
		LIMIT 10
	`).Scan(&cveRows)
	topCVEs := make([]gin.H, 0, len(cveRows))
	for _, r := range cveRows {
		topCVEs = append(topCVEs, gin.H{
			"cveId":    r.CveID,
			"severity": r.Severity,
			"title":    r.Title,
			"count":    r.Count,
		})
	}

	// === 9. 周期趋势 ===
	period := endTime.Sub(startTime)
	prevStart := startTime.Add(-period)
	prevEnd := startTime
	var prevTotal int64
	h.db.Model(&model.KubeAlarm{}).
		Where("created_at >= ? AND created_at <= ?", prevStart, prevEnd).
		Count(&prevTotal)
	growthPct := 0.0
	if prevTotal > 0 {
		growthPct = float64(aAgg.Total-prevTotal) / float64(prevTotal) * 100
	}

	// === 10. 自动建议 ===
	improvements := generateKubeImprovements(
		aAgg.Total, aAgg.Pending,
		severityDistribution["critical"], severityDistribution["high"],
		baselineFail, baselinePassRate,
		img.CriticalImgs,
	)

	// === 组装 ===
	reportID := fmt.Sprintf("kube-%d", time.Now().Unix())
	periodStr := fmt.Sprintf("%s ~ %s",
		startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))

	return gin.H{
		"meta": gin.H{
			"reportID":     reportID,
			"period":       periodStr,
			"generatedAt":  time.Now(),
			"clusterCount": clusterCount,
			"totalNodes":   totalNodes,
			"totalPods":    totalPods,
			"totalNs":      totalNs,
		},
		"summary": gin.H{
			"clusterCount":     clusterCount,
			"runningClusters":  runningCount,
			"offlineClusters":  offlineCount,
			"totalAlarms":      aAgg.Total,
			"pendingAlarms":    aAgg.Pending,
			"processedAlarms":  aAgg.Processed,
			"ignoredAlarms":    aAgg.Ignored,
			"totalWorkloads":   totalPods, // 用 Pod 数作为工作负载体量近似
			"baselinePassRate": baselinePassRate,
			"avgHealthScore":   avgHealthScore,
		},
		"clusters":              clusterRows,
		"severityDistribution":  severityDistribution,
		"alarmTypeDistribution": alarmTypeDistribution,
		"topAlarmTypes":         topAlarmTypes,
		"topWorkloads":          topWorkloads,
		"topNamespaces":         topNamespaces,
		"baseline": gin.H{
			"total":      baselineTotal,
			"passed":     baselinePass,
			"failed":     baselineFail,
			"warning":    baselineWarn,
			"passRate":   baselinePassRate,
			"bySeverity": baselineFailBySev,
			"byCategory": baselineByCategory,
			"topFailed":  topFailedBaselines,
		},
		"images": gin.H{
			"totalImages":    img.TotalImages,
			"scannedImages":  img.ScannedImages,
			"vulnerableImgs": img.VulnerableImgs,
			"criticalImgs":   img.CriticalImgs,
			"highRiskImgs":   img.HighRiskImgs,
			"topRisky":       topRiskyImages,
		},
		"topCVEs": topCVEs,
		"trend": gin.H{
			"prevPeriodAlarms": prevTotal,
			"growthPercent":    growthPct,
			"direction":        directionLabel(growthPct),
		},
		"improvements": improvements,
	}
}

// generateKubeImprovements 基于聚合数据自动产出 K8s 改进建议。
func generateKubeImprovements(
	totalAlarms, pendingAlarms int64,
	criticalAlarms, highAlarms int64,
	baselineFailed int64, baselinePassRate float64,
	criticalImgs int64,
) []string {
	out := make([]string, 0, 6)

	if criticalAlarms > 0 {
		out = append(out, fmt.Sprintf(
			"本周期产生 %d 条严重级别容器告警，建议立即排查是否存在容器逃逸、特权提升或恶意挖矿活动。",
			criticalAlarms))
	}
	if pendingAlarms > 50 {
		out = append(out, fmt.Sprintf(
			"待处理告警积压 %d 条（占比 %.1f%%），建议安全运营团队优先消化未处理告警。",
			pendingAlarms, float64(pendingAlarms)/float64(totalAlarms)*100))
	}
	if baselinePassRate < 70 && baselineFailed > 0 {
		out = append(out, fmt.Sprintf(
			"CIS 基线通过率仅 %.1f%%（%d 项不合规），建议优先修复 RBAC / NetworkPolicy / PodSecurity 高危项。",
			baselinePassRate, baselineFailed))
	}
	if criticalImgs > 0 {
		out = append(out, fmt.Sprintf(
			"镜像扫描发现 %d 个镜像含严重 CVE，建议升级基镜像或固定补丁版本后重建发布。",
			criticalImgs))
	}
	if highAlarms > 100 {
		out = append(out, "高危告警量较大，建议引入告警白名单/聚合，避免噪音淹没真实威胁。")
	}
	if len(out) == 0 {
		out = append(out, "K8s 容器安全态势平稳，建议保持基线巡检与镜像扫描节奏，关注新发布 CVE。")
	}
	return out
}
