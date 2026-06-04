// Package biz - pdf_render_task.go 任务报告 (按 task_id 维度) HTML 渲染。
//
// 流程：BuildTaskReportData (gin.H) → flatten 到 strongly-typed view-model
//
//	→ 渲染 SVG 图表 → html/template 执行 → HTML 字符串。
//
// 与 EDR 报告 (pdf_render.go) 区别：
//   - 维度是单个 task_id，而非周期 (period)
//   - cover 上显示「任务编号 + 任务类型 + 执行时间」而非「报告周期」
//   - 章节 9 章：执行摘要、任务基本信息、主机覆盖、执行结果、失败原因、
//     资产清单、关键问题、改进建议、附录
//
// 模板复用 EDR 同一 CSS，确保品牌风格一致。
package biz

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"

	"github.com/gin-gonic/gin"
)

// ===================== view model =====================

// taskReportView 任务报告模板视图模型。
type taskReportView struct {
	Meta                taskMeta
	Summary             taskSummary
	Conclusions         []string
	SeverityRows        []sevRow
	CategoryRows        []taskCategoryRow
	HostRows            []taskHostRow
	CriticalRules       []taskRuleRow
	CriticalSuggestions []taskSuggestionRow
	RetryHosts          []taskRetryHostRow
	Improvements        []string
	Charts              taskCharts
	Assets              edrAssets
}

type taskMeta struct {
	Title          string
	SiteName       string
	ReportID       string
	GeneratedAt    string
	TaskID         string
	TaskIDShort    string
	TaskName       string
	TaskType       string // 中文标签：基线扫描 / FIM 检测 / 漏洞扫描 / 病毒查杀
	TaskTypeRaw    string // 原始 type 字段值
	PolicyName     string
	StatusLabel    string
	ScheduledAt    string
	ExecutedAt     string
	CompletedAt    string
	Duration       string
	TimeoutMinutes int
	TargetType     string
	TargetDesc     string
	FailedReason   string
}

type taskSummary struct {
	HostCount           int64
	RuleCount           int64
	TotalChecks         int64
	PassedChecks        int64
	FailedChecks        int64
	WarningChecks       int64
	NAChecks            int64
	PassRate            float64
	FailureRate         float64 // 失败主机 / 覆盖主机
	DispatchedHostCount int64
	CompletedHostCount  int64
	SuccessHosts        int64
	FailedHosts         int64
	WarningHosts        int64
	PendingHosts        int64
}

type taskCategoryRow struct {
	Key   string
	Label string
	Count int64
	Pct   float64
}

type taskHostRow struct {
	Hostname     string
	IP           string
	OSFamily     string
	StatusLabel  string
	StatusColor  string
	StatusBg     string
	PassedCount  int64
	FailedCount  int64
	WarningCount int64
	Score        float64
}

type taskRuleRow struct {
	Title         string
	Category      string
	Label         string
	Color         string
	BgColor       string
	AffectedCount int64
}

type taskSuggestionRow struct {
	Title      string
	Suggestion string
}

type taskRetryHostRow struct {
	Hostname string
	IP       string
	Reason   string
}

type taskCharts struct {
	StatusPie   template.HTML
	CategoryPie template.HTML
	CategoryBar template.HTML
}

// ===================== 类型映射 =====================

// taskTypeLabel 把 ScanTask.Type 映射为中文展示标签。
// 当前仅 baseline_scan 落库，预留 fim/vuln/antivirus 以便后续扩展。
var taskTypeLabel = map[string]string{
	"baseline_scan": "基线合规扫描",
	"fim_scan":      "文件完整性检测",
	"vuln_scan":     "漏洞扫描",
	"antivirus":     "病毒查杀",
}

var taskStatusLabel = map[string]string{
	"created":   "已创建",
	"pending":   "待执行",
	"running":   "执行中",
	"completed": "已完成",
	"failed":    "已失败",
	"cancelled": "已取消",
}

var targetTypeLabel = map[string]string{
	"all":       "全部主机",
	"host_ids":  "指定主机列表",
	"os_family": "按 OS 类型",
}

// 主机状态颜色映射
var hostStatusStyle = map[string][3]string{
	// label, color, bg
	"pass":    {"通过", "#16a34a", "#16a34a1a"},
	"warning": {"预警", "#ca8a04", "#ca8a041a"},
	"fail":    {"失败", "#dc2626", "#dc26261a"},
	"pending": {"未响应", "#6b7280", "#6b72801a"},
}

// ===================== rendering =====================

// RenderTaskReportHTML 把 BuildTaskReportData 的输出装配成完整 HTML 字符串。
func RenderTaskReportHTML(data gin.H, opts ReportRenderOptions) (string, error) {
	v := flattenTaskData(data)
	v.Charts = buildTaskCharts(v)

	logoURI := opts.LogoURI
	if logoURI == "" {
		logoURI = logoDataURI
	}
	siteName := opts.SiteName
	if siteName == "" {
		siteName = "矩阵云安全平台"
	}
	v.Assets = edrAssets{LogoURI: template.URL(logoURI), LogoWideURI: template.URL(logoWideDataURI)}
	v.Meta.SiteName = siteName

	tmpl, err := template.New("task_report.html.tmpl").
		Funcs(template.FuncMap{
			"add": func(a, b int) int { return a + b },
		}).
		ParseFS(reportTemplates, "templates/task_report.html.tmpl")
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// flattenTaskData 把 gin.H 展平到 typed view model。
//
// 所有字段都给安全默认值，不抛错——报告渲染必须容错，
// 即使部分数据缺失也要出 PDF。
func flattenTaskData(d gin.H) taskReportView {
	v := taskReportView{}
	v.Meta.Title = "任务执行报告"

	// === Meta ===
	if meta, ok := d["meta"].(gin.H); ok {
		v.Meta.ReportID = getStr(meta, "reportID")
		v.Meta.GeneratedAt = getStr(meta, "generatedAt")
		v.Meta.TaskID = getStr(meta, "taskID")
		v.Meta.TaskIDShort = shortID(v.Meta.TaskID)
		v.Meta.TaskName = getStr(meta, "taskName")
		v.Meta.TaskTypeRaw = getStr(meta, "taskType")
		v.Meta.TaskType = labelOf(taskTypeLabel, v.Meta.TaskTypeRaw, v.Meta.TaskTypeRaw)
		v.Meta.PolicyName = getStr(meta, "policyName")
		statusRaw := getStr(meta, "status")
		v.Meta.StatusLabel = labelOf(taskStatusLabel, statusRaw, statusRaw)
		v.Meta.ScheduledAt = getStr(meta, "scheduledAt")
		v.Meta.ExecutedAt = getStr(meta, "executedAt")
		v.Meta.CompletedAt = getStr(meta, "completedAt")
		v.Meta.Duration = getStr(meta, "duration")
		v.Meta.TimeoutMinutes = int(getI64(meta, "timeoutMinutes"))
		v.Meta.TargetType = labelOf(targetTypeLabel, getStr(meta, "targetType"), getStr(meta, "targetType"))
		v.Meta.TargetDesc = getStr(meta, "targetDesc")
		v.Meta.FailedReason = getStr(meta, "failedReason")
	}

	// === Summary ===
	if s, ok := d["summary"].(gin.H); ok {
		v.Summary.HostCount = getI64(s, "hostCount")
		v.Summary.RuleCount = getI64(s, "ruleCount")
		v.Summary.TotalChecks = getI64(s, "totalChecks")
		v.Summary.PassedChecks = getI64(s, "passedChecks")
		v.Summary.FailedChecks = getI64(s, "failedChecks")
		v.Summary.WarningChecks = getI64(s, "warningChecks")
		v.Summary.NAChecks = getI64(s, "naChecks")
		v.Summary.PassRate = getF64(s, "passRate")
		v.Summary.DispatchedHostCount = getI64(s, "dispatchedHostCount")
		v.Summary.CompletedHostCount = getI64(s, "completedHostCount")
		v.Summary.SuccessHosts = getI64(s, "successHosts")
		v.Summary.FailedHosts = getI64(s, "failedHosts")
		v.Summary.WarningHosts = getI64(s, "warningHosts")
		v.Summary.PendingHosts = getI64(s, "pendingHosts")
	}
	if v.Summary.HostCount > 0 {
		v.Summary.FailureRate = float64(v.Summary.FailedHosts) / float64(v.Summary.HostCount) * 100
	}

	// === Severity ===
	if dist, ok := d["severityDistribution"].(map[string]int64); ok {
		total := dist["critical"] + dist["high"] + dist["medium"] + dist["low"]
		for _, k := range []string{"critical", "high", "medium", "low"} {
			c := dist[k]
			pct := 0.0
			if total > 0 {
				pct = float64(c) / float64(total) * 100
			}
			v.SeverityRows = append(v.SeverityRows, sevRow{
				Label: sevLabel[k], Color: sevColor[k], Count: c, Pct: pct,
			})
		}
	}

	// === Category ===
	if cs, ok := d["categoryDistribution"].([]gin.H); ok {
		total := int64(0)
		for _, c := range cs {
			total += getI64(c, "count")
		}
		for _, c := range cs {
			cnt := getI64(c, "count")
			pct := 0.0
			if total > 0 {
				pct = float64(cnt) / float64(total) * 100
			}
			key := getStr(c, "category")
			label := getStr(c, "label")
			if label == "" {
				label = key
			}
			v.CategoryRows = append(v.CategoryRows, taskCategoryRow{
				Key: key, Label: label, Count: cnt, Pct: pct,
			})
		}
	}

	// === Host rows ===
	if hs, ok := d["hostDetails"].([]gin.H); ok {
		for _, h := range hs {
			status := getStr(h, "status")
			st, ok := hostStatusStyle[status]
			if !ok {
				st = hostStatusStyle["pending"]
			}
			v.HostRows = append(v.HostRows, taskHostRow{
				Hostname:     getStr(h, "hostname"),
				IP:           getStr(h, "ip"),
				OSFamily:     getStr(h, "osFamily"),
				StatusLabel:  st[0],
				StatusColor:  st[1],
				StatusBg:     st[2],
				PassedCount:  getI64(h, "passedCount"),
				FailedCount:  getI64(h, "failedCount"),
				WarningCount: getI64(h, "warningCount"),
				Score:        getF64(h, "score"),
			})
		}
	}

	// === Critical rules (severity = critical/high) ===
	if rs, ok := d["criticalRules"].([]gin.H); ok {
		for _, r := range rs {
			sev := getStr(r, "severity")
			v.CriticalRules = append(v.CriticalRules, taskRuleRow{
				Title:         getStr(r, "title"),
				Category:      getStr(r, "category"),
				Label:         sevLabel[sev],
				Color:         sevColor[sev],
				BgColor:       sevColorBg(sevColor[sev]),
				AffectedCount: getI64(r, "affectedCount"),
			})
		}
	}

	// === Top suggestions (前 5 条高危规则的修复建议) ===
	if rs, ok := d["criticalSuggestions"].([]gin.H); ok {
		for _, r := range rs {
			v.CriticalSuggestions = append(v.CriticalSuggestions, taskSuggestionRow{
				Title:      getStr(r, "title"),
				Suggestion: getStr(r, "suggestion"),
			})
		}
	}

	// === Retry hosts ===
	if rs, ok := d["retryHosts"].([]gin.H); ok {
		for _, r := range rs {
			v.RetryHosts = append(v.RetryHosts, taskRetryHostRow{
				Hostname: getStr(r, "hostname"),
				IP:       getStr(r, "ip"),
				Reason:   getStr(r, "reason"),
			})
		}
	}

	// === Improvements ===
	if imp, ok := d["improvements"].([]string); ok {
		v.Improvements = imp
	}

	// === 结论 ===
	v.Conclusions = buildTaskConclusions(v)
	return v
}

// buildTaskConclusions 基于已 flatten 的字段生成执行摘要结论。
func buildTaskConclusions(v taskReportView) []string {
	out := make([]string, 0, 5)
	switch {
	case v.Summary.FailedChecks == 0 && v.Summary.WarningChecks == 0:
		out = append(out, "本次任务全部检查项均通过，未发现不合规配置，主机当前合规状态良好。")
	case v.Summary.PassRate >= 90:
		out = append(out, fmt.Sprintf("本次任务整体合规率 %.1f%%，处于「良好」区间，存在 %d 项需关注的失败配置。", v.Summary.PassRate, v.Summary.FailedChecks))
	case v.Summary.PassRate >= 60:
		out = append(out, fmt.Sprintf("本次任务整体合规率 %.1f%%，处于「一般」区间，发现 %d 项不合规配置，建议尽快整改。", v.Summary.PassRate, v.Summary.FailedChecks))
	default:
		out = append(out, fmt.Sprintf("本次任务整体合规率仅 %.1f%%，处于「较差」区间，发现 %d 项不合规配置，需立即启动整改。", v.Summary.PassRate, v.Summary.FailedChecks))
	}

	// severity 提示
	var critical, high int64
	for _, s := range v.SeverityRows {
		switch s.Label {
		case "严重":
			critical = s.Count
		case "高危":
			high = s.Count
		}
	}
	if critical > 0 {
		out = append(out, fmt.Sprintf("发现 %d 项严重级别失败配置，可能导致系统被完全控制，请立即处理。", critical))
	}
	if high > 0 {
		out = append(out, fmt.Sprintf("发现 %d 项高危级别失败配置，建议 24 小时内完成整改。", high))
	}

	if v.Summary.PendingHosts > 0 {
		out = append(out, fmt.Sprintf("%d 台主机下发后未回传结果，可能离线或执行超时，建议核查后重新下发任务。", v.Summary.PendingHosts))
	}
	if v.Summary.WarningChecks > 0 {
		out = append(out, fmt.Sprintf("存在 %d 条检查执行异常（命令失败/权限不足等），不计入合规率，但需排查。", v.Summary.WarningChecks))
	}
	return out
}

// buildTaskCharts 生成所有 SVG 图表。
func buildTaskCharts(v taskReportView) taskCharts {
	c := taskCharts{}

	// 4-1 状态分布 pie
	statusSlices := make([]PieSlice, 0, 4)
	if v.Summary.PassedChecks > 0 {
		statusSlices = append(statusSlices, PieSlice{Label: "通过", Value: float64(v.Summary.PassedChecks), Color: "#22c55e"})
	}
	if v.Summary.FailedChecks > 0 {
		statusSlices = append(statusSlices, PieSlice{Label: "失败", Value: float64(v.Summary.FailedChecks), Color: "#dc2626"})
	}
	if v.Summary.WarningChecks > 0 {
		statusSlices = append(statusSlices, PieSlice{Label: "异常", Value: float64(v.Summary.WarningChecks), Color: "#ca8a04"})
	}
	if v.Summary.NAChecks > 0 {
		statusSlices = append(statusSlices, PieSlice{Label: "不适用", Value: float64(v.Summary.NAChecks), Color: "#9ca3af"})
	}
	if len(statusSlices) > 0 {
		c.StatusPie = PieSVG(statusSlices, 820, 340)
	}

	// 5-1 类别 pie + 5-2 bar
	if len(v.CategoryRows) > 0 {
		// 排序（视图模型层做安全排序，避免依赖调用方）
		rows := make([]taskCategoryRow, len(v.CategoryRows))
		copy(rows, v.CategoryRows)
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })

		palette := []string{"#3B82F6", "#22C55E", "#F59E0B", "#EF4444", "#722ed1", "#14b8a6", "#ec4899", "#6366f1"}
		pieSlices := make([]PieSlice, 0, len(rows))
		barItems := make([]BarItem, 0, len(rows))
		for i, r := range rows {
			if r.Count <= 0 {
				continue
			}
			if i < 8 {
				pieSlices = append(pieSlices, PieSlice{
					Label: r.Label, Value: float64(r.Count), Color: palette[i%len(palette)],
				})
			}
			barItems = append(barItems, BarItem{Label: r.Label, Value: float64(r.Count)})
		}
		if len(pieSlices) > 0 {
			c.CategoryPie = PieSVG(pieSlices, 820, 360)
		}
		if len(barItems) > 0 {
			c.CategoryBar = BarSVG(barItems, 820, 340, "#722ed1")
		}
	}

	return c
}

// ===================== 辅助函数 =====================

// shortID 取 task_id 前 8 位用于封面展示。
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// labelOf 安全查表，未命中返回 fallback。
func labelOf(m map[string]string, key, fallback string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	if fallback == "" {
		return key
	}
	return fallback
}
