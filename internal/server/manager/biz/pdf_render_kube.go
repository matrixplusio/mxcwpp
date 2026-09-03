// Package biz - pdf_render_kube.go 把 K8s 容器安全报告数据装配成 HTML 字符串。
//
// 与 pdf_render.go (EDR) 同模式：
//
//	BuildKubeReportData (gin.H)
//	  → flattenKubeData (typed view-model)
//	  → buildKubeCharts (SVG)
//	  → html/template 执行 → HTML 字符串
//
// 复用：reportTemplates embed FS / logoDataURI / ReportRenderOptions /
//
//	LoadSiteBranding / PieSVG / BarSVG / sevColor / sevLabel /
//	gin.H helpers (getStr/getI64/getF64)。
package biz

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
)

// ===================== view model =====================

// kubeReportView K8s 容器安全报告模板视图模型。
type kubeReportView struct {
	Meta         kubeMeta
	Summary      kubeSummary
	Trend        kubeTrend
	Conclusions  []string
	SeverityRows []sevRow
	Clusters     []kubeClusterRow
	TopAlarmType []kubeAlarmTypeRow
	TopWorkloads []kubeWorkloadRow
	TopNamespace []kubeNsRow
	Baseline     kubeBaselineView
	Images       kubeImagesView
	TopCVEs      []kubeCVERow
	Improvements []string
	Charts       kubeCharts
	Assets       edrAssets // 复用 EDR 的 Assets 结构
}

type kubeMeta struct {
	Title        string
	SiteName     string
	ReportID     string
	Period       string
	GeneratedAt  string
	ClusterCount int64
	TotalNodes   int64
	TotalPods    int64
	TotalNs      int64
}

type kubeSummary struct {
	ClusterCount     int64
	RunningClusters  int64
	OfflineClusters  int64
	TotalAlarms      int64
	PendingAlarms    int64
	ProcessedAlarms  int64
	IgnoredAlarms    int64
	TotalWorkloads   int64
	BaselinePassRate float64
	AvgHealthScore   float64
}

type kubeTrend struct {
	PrevTotal  int64
	AbsPct     float64
	Verb       string
	Descriptor string
	Arrow      string
}

type kubeClusterRow struct {
	Name           string
	Version        string
	Status         string
	StatusLabel    string
	StatusColor    string
	NodeCount      int64
	PodCount       int64
	NamespaceCount int64
	HealthScore    int64
}

type kubeAlarmTypeRow struct {
	AlarmType string
	Label     string
	Count     int64
}

type kubeWorkloadRow struct {
	Target      string
	Namespace   string
	ClusterName string
	AlarmType   string
	AlarmLabel  string
	Severity    string
	SevLabel    string
	Color       string
	BgColor     string
	Count       int64
}

type kubeNsRow struct {
	Namespace   string
	ClusterName string
	Count       int64
}

type kubeBaselineView struct {
	Total      int64
	Passed     int64
	Failed     int64
	Warning    int64
	PassRate   float64
	BySeverity []sevRow
	ByCategory []kubeBaselineCatRow
	TopFailed  []kubeBaselineFailRow
}

type kubeBaselineCatRow struct {
	Category  string
	Label     string
	Total     int64
	Passed    int64
	Failed    int64
	PassRate  float64
	RateColor string // 绿/橙/红
}

type kubeBaselineFailRow struct {
	CheckID     string
	CheckName   string
	Category    string
	CategoryLbl string
	Severity    string
	SevLabel    string
	Color       string
	BgColor     string
	ClusterName string
	Description string
	Remediation string
}

type kubeImagesView struct {
	TotalImages    int64
	ScannedImages  int64
	VulnerableImgs int64
	CriticalImgs   int64
	HighRiskImgs   int64
	TopRisky       []kubeImageRow
}

type kubeImageRow struct {
	Image       string
	OS          string
	TotalVulns  int64
	CriticalCnt int64
	HighCnt     int64
}

type kubeCVERow struct {
	CveID    string
	Severity string
	SevLabel string
	Color    string
	BgColor  string
	Title    string
	Count    int64
}

type kubeCharts struct {
	SeverityPie    template.HTML
	AlarmTypeBar   template.HTML
	BaselineCatBar template.HTML
	BaselineSevPie template.HTML
	NamespaceBar   template.HTML
}

// ===================== label / color =====================

// kubeAlarmTypeLabel 把 KubeAlarmType 映射为中文标签。
var kubeAlarmTypeLabel = map[string]string{
	"container_escape":     "容器逃逸",
	"abnormal_process":     "异常进程",
	"abnormal_network":     "异常网络",
	"file_tamper":          "文件篡改",
	"privilege_escalation": "提权",
	"reverse_shell":        "反弹 Shell",
	"crypto_mining":        "挖矿活动",
}

// kubeBaselineCategoryLabel 把基线 category 映射为中文。
var kubeBaselineCategoryLabel = map[string]string{
	"rbac":               "RBAC 权限",
	"network":            "网络策略",
	"workload":           "工作负载",
	"pod":                "Pod 安全",
	"cluster":            "集群配置",
	"control_plane":      "控制面",
	"node":               "节点安全",
	"etcd":               "etcd 安全",
	"apiserver":          "API Server",
	"scheduler":          "调度器",
	"controller_manager": "控制器",
}

func kubeAlarmTypeLabelOf(t string) string {
	if v, ok := kubeAlarmTypeLabel[t]; ok {
		return v
	}
	return t
}

func kubeBaselineCategoryLabelOf(c string) string {
	if v, ok := kubeBaselineCategoryLabel[c]; ok {
		return v
	}
	return c
}

func kubeClusterStatusLabel(s string) (string, string) {
	switch s {
	case "running":
		return "运行中", "#22c55e"
	case "warning":
		return "告警", "#ea580c"
	case "offline":
		return "离线", "#dc2626"
	}
	return s, "#6b7280"
}

func baselineRateColor(rate float64) string {
	switch {
	case rate >= 90:
		return "#22c55e"
	case rate >= 70:
		return "#ca8a04"
	default:
		return "#dc2626"
	}
}

// ===================== rendering =====================

// RenderKubeReportHTML 把 BuildKubeReportData 的输出装配成完整 HTML 字符串。
func RenderKubeReportHTML(data gin.H, opts ReportRenderOptions) (string, error) {
	v := flattenKubeData(data)
	v.Charts = buildKubeCharts(v)

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

	tmpl, err := template.New("kube_report.html.tmpl").
		Funcs(template.FuncMap{
			"add": func(a, b int) int { return a + b },
		}).
		ParseFS(reportTemplates, "templates/kube_report.html.tmpl")
	if err != nil {
		return "", fmt.Errorf("parse kube template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("execute kube template: %w", err)
	}
	return buf.String(), nil
}

// flattenKubeData 把 gin.H 展平到 typed view model。
//
// 容错：任何字段缺失都给安全默认值，不抛错——报告必须出 PDF。
func flattenKubeData(d gin.H) kubeReportView {
	v := kubeReportView{}
	v.Meta.Title = "K8s 容器安全专项报告"

	if meta, ok := d["meta"].(gin.H); ok {
		v.Meta.ReportID = getStr(meta, "reportID")
		v.Meta.Period = getStr(meta, "period")
		if ts, ok := meta["generatedAt"].(time.Time); ok {
			v.Meta.GeneratedAt = ts.Format("2006-01-02 15:04:05")
		} else {
			v.Meta.GeneratedAt = getStr(meta, "generatedAt")
		}
		v.Meta.ClusterCount = getI64(meta, "clusterCount")
		v.Meta.TotalNodes = getI64(meta, "totalNodes")
		v.Meta.TotalPods = getI64(meta, "totalPods")
		v.Meta.TotalNs = getI64(meta, "totalNs")
	}

	if s, ok := d["summary"].(gin.H); ok {
		v.Summary.ClusterCount = getI64(s, "clusterCount")
		v.Summary.RunningClusters = getI64(s, "runningClusters")
		v.Summary.OfflineClusters = getI64(s, "offlineClusters")
		v.Summary.TotalAlarms = getI64(s, "totalAlarms")
		v.Summary.PendingAlarms = getI64(s, "pendingAlarms")
		v.Summary.ProcessedAlarms = getI64(s, "processedAlarms")
		v.Summary.IgnoredAlarms = getI64(s, "ignoredAlarms")
		v.Summary.TotalWorkloads = getI64(s, "totalWorkloads")
		v.Summary.BaselinePassRate = getF64(s, "baselinePassRate")
		v.Summary.AvgHealthScore = getF64(s, "avgHealthScore")
	}

	// trend
	if t, ok := d["trend"].(gin.H); ok {
		v.Trend.PrevTotal = getI64(t, "prevPeriodAlarms")
		growth := getF64(t, "growthPercent")
		dir := getStr(t, "direction")
		v.Trend.AbsPct = absF(growth)
		switch dir {
		case "up":
			v.Trend.Verb = "上升"
			v.Trend.Arrow = "↑"
			if v.Trend.AbsPct > 50 {
				v.Trend.Descriptor = "显著恶化"
			} else {
				v.Trend.Descriptor = "小幅上升"
			}
		case "down":
			v.Trend.Verb = "下降"
			v.Trend.Arrow = "↓"
			if v.Trend.AbsPct > 50 {
				v.Trend.Descriptor = "显著改善"
			} else {
				v.Trend.Descriptor = "小幅改善"
			}
		default:
			v.Trend.Verb = "保持稳定"
			v.Trend.Arrow = "→"
			v.Trend.Descriptor = "平稳"
		}
	}

	// severity distribution
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

	// clusters
	if cs, ok := d["clusters"].([]gin.H); ok {
		for _, c := range cs {
			st := getStr(c, "status")
			lbl, col := kubeClusterStatusLabel(st)
			v.Clusters = append(v.Clusters, kubeClusterRow{
				Name:           getStr(c, "name"),
				Version:        getStr(c, "version"),
				Status:         st,
				StatusLabel:    lbl,
				StatusColor:    col,
				NodeCount:      getI64(c, "nodeCount"),
				PodCount:       getI64(c, "podCount"),
				NamespaceCount: getI64(c, "namespaceCount"),
				HealthScore:    getI64(c, "healthScore"),
			})
		}
	}

	// top alarm types
	if ts, ok := d["topAlarmTypes"].([]gin.H); ok {
		for _, t := range ts {
			at := getStr(t, "alarmType")
			v.TopAlarmType = append(v.TopAlarmType, kubeAlarmTypeRow{
				AlarmType: at,
				Label:     kubeAlarmTypeLabelOf(at),
				Count:     getI64(t, "count"),
			})
		}
	}

	// top workloads
	if ws, ok := d["topWorkloads"].([]gin.H); ok {
		for _, w := range ws {
			sev := getStr(w, "severity")
			at := getStr(w, "alarmType")
			v.TopWorkloads = append(v.TopWorkloads, kubeWorkloadRow{
				Target:      getStr(w, "target"),
				Namespace:   getStr(w, "namespace"),
				ClusterName: getStr(w, "clusterName"),
				AlarmType:   at,
				AlarmLabel:  kubeAlarmTypeLabelOf(at),
				Severity:    sev,
				SevLabel:    sevLabel[sev],
				Color:       sevColor[sev],
				BgColor:     sevColorBg(sevColor[sev]),
				Count:       getI64(w, "count"),
			})
		}
	}

	// top namespaces
	if ns, ok := d["topNamespaces"].([]gin.H); ok {
		for _, n := range ns {
			v.TopNamespace = append(v.TopNamespace, kubeNsRow{
				Namespace:   getStr(n, "namespace"),
				ClusterName: getStr(n, "clusterName"),
				Count:       getI64(n, "count"),
			})
		}
	}

	// baseline
	if b, ok := d["baseline"].(gin.H); ok {
		v.Baseline.Total = getI64(b, "total")
		v.Baseline.Passed = getI64(b, "passed")
		v.Baseline.Failed = getI64(b, "failed")
		v.Baseline.Warning = getI64(b, "warning")
		v.Baseline.PassRate = getF64(b, "passRate")

		// 失败分级
		if dist, ok := b["bySeverity"].(map[string]int64); ok {
			total := dist["critical"] + dist["high"] + dist["medium"] + dist["low"]
			for _, k := range []string{"critical", "high", "medium", "low"} {
				c := dist[k]
				pct := 0.0
				if total > 0 {
					pct = float64(c) / float64(total) * 100
				}
				v.Baseline.BySeverity = append(v.Baseline.BySeverity, sevRow{
					Label: sevLabel[k], Color: sevColor[k], Count: c, Pct: pct,
				})
			}
		}

		// 分类通过率
		if cs, ok := b["byCategory"].([]gin.H); ok {
			for _, c := range cs {
				cat := getStr(c, "category")
				rate := getF64(c, "passRate")
				v.Baseline.ByCategory = append(v.Baseline.ByCategory, kubeBaselineCatRow{
					Category:  cat,
					Label:     kubeBaselineCategoryLabelOf(cat),
					Total:     getI64(c, "total"),
					Passed:    getI64(c, "passed"),
					Failed:    getI64(c, "failed"),
					PassRate:  rate,
					RateColor: baselineRateColor(rate),
				})
			}
			// 按通过率升序（最差排前）
			sort.SliceStable(v.Baseline.ByCategory, func(i, j int) bool {
				return v.Baseline.ByCategory[i].PassRate < v.Baseline.ByCategory[j].PassRate
			})
		}

		// Top 失败项
		if fs, ok := b["topFailed"].([]gin.H); ok {
			for _, f := range fs {
				sev := getStr(f, "severity")
				cat := getStr(f, "category")
				v.Baseline.TopFailed = append(v.Baseline.TopFailed, kubeBaselineFailRow{
					CheckID:     getStr(f, "checkId"),
					CheckName:   getStr(f, "checkName"),
					Category:    cat,
					CategoryLbl: kubeBaselineCategoryLabelOf(cat),
					Severity:    sev,
					SevLabel:    sevLabel[sev],
					Color:       sevColor[sev],
					BgColor:     sevColorBg(sevColor[sev]),
					ClusterName: getStr(f, "clusterName"),
					Description: getStr(f, "description"),
					Remediation: getStr(f, "remediation"),
				})
			}
		}
	}

	// images
	if i, ok := d["images"].(gin.H); ok {
		v.Images.TotalImages = getI64(i, "totalImages")
		v.Images.ScannedImages = getI64(i, "scannedImages")
		v.Images.VulnerableImgs = getI64(i, "vulnerableImgs")
		v.Images.CriticalImgs = getI64(i, "criticalImgs")
		v.Images.HighRiskImgs = getI64(i, "highRiskImgs")
		if rs, ok := i["topRisky"].([]gin.H); ok {
			for _, r := range rs {
				v.Images.TopRisky = append(v.Images.TopRisky, kubeImageRow{
					Image:       getStr(r, "image"),
					OS:          getStr(r, "os"),
					TotalVulns:  getI64(r, "totalVulns"),
					CriticalCnt: getI64(r, "criticalCnt"),
					HighCnt:     getI64(r, "highCnt"),
				})
			}
		}
	}

	// CVEs
	if cs, ok := d["topCVEs"].([]gin.H); ok {
		for _, c := range cs {
			sev := getStr(c, "severity")
			v.TopCVEs = append(v.TopCVEs, kubeCVERow{
				CveID:    getStr(c, "cveId"),
				Severity: sev,
				SevLabel: sevLabel[sev],
				Color:    sevColor[sev],
				BgColor:  sevColorBg(sevColor[sev]),
				Title:    getStr(c, "title"),
				Count:    getI64(c, "count"),
			})
		}
	}

	if imp, ok := d["improvements"].([]string); ok {
		v.Improvements = imp
	}

	v.Conclusions = buildKubeConclusions(v)
	return v
}

// buildKubeConclusions 生成 K8s 报告执行摘要核心结论。
func buildKubeConclusions(v kubeReportView) []string {
	var out []string
	if v.Summary.ClusterCount > 0 {
		out = append(out, fmt.Sprintf(
			"当前纳管 %d 个集群（运行 %d / 离线 %d），共 %d 个节点 · %d 个 Pod · %d 个 Namespace。",
			v.Summary.ClusterCount, v.Summary.RunningClusters, v.Summary.OfflineClusters,
			v.Meta.TotalNodes, v.Meta.TotalPods, v.Meta.TotalNs))
	}
	if v.Summary.TotalAlarms > 0 {
		out = append(out, fmt.Sprintf(
			"本周期共产生 %d 条容器安全告警（待处理 %d / 已处理 %d / 已忽略 %d）。",
			v.Summary.TotalAlarms, v.Summary.PendingAlarms,
			v.Summary.ProcessedAlarms, v.Summary.IgnoredAlarms))
	}
	if len(v.SeverityRows) > 0 && v.SeverityRows[0].Count > 0 {
		out = append(out, fmt.Sprintf(
			"严重告警 %d 条，需安全运营团队 24h 内闭环。",
			v.SeverityRows[0].Count))
	}
	if v.Baseline.Total > 0 {
		out = append(out, fmt.Sprintf(
			"CIS 基线检查 %d 项，通过率 %.1f%%（失败 %d / 警告 %d）。",
			v.Baseline.Total, v.Baseline.PassRate, v.Baseline.Failed, v.Baseline.Warning))
	}
	if v.Images.CriticalImgs > 0 {
		out = append(out, fmt.Sprintf(
			"镜像扫描覆盖 %d 个镜像，其中 %d 个含严重 CVE，建议立即升级。",
			v.Images.ScannedImages, v.Images.CriticalImgs))
	}
	if len(out) == 0 {
		out = append(out, "本周期 K8s 容器安全态势平稳，未发现高危事件。")
	}
	return out
}

// buildKubeCharts 生成所有 SVG 图表。
func buildKubeCharts(v kubeReportView) kubeCharts {
	c := kubeCharts{}

	// 告警严重程度 pie
	pie := make([]PieSlice, 0, 4)
	for _, r := range v.SeverityRows {
		if r.Count > 0 {
			pie = append(pie, PieSlice{Label: r.Label, Value: float64(r.Count), Color: r.Color})
		}
	}
	c.SeverityPie = PieSVG(pie, 820, 340)

	// 告警类型 Top Bar
	if len(v.TopAlarmType) > 0 {
		items := make([]BarItem, 0, len(v.TopAlarmType))
		for i, t := range v.TopAlarmType {
			if i >= 8 || t.Count <= 0 {
				break
			}
			items = append(items, BarItem{Label: t.Label, Value: float64(t.Count)})
		}
		c.AlarmTypeBar = BarSVG(items, 820, 340, "#722ed1")
	}

	// 基线分类通过率 Bar (按 PassRate 升序, 最差排前)
	if len(v.Baseline.ByCategory) > 0 {
		items := make([]BarItem, 0, len(v.Baseline.ByCategory))
		for i, b := range v.Baseline.ByCategory {
			if i >= 10 {
				break
			}
			items = append(items, BarItem{Label: b.Label, Value: b.PassRate})
		}
		c.BaselineCatBar = BarSVG(items, 820, 320, "#2563eb")
	}

	// 基线失败按严重 pie
	bslPie := make([]PieSlice, 0, 4)
	for _, r := range v.Baseline.BySeverity {
		if r.Count > 0 {
			bslPie = append(bslPie, PieSlice{Label: r.Label, Value: float64(r.Count), Color: r.Color})
		}
	}
	c.BaselineSevPie = PieSVG(bslPie, 820, 320)

	// 命名空间 Top Bar
	if len(v.TopNamespace) > 0 {
		items := make([]BarItem, 0, len(v.TopNamespace))
		for i, n := range v.TopNamespace {
			if i >= 8 {
				break
			}
			items = append(items, BarItem{Label: n.Namespace, Value: float64(n.Count)})
		}
		c.NamespaceBar = BarSVG(items, 820, 320, "#ea580c")
	}

	return c
}
