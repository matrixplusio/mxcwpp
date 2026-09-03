// Package biz - pdf_render_vuln.go 把漏洞管理报告数据装配成 HTML 字符串供 Gotenberg 渲染。
//
// 与 EDR 渲染同模式：BuildVulnReportData (gin.H) → flatten 到 typed view-model
// → 渲染 SVG 图表 → html/template 执行 → HTML 字符串。
//
// helpers (getStr/getI64/getF64/formatInt/absF/sevLabel/sevColor/sevColorBg
// 以及 LoadSiteBranding / logoDataURI / reportTemplates) 复用 pdf_render.go。
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

// vulnReportView 漏洞报告模板视图模型。
type vulnReportView struct {
	Meta         vulnMeta
	Summary      vulnSummaryView
	Derived      vulnDerived
	Posture      vulnPosture
	Conclusions  []string
	SeverityRows []sevRow // 复用 EDR 的 sevRow
	TopVulns     []topVulnRow
	TopHosts     []topVulnHostRow
	Fix          vulnFixView
	SLARows      []slaRow
	Sources      []vulnSourceRow
	SourceDist   []sourceDistRow
	Improvements []string
	Charts       vulnCharts
	Assets       edrAssets // 复用 EDR 的 assets struct
}

type vulnMeta struct {
	Title          string
	SiteName       string
	ReportID       string
	Period         string
	GeneratedAt    string
	OnlineHosts    int64
	TotalSources   int64
	EnabledSources int64
}

type vulnSummaryView struct {
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

type vulnDerived struct {
	FixRate          float64 // FixedVulns / TotalVulns
	HostCoverage     float64 // AffectedHosts / OnlineHosts
	SourceEnableRate float64 // EnabledSources / TotalSources
}

type vulnPosture struct {
	Descriptor string // "良好" / "需关注" / "严峻"
}

type topVulnRow struct {
	CveID          string
	Label          string
	Color, BgColor string
	CvssScore      float64
	Component      string
	AffectedHosts  int64
	Tags           string // "EXPLOIT / KEV" 等组合
}

type topVulnHostRow struct {
	Hostname      string
	IP            string
	VulnCount     int64
	CriticalCount int64
	HighCount     int64
}

type vulnFixView struct {
	TotalTasks         int64
	SuccessTasks       int64
	FailedTasks        int64
	RunningTasks       int64
	PendingVerifyTasks int64
	SuccessRate        float64
}

type slaRow struct {
	Label  string
	Color  string
	Window string // "24h" / "72h"
	Met    int64
	Total  int64
	Rate   float64
}

type vulnSourceRow struct {
	DisplayName string
	Region      string
	Category    string
	Enabled     bool
	LastSyncAt  string
	LastCount   int64
}

type sourceDistRow struct {
	Label string
	Count int64
	Pct   float64
}

type vulnCharts struct {
	SeverityPie  template.HTML
	ComponentBar template.HTML
	FixStatusBar template.HTML
}

// vuln source label 映射（用于 source 分布章节）
var vulnSourceLabel = map[string]string{
	"nvd":    "NVD",
	"osv":    "OSV.dev",
	"cnnvd":  "CNNVD",
	"cnvd":   "CNVD",
	"rhsa":   "RHSA (Red Hat)",
	"usn":    "USN (Ubuntu)",
	"alpine": "Alpine SecDB",
	"debian": "Debian Security Tracker",
}

// vulnSourceRegionLabel / vulnSourceCategoryLabel 中文翻译
var vulnSourceRegionLabel = map[string]string{
	"cn":     "国内",
	"global": "全球",
}

var vulnSourceCategoryLabel = map[string]string{
	"cn_official":  "国内官方",
	"os_advisory":  "OS 厂商",
	"cve_metadata": "CVE 元数据",
	"exploit":      "剥削情报",
}

// ===================== rendering =====================

// RenderVulnReportHTML 把 BuildVulnReportData 的输出装配成完整 HTML 字符串。
func RenderVulnReportHTML(data gin.H, opts ReportRenderOptions) (string, error) {
	v := flattenVulnData(data)
	v.Charts = buildVulnCharts(v, data)

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

	tmpl, err := template.New("vuln_report.html.tmpl").
		Funcs(template.FuncMap{
			"add": func(a, b int) int { return a + b },
		}).
		ParseFS(reportTemplates, "templates/vuln_report.html.tmpl")
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// flattenVulnData 把 gin.H 展平到 typed view model。
// 失败的字段给安全默认值，不抛错——报告必须容错。
func flattenVulnData(d gin.H) vulnReportView {
	v := vulnReportView{}
	v.Meta.Title = "漏洞管理与修复专项报告"

	if meta, ok := d["meta"].(gin.H); ok {
		v.Meta.ReportID = getStr(meta, "reportID")
		v.Meta.Period = getStr(meta, "period")
		if ts, ok := meta["generatedAt"].(time.Time); ok {
			v.Meta.GeneratedAt = ts.Format("2006-01-02 15:04:05")
		} else {
			v.Meta.GeneratedAt = getStr(meta, "generatedAt")
		}
		v.Meta.OnlineHosts = getI64(meta, "onlineHosts")
		v.Meta.TotalSources = getI64(meta, "totalSources")
		v.Meta.EnabledSources = getI64(meta, "enabledSources")
	}

	if s, ok := d["summary"].(gin.H); ok {
		v.Summary.TotalVulns = getI64(s, "totalVulns")
		v.Summary.UnpatchedVulns = getI64(s, "unpatchedVulns")
		v.Summary.FixedVulns = getI64(s, "fixedVulns")
		v.Summary.IgnoredVulns = getI64(s, "ignoredVulns")
		v.Summary.AffectedHosts = getI64(s, "affectedHosts")
		v.Summary.CriticalVulns = getI64(s, "criticalVulns")
		v.Summary.HighVulns = getI64(s, "highVulns")
		v.Summary.MediumVulns = getI64(s, "mediumVulns")
		v.Summary.LowVulns = getI64(s, "lowVulns")
		v.Summary.WithExploit = getI64(s, "withExploit")
		v.Summary.InKEV = getI64(s, "inKev")
	}

	// derived
	if v.Summary.TotalVulns > 0 {
		v.Derived.FixRate = float64(v.Summary.FixedVulns) / float64(v.Summary.TotalVulns) * 100
	}
	if v.Meta.OnlineHosts > 0 {
		v.Derived.HostCoverage = float64(v.Summary.AffectedHosts) / float64(v.Meta.OnlineHosts) * 100
	}
	if v.Meta.TotalSources > 0 {
		v.Derived.SourceEnableRate = float64(v.Meta.EnabledSources) / float64(v.Meta.TotalSources) * 100
	}

	// posture descriptor
	v.Posture.Descriptor = vulnPostureDescriptor(v.Summary, v.Derived)

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

	// top vulns
	if rs, ok := d["topVulns"].([]gin.H); ok {
		for _, r := range rs {
			sev := getStr(r, "severity")
			tags := ""
			if b, _ := r["hasExploit"].(bool); b {
				tags = "EXPLOIT"
			}
			if b, _ := r["inKev"].(bool); b {
				if tags != "" {
					tags += " / "
				}
				tags += "KEV"
			}
			v.TopVulns = append(v.TopVulns, topVulnRow{
				CveID:         getStr(r, "cveId"),
				Label:         sevLabel[sev],
				Color:         sevColor[sev],
				BgColor:       sevColorBg(sevColor[sev]),
				CvssScore:     getF64(r, "cvssScore"),
				Component:     getStr(r, "component"),
				AffectedHosts: getI64(r, "affectedHosts"),
				Tags:          tags,
			})
		}
	}

	// top hosts
	if hs, ok := d["topAffectedHosts"].([]gin.H); ok {
		for _, h := range hs {
			v.TopHosts = append(v.TopHosts, topVulnHostRow{
				Hostname:      getStr(h, "hostname"),
				IP:            getStr(h, "ip"),
				VulnCount:     getI64(h, "vulnCount"),
				CriticalCount: getI64(h, "criticalCount"),
				HighCount:     getI64(h, "highCount"),
			})
		}
	}

	// fix progress
	if f, ok := d["fixProgress"].(gin.H); ok {
		v.Fix.TotalTasks = getI64(f, "totalTasks")
		v.Fix.SuccessTasks = getI64(f, "successTasks")
		v.Fix.FailedTasks = getI64(f, "failedTasks")
		v.Fix.RunningTasks = getI64(f, "runningTasks")
		v.Fix.PendingVerifyTasks = getI64(f, "pendingVerifyTasks")
		if v.Fix.TotalTasks > 0 {
			v.Fix.SuccessRate = float64(v.Fix.SuccessTasks) / float64(v.Fix.TotalTasks) * 100
		}
	}

	// SLA
	if rs, ok := d["slaStats"].([]gin.H); ok {
		for _, r := range rs {
			sev := getStr(r, "severity")
			row := slaRow{
				Label:  sevLabel[sev],
				Color:  sevColor[sev],
				Window: getStr(r, "window"),
				Met:    getI64(r, "met"),
				Total:  getI64(r, "total"),
			}
			if row.Total > 0 {
				row.Rate = float64(row.Met) / float64(row.Total) * 100
			}
			v.SLARows = append(v.SLARows, row)
		}
	}

	// sources
	if rs, ok := d["sources"].([]gin.H); ok {
		for _, r := range rs {
			region := getStr(r, "region")
			if l, ok := vulnSourceRegionLabel[region]; ok {
				region = l
			}
			cat := getStr(r, "category")
			if l, ok := vulnSourceCategoryLabel[cat]; ok {
				cat = l
			}
			enabled, _ := r["enabled"].(bool)
			v.Sources = append(v.Sources, vulnSourceRow{
				DisplayName: getStr(r, "displayName"),
				Region:      region,
				Category:    cat,
				Enabled:     enabled,
				LastSyncAt:  getStr(r, "lastSyncAt"),
				LastCount:   getI64(r, "lastCount"),
			})
		}
	}

	// source distribution
	if rs, ok := d["sourceDistribution"].([]gin.H); ok {
		var total int64
		for _, r := range rs {
			total += getI64(r, "count")
		}
		for _, r := range rs {
			c := getI64(r, "count")
			pct := 0.0
			if total > 0 {
				pct = float64(c) / float64(total) * 100
			}
			label := getStr(r, "source")
			if l, ok := vulnSourceLabel[label]; ok {
				label = l
			}
			if label == "" {
				label = "未标记"
			}
			v.SourceDist = append(v.SourceDist, sourceDistRow{
				Label: label, Count: c, Pct: pct,
			})
		}
	}

	if imp, ok := d["improvements"].([]string); ok {
		v.Improvements = imp
	}

	v.Conclusions = buildVulnConclusions(v)

	return v
}

// vulnPostureDescriptor 根据 summary 给出整体态势描述。
func vulnPostureDescriptor(s vulnSummaryView, d vulnDerived) string {
	switch {
	case s.CriticalVulns > 10 || s.InKEV > 0:
		return "严峻"
	case s.CriticalVulns > 0 || s.HighVulns > 20:
		return "需重点关注"
	case d.FixRate < 50 && s.UnpatchedVulns > 50:
		return "整改滞后"
	case d.FixRate >= 80:
		return "良好"
	default:
		return "稳定"
	}
}

// buildVulnConclusions 生成执行摘要的核心结论。
func buildVulnConclusions(v vulnReportView) []string {
	out := make([]string, 0, 6)
	if v.Summary.CriticalVulns > 0 {
		out = append(out, fmt.Sprintf("本周期披露 %d 个严重 CVE，建议安全运营团队 24h 内启动应急修复流程。",
			v.Summary.CriticalVulns))
	}
	if v.Summary.InKEV > 0 {
		out = append(out, fmt.Sprintf("命中 CISA KEV 名录 %d 个，存在已知活跃剥削，应作为最高优先级处置。",
			v.Summary.InKEV))
	}
	if v.Summary.WithExploit > 0 {
		out = append(out, fmt.Sprintf("%d 个 CVE 已公开剥削代码，攻击门槛低，需在 SLA 前完成修复。",
			v.Summary.WithExploit))
	}
	if v.Derived.FixRate > 0 {
		out = append(out, fmt.Sprintf("CVE 修复率 %.1f%%（已修复 %d / 总计 %d），%s。",
			v.Derived.FixRate, v.Summary.FixedVulns, v.Summary.TotalVulns, fixRateComment(v.Derived.FixRate)))
	}
	if len(v.TopHosts) > 0 {
		top := v.TopHosts[0]
		out = append(out, fmt.Sprintf("受影响最严重的主机为 %s（%s），承载 %d 个 CVE，建议优先纳入修复计划。",
			top.Hostname, top.IP, top.VulnCount))
	}
	if v.Fix.TotalTasks > 0 && v.Fix.SuccessRate < 50 {
		out = append(out, fmt.Sprintf("修复任务成功率仅 %.1f%%（%d / %d），建议复盘失败原因并调整 pre-check 策略。",
			v.Fix.SuccessRate, v.Fix.SuccessTasks, v.Fix.TotalTasks))
	}
	if len(out) == 0 {
		out = append(out, "本周期未发现严重漏洞，修复进度处于稳态。")
	}
	return out
}

func fixRateComment(r float64) string {
	switch {
	case r >= 80:
		return "整改闭环表现良好"
	case r >= 50:
		return "整改进度可接受，仍有改进空间"
	default:
		return "修复滞后，建议加大整改投入"
	}
}

// buildVulnCharts 生成 SVG 图表。
func buildVulnCharts(v vulnReportView, d gin.H) vulnCharts {
	c := vulnCharts{}

	// 严重程度 pie
	pie := make([]PieSlice, 0, 4)
	for _, r := range v.SeverityRows {
		if r.Count > 0 {
			pie = append(pie, PieSlice{Label: r.Label, Value: float64(r.Count), Color: r.Color})
		}
	}
	c.SeverityPie = PieSVG(pie, 820, 340)

	// 组件 Top 10 bar
	if cd, ok := d["componentDistribution"].([]gin.H); ok {
		items := make([]BarItem, 0, len(cd))
		// 已经 ORDER BY count DESC，取前 10
		for i, r := range cd {
			if i >= 10 {
				break
			}
			name := getStr(r, "component")
			cnt := getI64(r, "count")
			if name == "" || cnt <= 0 {
				continue
			}
			items = append(items, BarItem{Label: name, Value: float64(cnt)})
		}
		if len(items) > 0 {
			c.ComponentBar = BarSVG(items, 820, 340, "#722ed1")
		}
	}

	// 修复状态 bar (fixed / unpatched / ignored)
	fixItems := []BarItem{
		{Label: "已修复", Value: float64(v.Summary.FixedVulns)},
		{Label: "待修复", Value: float64(v.Summary.UnpatchedVulns)},
		{Label: "已忽略", Value: float64(v.Summary.IgnoredVulns)},
	}
	// 保证至少有一项 > 0 才画
	if v.Summary.FixedVulns+v.Summary.UnpatchedVulns+v.Summary.IgnoredVulns > 0 {
		// 按值降序更好看
		sort.Slice(fixItems, func(i, j int) bool { return fixItems[i].Value > fixItems[j].Value })
		c.FixStatusBar = BarSVG(fixItems, 820, 300, "#2563eb")
	}

	return c
}
