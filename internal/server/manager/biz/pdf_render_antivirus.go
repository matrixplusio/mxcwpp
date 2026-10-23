// Package biz - pdf_render_antivirus.go 病毒查杀 (Antivirus) 报告 HTML 渲染。
//
// 与 EDR (pdf_render.go) 完全独立的视图模型 + flatten + chart 装配，
// 但共享底层 helpers (getStr/getI64/getF64/sevColor/sevLabel/formatInt)
// 以及 reportTemplates embed.FS（//go:embed templates/*.tmpl 已涵盖新模板）。
//
// 模板路径：templates/antivirus_report.html.tmpl
package biz

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/gin-gonic/gin"
)

// ===================== view model =====================

// antivirusReportView 病毒查杀报告模板视图模型。
type antivirusReportView struct {
	Meta             avMeta
	Summary          avSummary
	Derived          avDerived
	Trend            avTrend
	Tasks            avTaskStats
	Engine           avEngine
	Conclusions      []string
	SeverityRows     []sevRow // 复用 pdf_render.go 的 sevRow
	ThreatTypeRows   []avTypeRow
	TopThreats       []avTopThreat
	TopAffectedHosts []avAffectedHost
	RecentTasks      []avRecentTask
	Improvements     []string
	Charts           avCharts
	Assets           edrAssets // 复用 EDR 的 logo 资源结构
}

type avMeta struct {
	Title       string
	SiteName    string
	ReportID    string
	Period      string
	GeneratedAt string
	OnlineHosts int64
}

type avSummary struct {
	TotalTasks         int64
	TotalThreats       int64
	DetectedThreats    int64 // action=detected（待处置）
	QuarantinedThreats int64
	DeletedThreats     int64
	IgnoredThreats     int64
	PendingThreats     int64 // = DetectedThreats（语义别名，模板用）
	AffectedHosts      int64
	ScannedHosts       int64
}

type avDerived struct {
	ScanCoverageRate float64 // 受扫描主机 / 在线主机 × 100
	InfectionRate    float64 // 受感染主机 / 在线主机 × 100
	ClearRate        float64 // (隔离 + 清除) / 检出总数 × 100
}

type avTrend struct {
	PrevTotal  int64
	AbsPct     float64
	Verb       string
	Descriptor string
	Arrow      string
}

type avTaskStats struct {
	Completed  int64
	Running    int64
	Failed     int64
	Cancelled  int64
	Pending    int64
	QuickScan  int64
	FullScan   int64
	CustomScan int64
}

type avEngine struct {
	ClamAVVersion string
	SigDBVersion  string
	LastUpdateAt  time.Time
	LastUpdateFmt string
	LastStatus    string
	SyncCount     int64
	FailedSync    int64
	RecentSyncs   []avSyncRow
}

type avSyncRow struct {
	StartedAt string
	Version   string
	Status    string
	Duration  int
	FileSize  string // human readable
}

type avTypeRow struct {
	Label string
	Color string
	Count int64
	Pct   float64
}

type avTopThreat struct {
	ThreatName     string
	Label          string
	Color, BgColor string
	Count          int64
	AffectedHosts  int64
}

type avAffectedHost struct {
	Hostname    string
	IP          string
	ThreatCount int64
}

type avRecentTask struct {
	Name        string
	ScanType    string
	Status      string
	TotalHosts  int64
	ThreatCount int64
	FinishedAt  string
}

type avCharts struct {
	SeverityPie   template.HTML
	ThreatTypePie template.HTML
	TopHostBar    template.HTML
}

// ===================== threat-type 字典 =====================

// avThreatTypeLabel ClamAV 威胁类型 → 中文标签。
var avThreatTypeLabel = map[string]string{
	"virus":      "病毒",
	"trojan":     "木马",
	"worm":       "蠕虫",
	"ransomware": "勒索软件",
	"rootkit":    "Rootkit",
	"miner":      "挖矿程序",
	"backdoor":   "后门",
	"adware":     "广告软件",
	"spyware":    "间谍软件",
	"pup":        "可疑程序",
	"other":      "其他",
}

// avThreatTypePalette 与 EDR event-type pie 一致的色板，保持视觉风格统一。
var avThreatTypePalette = []string{
	"#dc2626", // virus 红
	"#ea580c", // trojan 橙
	"#f59e0b", // worm 琥珀
	"#7c3aed", // ransomware 紫
	"#0891b2", // rootkit 青
	"#16a34a", // miner 绿
	"#3b82f6", // backdoor 蓝
	"#ec4899", // adware 粉
	"#6366f1", // spyware 靛
	"#14b8a6", // pup 翡翠
	"#6b7280", // other 灰
}

// ===================== rendering =====================

// RenderAntivirusReportHTML 把 BuildAntivirusReportData 的输出装配成完整 HTML 字符串。
//
// 渲染流程与 RenderEDRReportHTML 对齐：
//  1. flatten gin.H → 强类型 view-model
//  2. 装配 SVG 图表（严重程度 pie / 威胁类型 pie / Top 主机 bar）
//  3. 注入 logo + 站点名
//  4. html/template 执行
func RenderAntivirusReportHTML(data gin.H, opts ReportRenderOptions) (string, error) {
	v := flattenAntivirusData(data)
	v.Charts = buildAntivirusCharts(v)

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

	tmpl, err := template.New("antivirus_report.html.tmpl").
		Funcs(template.FuncMap{
			"add": func(a, b int) int { return a + b },
		}).
		ParseFS(reportTemplates, "templates/antivirus_report.html.tmpl")
	if err != nil {
		return "", fmt.Errorf("parse antivirus template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("execute antivirus template: %w", err)
	}
	return buf.String(), nil
}

// flattenAntivirusData 把 gin.H 展平到强类型 view model（容错：缺字段不报错，仅给默认值）。
func flattenAntivirusData(d gin.H) antivirusReportView {
	v := antivirusReportView{}
	v.Meta.Title = "病毒查杀检测专项报告"

	// === meta ===
	if meta, ok := d["meta"].(gin.H); ok {
		v.Meta.ReportID = getStr(meta, "reportID")
		v.Meta.Period = getStr(meta, "period")
		if ts, ok := meta["generatedAt"].(time.Time); ok {
			v.Meta.GeneratedAt = ts.Format("2006-01-02 15:04:05")
		} else {
			v.Meta.GeneratedAt = getStr(meta, "generatedAt")
		}
		v.Meta.OnlineHosts = getI64(meta, "onlineHosts")
	}

	// === summary ===
	if s, ok := d["summary"].(gin.H); ok {
		v.Summary.TotalTasks = getI64(s, "totalTasks")
		v.Summary.TotalThreats = getI64(s, "totalThreats")
		v.Summary.DetectedThreats = getI64(s, "detectedThreats")
		v.Summary.QuarantinedThreats = getI64(s, "quarantinedThreats")
		v.Summary.DeletedThreats = getI64(s, "deletedThreats")
		v.Summary.IgnoredThreats = getI64(s, "ignoredThreats")
		v.Summary.AffectedHosts = getI64(s, "affectedHosts")
		v.Summary.ScannedHosts = getI64(s, "scannedHosts")
		// PendingThreats 是模板别名 — detected = action 为 detected（未处置）的条数
		v.Summary.PendingThreats = v.Summary.DetectedThreats
	}

	// === derived ===
	if v.Meta.OnlineHosts > 0 {
		v.Derived.ScanCoverageRate = float64(v.Summary.ScannedHosts) / float64(v.Meta.OnlineHosts) * 100
		v.Derived.InfectionRate = float64(v.Summary.AffectedHosts) / float64(v.Meta.OnlineHosts) * 100
	}
	if v.Summary.TotalThreats > 0 {
		v.Derived.ClearRate = float64(v.Summary.QuarantinedThreats+v.Summary.DeletedThreats) /
			float64(v.Summary.TotalThreats) * 100
	}

	// === trend ===
	if t, ok := d["trend"].(gin.H); ok {
		v.Trend.PrevTotal = getI64(t, "prevPeriodThreats")
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

	// === task stats ===
	if ts, ok := d["taskStats"].(gin.H); ok {
		v.Tasks.Completed = getI64(ts, "completed")
		v.Tasks.Running = getI64(ts, "running")
		v.Tasks.Failed = getI64(ts, "failed")
		v.Tasks.Cancelled = getI64(ts, "cancelled")
		v.Tasks.Pending = getI64(ts, "pending")
		v.Tasks.QuickScan = getI64(ts, "quickScan")
		v.Tasks.FullScan = getI64(ts, "fullScan")
		v.Tasks.CustomScan = getI64(ts, "customScan")
	}

	// === severity ===
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

	// === threat type ===
	if dist, ok := d["threatTypeDistribution"].(map[string]int64); ok {
		// 按 count 降序整理（map 顺序不定，需排序）
		type kv struct {
			K string
			V int64
		}
		kvs := make([]kv, 0, len(dist))
		var total int64
		for k, c := range dist {
			if c > 0 {
				kvs = append(kvs, kv{k, c})
				total += c
			}
		}
		// 冒泡排序（项目少，简洁优先）
		for i := 0; i < len(kvs); i++ {
			for j := i + 1; j < len(kvs); j++ {
				if kvs[j].V > kvs[i].V {
					kvs[i], kvs[j] = kvs[j], kvs[i]
				}
			}
		}
		for i, p := range kvs {
			label := avThreatTypeLabel[p.K]
			if label == "" {
				label = p.K
			}
			color := avThreatTypePalette[i%len(avThreatTypePalette)]
			pct := 0.0
			if total > 0 {
				pct = float64(p.V) / float64(total) * 100
			}
			v.ThreatTypeRows = append(v.ThreatTypeRows, avTypeRow{
				Label: label, Color: color, Count: p.V, Pct: pct,
			})
		}
	}

	// === top threats ===
	if ts, ok := d["topThreats"].([]gin.H); ok {
		for _, t := range ts {
			sev := getStr(t, "severity")
			v.TopThreats = append(v.TopThreats, avTopThreat{
				ThreatName:    getStr(t, "threatName"),
				Label:         sevLabel[sev],
				Color:         sevColor[sev],
				BgColor:       sevColorBg(sevColor[sev]),
				Count:         getI64(t, "count"),
				AffectedHosts: getI64(t, "affectedHosts"),
			})
		}
	}

	// === top affected hosts ===
	if hs, ok := d["topAffectedHosts"].([]gin.H); ok {
		for _, h := range hs {
			v.TopAffectedHosts = append(v.TopAffectedHosts, avAffectedHost{
				Hostname:    getStr(h, "hostname"),
				IP:          getStr(h, "ip"),
				ThreatCount: getI64(h, "threatCount"),
			})
		}
	}

	// === recent tasks ===
	if rs, ok := d["recentTasks"].([]gin.H); ok {
		for _, r := range rs {
			finishedAt := ""
			if ts, ok := r["finishedAt"].(time.Time); ok {
				finishedAt = ts.Format("2006-01-02 15:04")
			} else {
				finishedAt = getStr(r, "finishedAt")
			}
			v.RecentTasks = append(v.RecentTasks, avRecentTask{
				Name:        getStr(r, "name"),
				ScanType:    getStr(r, "scanType"),
				Status:      getStr(r, "status"),
				TotalHosts:  getI64(r, "totalHosts"),
				ThreatCount: getI64(r, "threatCount"),
				FinishedAt:  finishedAt,
			})
		}
	}

	// === engine ===
	if e, ok := d["engine"].(gin.H); ok {
		v.Engine.ClamAVVersion = strOr(getStr(e, "clamAVVersion"), "未知")
		v.Engine.SigDBVersion = strOr(getStr(e, "sigDBVersion"), "未知")
		if ts, ok := e["lastUpdateAt"].(time.Time); ok && !ts.IsZero() {
			v.Engine.LastUpdateAt = ts
			v.Engine.LastUpdateFmt = ts.Format("2006-01-02 15:04")
		} else {
			v.Engine.LastUpdateFmt = "暂无记录"
		}
		v.Engine.LastStatus = strOr(getStr(e, "lastStatus"), "未知")
		v.Engine.SyncCount = getI64(e, "syncCount")
		v.Engine.FailedSync = getI64(e, "failedSync")
		if syncs, ok := e["recentSyncs"].([]gin.H); ok {
			for _, s := range syncs {
				startedAt := ""
				if ts, ok := s["startedAt"].(time.Time); ok {
					startedAt = ts.Format("2006-01-02 15:04")
				} else {
					startedAt = getStr(s, "startedAt")
				}
				v.Engine.RecentSyncs = append(v.Engine.RecentSyncs, avSyncRow{
					StartedAt: startedAt,
					Version:   getStr(s, "version"),
					Status:    getStr(s, "status"),
					Duration:  int(getI64(s, "duration")),
					FileSize:  humanFileSize(getI64(s, "fileSize")),
				})
			}
		}
	} else {
		v.Engine.ClamAVVersion = "未知"
		v.Engine.SigDBVersion = "未知"
		v.Engine.LastUpdateFmt = "暂无记录"
		v.Engine.LastStatus = "未知"
	}

	// === improvements ===
	if imp, ok := d["improvements"].([]string); ok {
		v.Improvements = imp
	}

	// === 自动结论 ===
	v.Conclusions = buildAVConclusions(v)

	return v
}

// buildAVConclusions 生成执行摘要核心结论。
func buildAVConclusions(v antivirusReportView) []string {
	var out []string
	if v.Summary.TotalThreats == 0 {
		out = append(out, "本周期未检出任何威胁，环境清洁度良好。")
	} else if len(v.TopThreats) > 0 {
		out = append(out, fmt.Sprintf("检出频次最高的威胁为「%s」（%d 次），影响 %d 台主机，建议优先核查传播路径。",
			v.TopThreats[0].ThreatName, v.TopThreats[0].Count, v.TopThreats[0].AffectedHosts))
	}
	if len(v.TopAffectedHosts) > 0 {
		out = append(out, fmt.Sprintf("受感染最严重的主机为 %s（%d 条威胁），建议下钻文件路径与时间线确认入口。",
			v.TopAffectedHosts[0].Hostname, v.TopAffectedHosts[0].ThreatCount))
	}
	if v.Summary.PendingThreats > 0 {
		out = append(out, fmt.Sprintf("尚有 %d 条威胁处于待处置状态，建议安全运营团队 24h 内完成隔离或清除决策。",
			v.Summary.PendingThreats))
	}
	if v.Derived.ClearRate >= 90 {
		out = append(out, fmt.Sprintf("威胁清除率达 %.1f%%，处置闭环效率良好。", v.Derived.ClearRate))
	} else if v.Summary.TotalThreats > 0 && v.Derived.ClearRate < 50 {
		out = append(out, fmt.Sprintf("威胁清除率仅 %.1f%%，建议复盘处置流程是否存在卡点。", v.Derived.ClearRate))
	}
	if v.Engine.FailedSync > 0 {
		out = append(out, fmt.Sprintf("病毒库同步失败 %d 次，可能影响最新签名覆盖，建议检查 freshclam 网络与权限。",
			v.Engine.FailedSync))
	}
	return out
}

// buildAntivirusCharts 渲染所有 SVG 图表。
func buildAntivirusCharts(v antivirusReportView) avCharts {
	c := avCharts{}

	// 严重程度 pie
	pie := make([]PieSlice, 0, 4)
	for _, r := range v.SeverityRows {
		if r.Count > 0 {
			pie = append(pie, PieSlice{Label: r.Label, Value: float64(r.Count), Color: r.Color})
		}
	}
	c.SeverityPie = PieSVG(pie, 820, 340)

	// 威胁类型 pie（最多 8 个，超出归并 Other 由 view 决定 — 这里直接取已排序前 8）
	tpie := make([]PieSlice, 0, 8)
	for i, r := range v.ThreatTypeRows {
		if i >= 8 || r.Count <= 0 {
			break
		}
		tpie = append(tpie, PieSlice{Label: r.Label, Value: float64(r.Count), Color: r.Color})
	}
	c.ThreatTypePie = PieSVG(tpie, 820, 360)

	// Top 受感染主机 bar
	items := make([]BarItem, 0, len(v.TopAffectedHosts))
	for _, h := range v.TopAffectedHosts {
		name := h.Hostname
		if name == "" {
			name = h.IP
		}
		items = append(items, BarItem{Label: name, Value: float64(h.ThreatCount)})
	}
	c.TopHostBar = BarSVG(items, 820, 340, "#dc2626")

	return c
}

// ===================== helpers =====================

// strOr 第一个非空字符串。
func strOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// humanFileSize 把字节数渲染为 KB/MB/GB。
func humanFileSize(n int64) string {
	if n <= 0 {
		return "-"
	}
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
