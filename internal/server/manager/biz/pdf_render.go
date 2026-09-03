// Package biz - pdf_render.go 把报告数据装配成 HTML 字符串供 Gotenberg 渲染。
//
// 流程：BuildEDRReportData (gin.H) → flatten 到 strongly-typed view-model
//
//	→ 渲染 SVG 图表 → html/template 执行 → HTML 字符串。
//
// 模板嵌入：用 //go:embed 把 templates/*.tmpl 编入二进制，
// 部署只需 manager 单文件，无外部模板路径依赖。
package biz

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

//go:embed templates/*.tmpl templates/assets/*
var reportTemplates embed.FS

// logo data URI 缓存（一次编码全局复用，避免每次渲染重复 base64）
var (
	logoDataURI     string
	logoWideDataURI string
)

func init() {
	if b, err := reportTemplates.ReadFile("templates/assets/logo.png"); err == nil {
		logoDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(b)
	}
	if b, err := reportTemplates.ReadFile("templates/assets/logo-wide.png"); err == nil {
		logoWideDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(b)
	}
}

// ===================== view model =====================

// edrReportView EDR 报告模板视图模型。
type edrReportView struct {
	Meta         edrMeta
	Summary      edrSummary
	Derived      edrDerived
	Trend        edrTrend
	Conclusions  []string
	SeverityRows []sevRow
	TopRules     []topRuleRow
	TopHosts     []topHostRow
	TopStories   []topStoryRow
	Suppression  []supRow
	Raw          edrRawView
	AutoResp     edrAutoResp
	IOC          edrIOCView
	Rule         edrRuleView
	Improvements []string
	Charts       edrCharts
	Assets       edrAssets
}

type edrMeta struct {
	Title        string
	SiteName     string
	ReportID     string
	Period       string
	GeneratedAt  string
	OnlineHosts  int64
	TotalRules   int64
	EnabledRules int64
}
type edrSummary struct {
	TotalAlerts     int64
	ActiveAlerts    int64
	ResolvedAlerts  int64
	IgnoredAlerts   int64
	AffectedHosts   int64
	TotalStories    int64
	HighRiskStories int64
}
type edrDerived struct {
	RuleEnableRate      float64
	AlertConversionRate float64 // 告警 / 原始事件 × 100
}
type edrTrend struct {
	PrevTotal  int64
	AbsPct     float64
	Verb       string
	Descriptor string
	Arrow      string
}
type sevRow struct {
	Label, Color string
	Count        int64
	Pct          float64
}
type topRuleRow struct {
	Title          string
	Label          string // 中文严重程度
	Color, BgColor string
	Count          int64
}
type topHostRow struct {
	Hostname string
	Count    int64
}
type topStoryRow struct {
	Hostname, Phase string
	Label           string
	Color, BgColor  string
	EventCount      int
	AlertCount      int
	RiskScore       int
}
type supRow struct {
	Reason string
	Count  int64
}
type edrRawView struct {
	Available      bool
	TotalEvents    uint64
	TotalEventsFmt string
	UniqueHosts    uint64
	AvgPerHost     string
	TopHosts       []rawHostRow
	TopExe         []rawExeRow
}
type rawHostRow struct {
	Hostname string
	CountFmt string
}
type rawExeRow struct {
	Exe      string
	CountFmt string
}
type edrAutoResp struct {
	NetworkBlocks  int64
	HostIsolations int64
	ProcessKills   int64
	Total          int64
}
type edrIOCView struct {
	Snapshots     int64
	MemoryThreats int64
	TopTypes      []iocTypeRow
}
type iocTypeRow struct {
	Technique string
	Count     int64
}
type edrRuleView struct {
	EnabledRules int64
	HitRules     int64
	ZeroHitRules int64
	HitRate      float64
	TopZeroHit   []zeroHitRow
}
type zeroHitRow struct {
	ID       int64
	Name     string
	Category string
}
type edrCharts struct {
	SeverityPie    template.HTML
	TacticBar      template.HTML
	EventTypePie   template.HTML
	EventTrendLine template.HTML
}

type edrAssets struct {
	LogoURI     template.URL // 用 template.URL 让 html/template 信任 data: 协议，不被 sanitizer 替换为 #ZgotmplZ
	LogoWideURI template.URL
}

// ===================== severity / tactic / 颜色 =====================

var sevColor = map[string]string{
	"critical": "#dc2626",
	"high":     "#ea580c",
	"medium":   "#ca8a04",
	"low":      "#0891b2",
}
var sevLabel = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
}
var tacticLabel = map[string]string{
	"initial_access": "初始访问", "execution": "执行", "persistence": "持久化",
	"privilege_escalation": "权限提升", "defense_evasion": "防御规避",
	"credential_access": "凭据访问", "discovery": "发现", "lateral_movement": "横向移动",
	"collection": "收集", "exfiltration": "数据渗出", "command_and_control": "C2 通信",
	"impact": "影响", "other": "其他",
}

func sevColorBg(c string) string {
	if len(c) == 7 {
		return c + "1a" // 透明度 ~10%
	}
	return "#86909c1a"
}

// ===================== rendering =====================

// ReportRenderOptions 控制报告渲染细节。
type ReportRenderOptions struct {
	// LogoURI 优先使用此处提供的 data URI（通常来自 site_config.site_logo
	// 持久化字段）；为空时回退到内嵌品牌默认 logo。
	LogoURI string
	// SiteName 自定义站点名（来自 site_config.site_name），空则用默认。
	SiteName string
}

// systemConfigRow 仅用于解析 system_configs 表中的 site_config 行。
type systemConfigRow struct {
	Key   string `gorm:"column:key"`
	Value string `gorm:"column:value"`
}

func (systemConfigRow) TableName() string { return "system_configs" }

// LoadSiteBranding 从 system_configs.site_config 读取站点名 + logo，
// 把 logo URL（如 /uploads/site/logo_xxx.png）解析为本地文件路径并 base64 编码。
//
// uploadStaticPath: 部署中静态文件 HTTP 路径前缀，例如 "/uploads"
// uploadDir:        对应的文件系统目录，例如 "./uploads"
// httpPrefix:       manager 公网地址，例如 "http://127.0.0.1:8080"，
//
//	用于回退场景：site_logo 是绝对 URL（如 http://...）时直接 HTTP 拉取。
func LoadSiteBranding(db *gorm.DB, uploadStaticPath, uploadDir, httpPrefix string) ReportRenderOptions {
	opts := ReportRenderOptions{}
	if db == nil {
		return opts
	}
	var row systemConfigRow
	if err := db.Where("`key` = ? AND category = ?", "site_config", "site").Take(&row).Error; err != nil {
		return opts
	}
	var sc struct {
		SiteName string `json:"site_name"`
		SiteLogo string `json:"site_logo"`
	}
	if err := json.Unmarshal([]byte(row.Value), &sc); err != nil {
		return opts
	}
	opts.SiteName = sc.SiteName
	if sc.SiteLogo == "" {
		return opts
	}
	// 优先按本地文件解析（/uploads/xxx → <uploadDir>/xxx）
	if uploadStaticPath != "" && strings.HasPrefix(sc.SiteLogo, uploadStaticPath) {
		relPath := strings.TrimPrefix(sc.SiteLogo, uploadStaticPath)
		filePath := filepath.Join(uploadDir, relPath)
		if data, err := os.ReadFile(filePath); err == nil {
			opts.LogoURI = "data:" + detectImageMIME(filePath, data) + ";base64," + base64.StdEncoding.EncodeToString(data)
			return opts
		}
	}
	// 绝对 URL 回退 HTTP 拉取
	if strings.HasPrefix(sc.SiteLogo, "http://") || strings.HasPrefix(sc.SiteLogo, "https://") {
		if data, mime, ok := httpFetchImage(sc.SiteLogo); ok {
			opts.LogoURI = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
			return opts
		}
	}
	// 相对路径但前缀不匹配，尝试拼 httpPrefix
	if httpPrefix != "" && strings.HasPrefix(sc.SiteLogo, "/") {
		if data, mime, ok := httpFetchImage(httpPrefix + sc.SiteLogo); ok {
			opts.LogoURI = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
			return opts
		}
	}
	return opts
}

func detectImageMIME(path string, data []byte) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".webp":
		return "image/webp"
	}
	return http.DetectContentType(data)
}

func httpFetchImage(url string) ([]byte, string, bool) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, "", false
	}
	defer resp.Body.Close()
	data := make([]byte, 0, 64*1024)
	buf := make([]byte, 8*1024)
	for {
		n, e := resp.Body.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if e != nil {
			break
		}
		if len(data) > 5*1024*1024 { // logo 上限 5MB
			break
		}
	}
	mime := resp.Header.Get("Content-Type")
	if mime == "" {
		mime = http.DetectContentType(data)
	}
	return data, mime, true
}

// RenderEDRReportHTML 把 BuildEDRReportData 的输出装配成完整 HTML 字符串。
func RenderEDRReportHTML(data gin.H, opts ReportRenderOptions) (string, error) {
	v := flattenEDRData(data)
	v.Charts = buildEDRCharts(v, data)

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

	tmpl, err := template.New("edr_report.html.tmpl").
		Funcs(template.FuncMap{
			"add": func(a, b int) int { return a + b },
		}).
		ParseFS(reportTemplates, "templates/edr_report.html.tmpl")
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// flattenEDRData 把 gin.H 展平到 typed view model。
//
// 失败的字段都给安全默认值，不抛错——报告渲染必须容错，
// 即使部分数据缺失也要出 PDF。
func flattenEDRData(d gin.H) edrReportView {
	v := edrReportView{}
	v.Meta.Title = "EDR 检测专项报告"

	if meta, ok := d["meta"].(gin.H); ok {
		v.Meta.ReportID = getStr(meta, "reportID")
		v.Meta.Period = getStr(meta, "period")
		if ts, ok := meta["generatedAt"].(time.Time); ok {
			v.Meta.GeneratedAt = ts.Format("2006-01-02 15:04:05")
		} else {
			v.Meta.GeneratedAt = getStr(meta, "generatedAt")
		}
		v.Meta.OnlineHosts = getI64(meta, "onlineHosts")
		v.Meta.TotalRules = getI64(meta, "totalRules")
		v.Meta.EnabledRules = getI64(meta, "enabledRules")
	}
	if s, ok := d["summary"].(gin.H); ok {
		v.Summary.TotalAlerts = getI64(s, "totalAlerts")
		v.Summary.ActiveAlerts = getI64(s, "activeAlerts")
		v.Summary.ResolvedAlerts = getI64(s, "resolvedAlerts")
		v.Summary.IgnoredAlerts = getI64(s, "ignoredAlerts")
		v.Summary.AffectedHosts = getI64(s, "affectedHosts")
		v.Summary.TotalStories = getI64(s, "totalStories")
		v.Summary.HighRiskStories = getI64(s, "highRiskStories")
	}

	if v.Meta.TotalRules > 0 {
		v.Derived.RuleEnableRate = float64(v.Meta.EnabledRules) / float64(v.Meta.TotalRules) * 100
	}

	// trend
	if t, ok := d["trend"].(gin.H); ok {
		v.Trend.PrevTotal = getI64(t, "prevPeriodAlerts")
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

	// severity
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

	// top rules
	if rs, ok := d["topRules"].([]gin.H); ok {
		for _, r := range rs {
			sev := getStr(r, "severity")
			v.TopRules = append(v.TopRules, topRuleRow{
				Title:   getStr(r, "title"),
				Label:   sevLabel[sev],
				Color:   sevColor[sev],
				BgColor: sevColorBg(sevColor[sev]),
				Count:   getI64(r, "count"),
			})
		}
	}
	// top hosts
	if hs, ok := d["topHosts"].([]gin.H); ok {
		for _, h := range hs {
			v.TopHosts = append(v.TopHosts, topHostRow{
				Hostname: getStr(h, "hostname"),
				Count:    getI64(h, "count"),
			})
		}
	}
	// stories
	if ss, ok := d["topStories"].([]gin.H); ok {
		for _, s := range ss {
			sev := getStr(s, "severity")
			v.TopStories = append(v.TopStories, topStoryRow{
				Hostname:   getStr(s, "hostname"),
				Phase:      getStr(s, "phase"),
				Label:      sevLabel[sev],
				Color:      sevColor[sev],
				BgColor:    sevColorBg(sevColor[sev]),
				EventCount: int(getI64(s, "event_count")),
				AlertCount: int(getI64(s, "alert_count")),
				RiskScore:  int(getI64(s, "risk_score")),
			})
		}
	}
	// suppression
	if ss, ok := d["suppressionStats"].([]gin.H); ok {
		for _, s := range ss {
			v.Suppression = append(v.Suppression, supRow{
				Reason: getStr(s, "reason"),
				Count:  getI64(s, "count"),
			})
		}
	}

	// raw events (gin.H)
	if rs, ok := d["rawEventStats"].(gin.H); ok {
		v.Raw.Available, _ = rs["available"].(bool)
		v.Raw.TotalEvents = uint64(getI64(rs, "totalEvents"))
		v.Raw.TotalEventsFmt = formatInt(int(v.Raw.TotalEvents))
		v.Raw.UniqueHosts = uint64(getI64(rs, "uniqueHosts"))
		if v.Raw.UniqueHosts > 0 {
			v.Raw.AvgPerHost = formatInt(int(v.Raw.TotalEvents / v.Raw.UniqueHosts))
		} else {
			v.Raw.AvgPerHost = "0"
		}
		if tops, ok := rs["topHostsByEvent"].([]gin.H); ok {
			for _, h := range tops {
				v.Raw.TopHosts = append(v.Raw.TopHosts, rawHostRow{
					Hostname: getStr(h, "hostname"),
					CountFmt: formatInt(int(getI64(h, "count"))),
				})
			}
		}
		if exes, ok := rs["topExe"].([]gin.H); ok {
			for _, e := range exes {
				v.Raw.TopExe = append(v.Raw.TopExe, rawExeRow{
					Exe:      getStr(e, "exe"),
					CountFmt: formatInt(int(getI64(e, "count"))),
				})
			}
		}
		if v.Raw.TotalEvents > 0 {
			v.Derived.AlertConversionRate = float64(v.Summary.TotalAlerts) / float64(v.Raw.TotalEvents) * 100
		}
	}

	// auto response (gin.H)
	if ar, ok := d["autoResponseStats"].(gin.H); ok {
		v.AutoResp.NetworkBlocks = getI64(ar, "networkBlocks")
		v.AutoResp.HostIsolations = getI64(ar, "hostIsolations")
		v.AutoResp.ProcessKills = getI64(ar, "processKills")
		v.AutoResp.Total = getI64(ar, "total")
	}

	// ioc (gin.H)
	if i, ok := d["iocStats"].(gin.H); ok {
		v.IOC.Snapshots = getI64(i, "iocSnapshots")
		v.IOC.MemoryThreats = getI64(i, "memoryThreats")
		if tt, ok := i["topIOCTypes"].([]gin.H); ok {
			for _, t := range tt {
				v.IOC.TopTypes = append(v.IOC.TopTypes, iocTypeRow{
					Technique: getStr(t, "technique"),
					Count:     getI64(t, "count"),
				})
			}
		}
	}

	// rule efficacy (gin.H)
	if r, ok := d["ruleEfficacy"].(gin.H); ok {
		v.Rule.EnabledRules = getI64(r, "enabledRules")
		v.Rule.HitRules = getI64(r, "hitRules")
		v.Rule.ZeroHitRules = getI64(r, "zeroHitRules")
		v.Rule.HitRate = getF64(r, "hitRate")
		if zh, ok := r["topZeroHit"].([]gin.H); ok {
			for _, z := range zh {
				v.Rule.TopZeroHit = append(v.Rule.TopZeroHit, zeroHitRow{
					ID:       getI64(z, "id"),
					Name:     getStr(z, "name"),
					Category: getStr(z, "category"),
				})
			}
		}
	}

	if imp, ok := d["improvements"].([]string); ok {
		v.Improvements = imp
	}

	// 自动结论：基于已 flatten 的字段生成
	v.Conclusions = buildConclusions(v)

	return v
}

// buildConclusions 生成结论文案（执行摘要核心段）。
func buildConclusions(v edrReportView) []string {
	var out []string
	if len(v.TopRules) > 0 {
		out = append(out, fmt.Sprintf("触发量最高的检测规则为「%s」（%d 次），建议优先验证其规则准确性与处置 SLA。",
			v.TopRules[0].Title, v.TopRules[0].Count))
	}
	if len(v.TopHosts) > 0 {
		out = append(out, fmt.Sprintf("受影响最严重的主机为 %s（%d 条告警），建议下钻进程/网络上下文确认是否真实威胁。",
			v.TopHosts[0].Hostname, v.TopHosts[0].Count))
	}
	if v.Summary.HighRiskStories > 0 {
		out = append(out, fmt.Sprintf("本周期出现 %d 条高危攻击故事线（风险分 ≥ 70），需安全运营团队 24h 内闭环。",
			v.Summary.HighRiskStories))
	} else {
		out = append(out, "本周期未出现高危攻击故事线，整体处于稳态。")
	}
	if v.AutoResp.Total > 0 {
		out = append(out, fmt.Sprintf("自动响应共执行 %d 次（封禁 %d / 隔离 %d / 查杀 %d），平均响应时间 < 1s。",
			v.AutoResp.Total, v.AutoResp.NetworkBlocks, v.AutoResp.HostIsolations, v.AutoResp.ProcessKills))
	}
	if v.Rule.ZeroHitRules > 0 {
		out = append(out, fmt.Sprintf("存在 %d 条规则本周期零命中，参见规则有效性章节复核清单。", v.Rule.ZeroHitRules))
	}
	return out
}

// buildEDRCharts 生成所有 SVG 图表。
func buildEDRCharts(v edrReportView, d gin.H) edrCharts {
	c := edrCharts{}

	// 严重程度 pie
	pie := make([]PieSlice, 0, 4)
	for _, r := range v.SeverityRows {
		if r.Count > 0 {
			pie = append(pie, PieSlice{Label: r.Label, Value: float64(r.Count), Color: r.Color})
		}
	}
	c.SeverityPie = PieSVG(pie, 820, 340)

	// MITRE tactic bar
	if td, ok := d["tacticDistribution"].(map[string]int64); ok {
		items := make([]BarItem, 0, len(td))
		// 按值降序排
		type kv struct {
			K string
			V int64
		}
		kvs := make([]kv, 0, len(td))
		for k, vv := range td {
			if vv > 0 {
				kvs = append(kvs, kv{k, vv})
			}
		}
		// 简单冒泡 (项目少)
		for i := 0; i < len(kvs); i++ {
			for j := i + 1; j < len(kvs); j++ {
				if kvs[j].V > kvs[i].V {
					kvs[i], kvs[j] = kvs[j], kvs[i]
				}
			}
		}
		for _, p := range kvs {
			label := tacticLabel[p.K]
			if label == "" {
				label = p.K
			}
			items = append(items, BarItem{Label: label, Value: float64(p.V)})
		}
		c.TacticBar = BarSVG(items, 820, 340, "#722ed1")
	}

	// raw event type + trend (仅在 CH 可用时)
	if v.Raw.Available {
		if rs, ok := d["rawEventStats"].(gin.H); ok {
			palette := []string{"#3B82F6", "#22C55E", "#F59E0B", "#EF4444", "#722ed1", "#14b8a6", "#ec4899", "#6366f1"}
			if et, ok := rs["eventsByType"].([]gin.H); ok {
				pie2 := make([]PieSlice, 0, len(et))
				for i, e := range et {
					name := getStr(e, "event_type")
					cnt := float64(getI64(e, "count"))
					if cnt <= 0 || name == "" {
						continue
					}
					// 限 8 类 (与 palette 长度匹配); 多余合 Other 避免 legend 挤
					if len(pie2) >= 8 {
						break
					}
					pie2 = append(pie2, PieSlice{Label: name, Value: cnt, Color: palette[i%len(palette)]})
				}
				c.EventTypePie = PieSVG(pie2, 820, 360)
			}
			if eh, ok := rs["eventsByHour"].([]gin.H); ok {
				labels := make([]string, 0, len(eh))
				vals := make([]float64, 0, len(eh))
				for _, e := range eh {
					h := getStr(e, "hour")
					if len(h) > 5 {
						h = h[5:]
					}
					labels = append(labels, h)
					vals = append(vals, float64(getI64(e, "count")))
				}
				c.EventTrendLine = LineSVG(labels, vals, 820, 300, "#3b82f6")
			}
		}
	}

	return c
}

// ===================== gin.H helpers =====================

func getStr(m gin.H, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func getI64(m gin.H, k string) int64 {
	return toI64(m[k])
}

func getF64(m gin.H, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case uint64:
		return float64(v)
	}
	return 0
}

func toI64(v any) int64 {
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

func absF(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
