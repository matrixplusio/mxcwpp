// Package biz - svg_chart.go 服务端 SVG 图表渲染。
//
// 设计目标：
//   - 完全静态 SVG，PDF 中保持矢量、可缩放、可搜索
//   - 不依赖任何前端 JS 渲染，避免 Chromium 等待 canvas 渲染
//   - 输出 template.HTML 类型，可在 html/template 中直接嵌入
//
// 支持图表：
//   - PieSVG  饼图 (严重程度 / 类型分布)
//   - BarSVG  柱图 (MITRE 战术 / Top 项)
//   - LineSVG 折线图 (时序趋势)
package biz

import (
	"fmt"
	"html/template"
	"math"
	"strings"
)

// ===================== Pie =====================

// PieSlice 饼图扇区。
type PieSlice struct {
	Label string
	Value float64
	Color string // #RRGGBB
}

// PieSVG 渲染饼图为 SVG (带右侧图例)。
//
// width / height 单位 px (PDF 中 px 直接映射，96dpi 下 1px ≈ 0.265mm)。
func PieSVG(slices []PieSlice, width, height int) template.HTML {
	if len(slices) == 0 || width <= 0 || height <= 0 {
		return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d"></svg>`, width, height))
	}

	var total float64
	for _, s := range slices {
		total += s.Value
	}
	if total <= 0 {
		return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d"></svg>`, width, height))
	}

	legendW := 180
	chartW := width - legendW
	if chartW < 200 {
		chartW = 200
	}
	cx := float64(chartW) / 2
	cy := float64(height) / 2
	radius := math.Min(cx, cy) - 20
	innerR := radius * 0.55 // donut hole

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="-apple-system, PingFang SC, Microsoft YaHei, sans-serif" font-size="14">`,
		width, height, width, height)

	startAngle := -math.Pi / 2 // 12 点钟方向
	for _, s := range slices {
		if s.Value <= 0 {
			continue
		}
		angle := s.Value / total * 2 * math.Pi
		endAngle := startAngle + angle

		x1 := cx + radius*math.Cos(startAngle)
		y1 := cy + radius*math.Sin(startAngle)
		x2 := cx + radius*math.Cos(endAngle)
		y2 := cy + radius*math.Sin(endAngle)

		ix1 := cx + innerR*math.Cos(endAngle)
		iy1 := cy + innerR*math.Sin(endAngle)
		ix2 := cx + innerR*math.Cos(startAngle)
		iy2 := cy + innerR*math.Sin(startAngle)

		largeArc := 0
		if angle > math.Pi {
			largeArc = 1
		}
		// donut path
		d := fmt.Sprintf("M %.2f %.2f A %.2f %.2f 0 %d 1 %.2f %.2f L %.2f %.2f A %.2f %.2f 0 %d 0 %.2f %.2f Z",
			x1, y1, radius, radius, largeArc, x2, y2,
			ix1, iy1, innerR, innerR, largeArc, ix2, iy2)
		fmt.Fprintf(&sb, `<path d="%s" fill="%s" stroke="#fff" stroke-width="2"/>`, d, s.Color)

		// 数值标签 (扇区中点)
		mid := startAngle + angle/2
		labelR := (radius + innerR) / 2
		lx := cx + labelR*math.Cos(mid)
		ly := cy + labelR*math.Sin(mid)
		pct := s.Value / total * 100
		if pct >= 5 {
			fmt.Fprintf(&sb,
				`<text x="%.2f" y="%.2f" text-anchor="middle" dominant-baseline="middle" fill="#fff" font-weight="700" font-size="15">%.1f%%</text>`,
				lx, ly, pct)
		}
		startAngle = endAngle
	}

	// 图例
	legendX := chartW + 10
	legendStartY := (height - len(slices)*22) / 2
	if legendStartY < 16 {
		legendStartY = 16
	}
	for i, s := range slices {
		if s.Value <= 0 {
			continue
		}
		y := legendStartY + i*22
		fmt.Fprintf(&sb,
			`<rect x="%d" y="%d" width="12" height="12" rx="2" fill="%s"/>`,
			legendX, y, s.Color)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" fill="#222" dominant-baseline="middle">%s · %s</text>`,
			legendX+18, y+6,
			template.HTMLEscapeString(s.Label),
			formatInt(int(s.Value)))
	}

	sb.WriteString("</svg>")
	return template.HTML(sb.String())
}

// ===================== Bar =====================

// BarItem 柱图条目。
type BarItem struct {
	Label string
	Value float64
}

// BarSVG 渲染垂直柱图为 SVG。
func BarSVG(items []BarItem, width, height int, color string) template.HTML {
	if len(items) == 0 || width <= 0 || height <= 0 {
		return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d"></svg>`, width, height))
	}
	if color == "" {
		color = "#2563eb"
	}
	padL, padR, padT, padB := 40, 16, 16, 60
	plotW := width - padL - padR
	plotH := height - padT - padB

	var maxV float64
	for _, it := range items {
		if it.Value > maxV {
			maxV = it.Value
		}
	}
	if maxV == 0 {
		maxV = 1
	}
	// 向上取整到漂亮刻度
	maxV = niceCeil(maxV)

	barGap := 8
	barW := (plotW - barGap*(len(items)-1)) / len(items)
	if barW < 8 {
		barW = 8
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="-apple-system, PingFang SC, Microsoft YaHei, sans-serif" font-size="14">`,
		width, height, width, height)

	// 网格 + Y 轴刻度
	for i := 0; i <= 4; i++ {
		y := padT + plotH*i/4
		v := maxV * float64(4-i) / 4
		fmt.Fprintf(&sb,
			`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#e5e7eb" stroke-dasharray="2,2"/>`,
			padL, y, padL+plotW, y)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="end" dominant-baseline="middle" fill="#6b7280" font-size="12">%s</text>`,
			padL-6, y, formatInt(int(v)))
	}

	// 柱
	for i, it := range items {
		x := padL + i*(barW+barGap)
		h := int(it.Value / maxV * float64(plotH))
		y := padT + plotH - h
		fmt.Fprintf(&sb,
			`<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s"/>`,
			x, y, barW, h, color)
		// 数值
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="middle" fill="#222" font-size="13" font-weight="600">%s</text>`,
			x+barW/2, y-5, formatInt(int(it.Value)))
		// label (旋转 30°)
		lx := x + barW/2
		ly := padT + plotH + 14
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="end" fill="#222" font-size="12" transform="rotate(-30 %d %d)">%s</text>`,
			lx, ly, lx, ly, template.HTMLEscapeString(truncateRunes(it.Label, 12)))
	}

	// X / Y 轴
	fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9ca3af"/>`,
		padL, padT+plotH, padL+plotW, padT+plotH)
	fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9ca3af"/>`,
		padL, padT, padL, padT+plotH)

	sb.WriteString("</svg>")
	return template.HTML(sb.String())
}

// ===================== Line =====================

// LineSVG 渲染折线图（含填充区域）。
func LineSVG(labels []string, values []float64, width, height int, color string) template.HTML {
	n := len(values)
	if n == 0 || width <= 0 || height <= 0 {
		return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d"></svg>`, width, height))
	}
	if color == "" {
		color = "#3b82f6"
	}
	padL, padR, padT, padB := 44, 12, 16, 44
	plotW := width - padL - padR
	plotH := height - padT - padB

	var maxV float64
	for _, v := range values {
		if v > maxV {
			maxV = v
		}
	}
	if maxV == 0 {
		maxV = 1
	}
	maxV = niceCeil(maxV)

	step := 0.0
	if n > 1 {
		step = float64(plotW) / float64(n-1)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="-apple-system, PingFang SC, Microsoft YaHei, sans-serif" font-size="13">`,
		width, height, width, height)

	// 网格 + Y 轴
	for i := 0; i <= 4; i++ {
		y := padT + plotH*i/4
		v := maxV * float64(4-i) / 4
		fmt.Fprintf(&sb,
			`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#e5e7eb" stroke-dasharray="2,2"/>`,
			padL, y, padL+plotW, y)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="end" dominant-baseline="middle" fill="#6b7280" font-size="12">%s</text>`,
			padL-6, y, formatInt(int(v)))
	}

	// 折线 path
	var pathD, areaD strings.Builder
	for i, v := range values {
		x := float64(padL) + step*float64(i)
		y := float64(padT+plotH) - (v/maxV)*float64(plotH)
		if i == 0 {
			fmt.Fprintf(&pathD, "M %.2f %.2f ", x, y)
			fmt.Fprintf(&areaD, "M %.2f %d L %.2f %.2f ", x, padT+plotH, x, y)
		} else {
			fmt.Fprintf(&pathD, "L %.2f %.2f ", x, y)
			fmt.Fprintf(&areaD, "L %.2f %.2f ", x, y)
		}
	}
	lastX := float64(padL) + step*float64(n-1)
	fmt.Fprintf(&areaD, "L %.2f %d Z", lastX, padT+plotH)

	fmt.Fprintf(&sb, `<path d="%s" fill="%s" opacity="0.18"/>`, areaD.String(), color)
	fmt.Fprintf(&sb, `<path d="%s" fill="none" stroke="%s" stroke-width="1.6"/>`, pathD.String(), color)

	// X 轴标签 (稀疏)
	tickStep := 1
	maxTicks := 12
	if n > maxTicks {
		tickStep = (n + maxTicks - 1) / maxTicks
	}
	for i := 0; i < n; i += tickStep {
		x := float64(padL) + step*float64(i)
		fmt.Fprintf(&sb,
			`<text x="%.2f" y="%d" text-anchor="end" fill="#222" font-size="12" transform="rotate(-35 %.2f %d)">%s</text>`,
			x, padT+plotH+14, x, padT+plotH+14, template.HTMLEscapeString(labels[i]))
	}
	// 轴
	fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9ca3af"/>`,
		padL, padT+plotH, padL+plotW, padT+plotH)
	fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9ca3af"/>`,
		padL, padT, padL, padT+plotH)

	sb.WriteString("</svg>")
	return template.HTML(sb.String())
}

// ===================== utils =====================

func niceCeil(v float64) float64 {
	if v <= 0 {
		return 1
	}
	exp := math.Pow(10, math.Floor(math.Log10(v)))
	n := v / exp
	switch {
	case n <= 1:
		return 1 * exp
	case n <= 2:
		return 2 * exp
	case n <= 5:
		return 5 * exp
	default:
		return 10 * exp
	}
}

func formatInt(n int) string {
	if n < 0 {
		return "-" + formatInt(-n)
	}
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	var out strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(c)
	}
	return out.String()
}

func truncateRunes(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "…"
}
