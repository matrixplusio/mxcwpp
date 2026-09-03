// Package biz 提供业务逻辑层。
//
// pdf.go 实现服务端 PDF 生成，通过 Gotenberg sidecar (HTTP API) 调
// Chromium 渲染指定 URL 为 PDF。
//
// 设计:
//   - 调用方传 URL（manager 内部报告渲染地址）+ 选项
//   - Gotenberg 拉取 URL → Chromium 渲染 → 返回 PDF 字节流
//   - URL 含 sign token 让目标页面免鉴权（短期有效）
//
// 与 jsPDF + html2canvas 相比:
//   - 矢量文本可搜索可复制
//   - 完美 CSS3 / Web Font / SVG 支持
//   - 大数据集（1w+ 行）秒级，浏览器不崩
//   - 支持 cron 后台触发，可订阅推送
package biz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// PDFOptions 描述 PDF 生成参数。
type PDFOptions struct {
	URL             string  // 内部 manager 渲染 URL (含 token)
	PaperWidth      float64 // 英寸，A4 = 8.27
	PaperHeight     float64 // A4 = 11.69
	MarginTop       float64
	MarginBottom    float64
	MarginLeft      float64
	MarginRight     float64
	PrintBackground bool
	Landscape       bool
	WaitDelaySec    int // 等待 JS 渲染完成 (秒)
}

// DefaultPDFOptions A4 默认参数。
func DefaultPDFOptions(url string) PDFOptions {
	return PDFOptions{
		URL:             url,
		PaperWidth:      8.27,
		PaperHeight:     11.69,
		MarginTop:       0.5,
		MarginBottom:    0.5,
		MarginLeft:      0.4,
		MarginRight:     0.4,
		PrintBackground: true,
		WaitDelaySec:    3,
	}
}

// PDFService 通过 Gotenberg 生成 PDF。
type PDFService struct {
	gotenbergURL string // 如 http://gotenberg:3000
	httpClient   *http.Client
	logger       *zap.Logger
}

// NewPDFService 创建 PDF 服务。gotenbergURL 为空时禁用（HasGotenberg 返回 false）。
func NewPDFService(gotenbergURL string, logger *zap.Logger) *PDFService {
	return &PDFService{
		gotenbergURL: gotenbergURL,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
		logger: logger,
	}
}

// HasGotenberg 是否配置了 Gotenberg。
func (s *PDFService) HasGotenberg() bool {
	return s.gotenbergURL != ""
}

// RenderURL 调 Gotenberg `/forms/chromium/convert/url` 把 URL 渲染为 PDF。
//
// Gotenberg 8 API 参考: https://gotenberg.dev/docs/routes#url-into-pdf-route
func (s *PDFService) RenderURL(ctx context.Context, opts PDFOptions) ([]byte, error) {
	if !s.HasGotenberg() {
		return nil, fmt.Errorf("PDF 服务未配置 (gotenbergURL 为空)")
	}
	if opts.URL == "" {
		return nil, fmt.Errorf("URL 不能为空")
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	// 必填: url
	if err := w.WriteField("url", opts.URL); err != nil {
		return nil, err
	}
	// A4 默认
	writeFloat := func(name string, v float64) {
		if v > 0 {
			_ = w.WriteField(name, fmt.Sprintf("%.2f", v))
		}
	}
	writeFloat("paperWidth", opts.PaperWidth)
	writeFloat("paperHeight", opts.PaperHeight)
	writeFloat("marginTop", opts.MarginTop)
	writeFloat("marginBottom", opts.MarginBottom)
	writeFloat("marginLeft", opts.MarginLeft)
	writeFloat("marginRight", opts.MarginRight)

	if opts.PrintBackground {
		_ = w.WriteField("printBackground", "true")
	}
	if opts.Landscape {
		_ = w.WriteField("landscape", "true")
	}
	if opts.WaitDelaySec > 0 {
		_ = w.WriteField("waitDelay", fmt.Sprintf("%ds", opts.WaitDelaySec))
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		s.gotenbergURL+"/forms/chromium/convert/url", &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("Gotenberg 请求失败",
			zap.String("url", opts.URL), zap.Error(err))
		return nil, fmt.Errorf("gotenberg 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		s.logger.Error("Gotenberg 返回错误",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(respBody)))
		return nil, fmt.Errorf("gotenberg %d: %s", resp.StatusCode, string(respBody))
	}

	pdf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	s.logger.Info("PDF 生成完成",
		zap.String("url", opts.URL),
		zap.Int("bytes", len(pdf)),
		zap.Duration("elapsed", time.Since(start)))
	return pdf, nil
}

// HTMLOptions 描述 HTML→PDF 生成参数。
//
// 与 RenderURL 的区别：HTML 字符串直接 POST 给 Gotenberg
// (`/forms/chromium/convert/html`)，不走 URL 拉取，所以：
//   - 无 SPA 登录态依赖（不会 401 跳登录）
//   - 无网络往返到前端容器
//   - 适合服务端模板渲染场景（拉数据 → 渲模板 → PDF）
type HTMLOptions struct {
	HTML            string  // 完整 <!DOCTYPE html>... 字符串
	PaperWidth      float64 // 英寸，A4 = 8.27
	PaperHeight     float64 // A4 = 11.69
	MarginTop       float64
	MarginBottom    float64
	MarginLeft      float64
	MarginRight     float64
	PrintBackground bool
	Landscape       bool
	WaitDelaySec    int
}

// DefaultHTMLOptions A4 默认参数。
func DefaultHTMLOptions(html string) HTMLOptions {
	return HTMLOptions{
		HTML:            html,
		PaperWidth:      8.27,
		PaperHeight:     11.69,
		MarginTop:       0.4,
		MarginBottom:    0.5,
		MarginLeft:      0.4,
		MarginRight:     0.4,
		PrintBackground: true,
		WaitDelaySec:    1,
	}
}

// RenderHTML 把 HTML 字符串直接喂给 Gotenberg 渲染 PDF。
//
// Gotenberg 8 API: POST /forms/chromium/convert/html
// 必填 multipart field: `files` 一个名为 index.html 的 HTML 文件。
func (s *PDFService) RenderHTML(ctx context.Context, opts HTMLOptions) ([]byte, error) {
	if !s.HasGotenberg() {
		return nil, fmt.Errorf("PDF 服务未配置 (gotenbergURL 为空)")
	}
	if opts.HTML == "" {
		return nil, fmt.Errorf("HTML 不能为空")
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	// 必填: files (index.html)
	fw, err := w.CreateFormFile("files", "index.html")
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write([]byte(opts.HTML)); err != nil {
		return nil, err
	}

	writeFloat := func(name string, v float64) {
		if v > 0 {
			_ = w.WriteField(name, fmt.Sprintf("%.2f", v))
		}
	}
	writeFloat("paperWidth", opts.PaperWidth)
	writeFloat("paperHeight", opts.PaperHeight)
	writeFloat("marginTop", opts.MarginTop)
	writeFloat("marginBottom", opts.MarginBottom)
	writeFloat("marginLeft", opts.MarginLeft)
	writeFloat("marginRight", opts.MarginRight)
	if opts.PrintBackground {
		_ = w.WriteField("printBackground", "true")
	}
	if opts.Landscape {
		_ = w.WriteField("landscape", "true")
	}
	if opts.WaitDelaySec > 0 {
		_ = w.WriteField("waitDelay", fmt.Sprintf("%ds", opts.WaitDelaySec))
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		s.gotenbergURL+"/forms/chromium/convert/html", &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("Gotenberg HTML 请求失败", zap.Error(err))
		return nil, fmt.Errorf("gotenberg 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		s.logger.Error("Gotenberg HTML 返回错误",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(respBody)))
		return nil, fmt.Errorf("gotenberg %d: %s", resp.StatusCode, string(respBody))
	}

	pdf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	s.logger.Info("PDF HTML→PDF 生成完成",
		zap.Int("html_bytes", len(opts.HTML)),
		zap.Int("pdf_bytes", len(pdf)),
		zap.Duration("elapsed", time.Since(start)))
	return pdf, nil
}
