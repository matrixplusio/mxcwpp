// Package api 提供 HTTP API 处理器。
//
// reports_pdf.go 提供报告 PDF 导出 endpoint。
//
// 渲染流程 (v2 — server-side template)：
//
//	client → manager
//	  ├── BuildEDRReportData (复用 JSON API 同一数据装配函数)
//	  ├── biz.RenderEDRReportHTML (Go html/template + 内嵌 SVG 图表)
//	  └── biz.PDFService.RenderHTML (POST Gotenberg /forms/chromium/convert/html)
//	         → 返回矢量 PDF 字节流
//
// 优势 vs 旧 SPA 拉取方式：
//   - 无 SPA 登录态依赖（不会被 401 重定向到登录页）
//   - 数据装配函数共享，JSON / PDF 数据一致不漂移
//   - 报告模板独立维护，不耦合前端 dashboard UI
//   - 可被 cron / scheduler 后台调用
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
)

// ReportPDFHandler 处理报告 PDF 导出。
type ReportPDFHandler struct {
	pdfService     *biz.PDFService
	reportsHandler *ReportsHandler // 复用数据装配函数
	uploadStatic   string          // /uploads（HTTP 路径）
	uploadDir      string          // ./uploads（本地目录）
	httpPrefix     string          // manager HTTP 前缀，回退拉 logo
	logger         *zap.Logger
}

// NewReportPDFHandler 创建处理器。
//
// gotenbergURL 为空时 HasGotenberg 返回 false，导出接口直接报错。
// uploadStatic/uploadDir 用于把 site_config.site_logo URL 解析为本地文件。
func NewReportPDFHandler(gotenbergURL string, rh *ReportsHandler, uploadStatic, uploadDir, httpPrefix string, logger *zap.Logger) *ReportPDFHandler {
	return &ReportPDFHandler{
		pdfService:     biz.NewPDFService(gotenbergURL, logger),
		reportsHandler: rh,
		uploadStatic:   uploadStatic,
		uploadDir:      uploadDir,
		httpPrefix:     httpPrefix,
		logger:         logger,
	}
}

// renderPDF 渲染 + 流式返回的公共流程，复用给所有报告类型。
// htmlRenderer: 把 data + branding 转为 HTML 的函数（biz.RenderXxxReportHTML）
// dataFn:       拉取业务数据的函数（h.reportsHandler.BuildXxxReportData）
// filePrefix:   导出文件名前缀（如 "EDR-Report"）
func (h *ReportPDFHandler) renderPDF(
	c *gin.Context,
	data gin.H,
	htmlRenderer func(gin.H, biz.ReportRenderOptions) (string, error),
	filePrefix string,
) {
	if !h.pdfService.HasGotenberg() {
		BadRequest(c, "PDF 服务未配置 (Gotenberg sidecar 未部署)")
		return
	}
	if data == nil {
		NotFound(c, "报告数据不存在")
		return
	}
	landscape := c.Query("landscape") == "true"

	branding := biz.LoadSiteBranding(h.reportsHandler.db, h.uploadStatic, h.uploadDir, h.httpPrefix)

	html, err := htmlRenderer(data, branding)
	if err != nil {
		h.logger.Error("HTML 渲染失败", zap.String("prefix", filePrefix), zap.Error(err))
		InternalError(c, fmt.Sprintf("报告 HTML 渲染失败: %s", err.Error()))
		return
	}

	opts := biz.DefaultHTMLOptions(html)
	opts.Landscape = landscape

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()
	pdf, err := h.pdfService.RenderHTML(ctx, opts)
	if err != nil {
		h.logger.Error("PDF 渲染失败", zap.String("prefix", filePrefix), zap.Error(err))
		InternalError(c, fmt.Sprintf("PDF 渲染失败: %s", err.Error()))
		return
	}

	filename := fmt.Sprintf("%s-%s.pdf", filePrefix, time.Now().Format("20060102-150405"))
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Length", fmt.Sprintf("%d", len(pdf)))
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	_, _ = c.Writer.Write(pdf)
}

// ExportEDRReportPDF GET /api/v1/reports/edr/pdf?start_time=&end_time=&landscape=
func (h *ReportPDFHandler) ExportEDRReportPDF(c *gin.Context) {
	startTime, endTime, ok := parseReportTimeRange(c)
	if !ok {
		return
	}
	data := h.reportsHandler.BuildEDRReportData(startTime, endTime)
	h.renderPDF(c, data, biz.RenderEDRReportHTML, "EDR-Report")
}

// ExportAntivirusReportPDF GET /api/v1/reports/antivirus/pdf?start_time=&end_time=
func (h *ReportPDFHandler) ExportAntivirusReportPDF(c *gin.Context) {
	startTime, endTime, ok := parseReportTimeRange(c)
	if !ok {
		return
	}
	data := h.reportsHandler.BuildAntivirusReportData(startTime, endTime)
	h.renderPDF(c, data, biz.RenderAntivirusReportHTML, "Antivirus-Report")
}

// ExportVulnReportPDF GET /api/v1/reports/vulnerability/pdf?start_time=&end_time=
func (h *ReportPDFHandler) ExportVulnReportPDF(c *gin.Context) {
	startTime, endTime, ok := parseReportTimeRange(c)
	if !ok {
		return
	}
	data := h.reportsHandler.BuildVulnReportData(startTime, endTime)
	h.renderPDF(c, data, biz.RenderVulnReportHTML, "Vulnerability-Report")
}

// ExportKubeReportPDF GET /api/v1/reports/kube/pdf?start_time=&end_time=
func (h *ReportPDFHandler) ExportKubeReportPDF(c *gin.Context) {
	startTime, endTime, ok := parseReportTimeRange(c)
	if !ok {
		return
	}
	data := h.reportsHandler.BuildKubeReportData(startTime, endTime)
	h.renderPDF(c, data, biz.RenderKubeReportHTML, "Kube-Report")
}

// ExportTaskReportPDF GET /api/v1/reports/task/:task_id/pdf
func (h *ReportPDFHandler) ExportTaskReportPDF(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "task_id 参数缺失")
		return
	}
	data := h.reportsHandler.BuildTaskReportData(taskID)
	h.renderPDF(c, data, biz.RenderTaskReportHTML, fmt.Sprintf("Task-Report-%s", taskID))
}
