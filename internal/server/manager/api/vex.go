// Package api — VEX 漏洞利用性声明 HTTP handler (B7).
//
// Route:
//
//	GET /api/v1/vex/:product_id?version=X.Y.Z              → 整份 VEX JSON
//	GET /api/v1/vex/:product_id/cyclonedx?version=X.Y.Z   → CycloneDX VEX 1.5 下载
//	GET /api/v1/vex/:product_id/csaf?version=X.Y.Z        → CSAF 2.0 下载
//	GET /api/v1/vex/:product_id/statements                → CVE 声明列表
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz/vex"
)

type VEXHandler struct {
	gen    *vex.Generator
	logger *zap.Logger
}

func NewVEXHandler(db *gorm.DB, logger *zap.Logger) *VEXHandler {
	return &VEXHandler{
		gen:    vex.NewGenerator(db, logger, "mxsec"),
		logger: logger,
	}
}

// GetDocument 返回完整 VEX 文档.
// GET /api/v1/vex/:product_id?version=X.Y.Z
func (h *VEXHandler) GetDocument(c *gin.Context) {
	productID := c.Param("product_id")
	version := c.DefaultQuery("version", "")
	doc, err := h.gen.GenerateForProduct(c.Request.Context(), productID, version)
	if err != nil {
		h.logger.Error("generate VEX failed", zap.Error(err))
		InternalError(c, "生成 VEX 失败")
		return
	}
	Success(c, doc)
}

// ListStatements 返回 CVE 声明列表 (与 GetDocument.Statements 等价, 提供独立端点便于分页).
// GET /api/v1/vex/:product_id/statements
func (h *VEXHandler) ListStatements(c *gin.Context) {
	productID := c.Param("product_id")
	version := c.DefaultQuery("version", "")
	doc, err := h.gen.GenerateForProduct(c.Request.Context(), productID, version)
	if err != nil {
		h.logger.Error("generate VEX statements failed", zap.Error(err))
		InternalError(c, "生成声明失败")
		return
	}
	Success(c, gin.H{
		"items": doc.Statements,
		"total": len(doc.Statements),
	})
}

// ExportCycloneDX 下载 CycloneDX VEX 1.5 JSON.
// GET /api/v1/vex/:product_id/cyclonedx?version=X.Y.Z
func (h *VEXHandler) ExportCycloneDX(c *gin.Context) {
	productID := c.Param("product_id")
	version := c.DefaultQuery("version", "")
	doc, err := h.gen.GenerateForProduct(c.Request.Context(), productID, version)
	if err != nil {
		h.logger.Error("generate VEX failed", zap.Error(err))
		InternalError(c, "生成 VEX 失败")
		return
	}
	data, err := h.gen.MarshalCycloneDX(doc)
	if err != nil {
		h.logger.Error("marshal CycloneDX failed", zap.Error(err))
		InternalError(c, "序列化失败")
		return
	}
	filename := productID + "-" + version + "-cyclonedx.json"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "application/json", data)
}

// ExportCSAF 下载 CSAF 2.0 JSON.
// GET /api/v1/vex/:product_id/csaf?version=X.Y.Z
func (h *VEXHandler) ExportCSAF(c *gin.Context) {
	productID := c.Param("product_id")
	version := c.DefaultQuery("version", "")
	doc, err := h.gen.GenerateForProduct(c.Request.Context(), productID, version)
	if err != nil {
		h.logger.Error("generate VEX failed", zap.Error(err))
		InternalError(c, "生成 VEX 失败")
		return
	}
	data, err := h.gen.MarshalCSAF(doc)
	if err != nil {
		h.logger.Error("marshal CSAF failed", zap.Error(err))
		InternalError(c, "序列化失败")
		return
	}
	filename := productID + "-" + version + "-csaf.json"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "application/json", data)
}
