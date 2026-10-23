package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// SBOMImportHandler SBOM 导入 API 处理器
type SBOMImportHandler struct {
	db       *gorm.DB
	logger   *zap.Logger
	importer *biz.SBOMImporter
}

// NewSBOMImportHandler 创建处理器
func NewSBOMImportHandler(db *gorm.DB, logger *zap.Logger) *SBOMImportHandler {
	scanner := biz.NewVulnScanner(db, logger)
	return &SBOMImportHandler{
		db:       db,
		logger:   logger,
		importer: biz.NewSBOMImporter(db, logger, scanner),
	}
}

// ImportSBOM 上传 SBOM 文件
func (h *SBOMImportHandler) ImportSBOM(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		BadRequest(c, "请上传 SBOM 文件")
		return
	}
	defer file.Close()

	format := c.DefaultPostForm("format", "auto")
	projectName := c.PostForm("project_name")
	if projectName == "" {
		BadRequest(c, "请提供项目名称")
		return
	}

	result, err := h.importer.Import(file, format, projectName)
	if err != nil {
		InternalError(c, "SBOM 导入失败: "+err.Error())
		return
	}

	Success(c, result)
}

// ListProjects SBOM 项目列表
func (h *SBOMImportHandler) ListProjects(c *gin.Context) {
	type projectInfo struct {
		ProjectName    string `json:"projectName"`
		ComponentCount int64  `json:"componentCount"`
	}

	var results []projectInfo
	h.db.Table("software").
		Select("REPLACE(host_id, 'sbom:', '') AS project_name, COUNT(*) AS component_count").
		Where("host_id LIKE ?", "sbom:%").
		Group("host_id").
		Order("project_name").
		Scan(&results)

	Success(c, results)
}

// GetProject 项目组件 + 漏洞详情
func (h *SBOMImportHandler) GetProject(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		BadRequest(c, "项目名称不能为空")
		return
	}

	hostID := "sbom:" + name

	var software []model.Software
	h.db.Where("host_id = ?", hostID).Find(&software)

	var vulns []model.Vulnerability
	h.db.Joins("JOIN host_vulnerabilities hv ON hv.vuln_id = vulnerabilities.id").
		Where("hv.host_id = ?", hostID).
		Find(&vulns)

	Success(c, gin.H{
		"projectName":     name,
		"components":      software,
		"vulnerabilities": vulns,
	})
}
