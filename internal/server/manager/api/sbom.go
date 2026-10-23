// Package api 提供 HTTP API 处理器
package api

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// CycloneDX v1.5 JSON structures

type cdxBOM struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	Metadata     cdxMetadata        `json:"metadata"`
	Components   []cdxComponent     `json:"components"`
	Vulns        []cdxVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type cdxVulnerability struct {
	ID          string      `json:"id"`
	Source      cdxSource   `json:"source"`
	Ratings     []cdxRating `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []cdxAffect `json:"affects,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxRating struct {
	Severity string  `json:"severity"`
	Score    float64 `json:"score,omitempty"`
	Method   string  `json:"method,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// ExportSBOM 导出 CycloneDX v1.5 SBOM
// GET /api/v1/assets/sbom?host_id=xxx
//
// host_id 必填:不传时全量导出 5w 软件包 + 5w 漏洞,响应体 14MB+,严重拖累 MySQL +
// 网关 + 客户端 IO,且全集群 SBOM 业务意义不大(SBOM 单元应是单主机/容器)。
func (h *AssetsHandler) ExportSBOM(c *gin.Context) {
	hostID := c.Query("host_id")
	if hostID == "" {
		BadRequest(c, "host_id 必填:SBOM 单元应为单主机,无 host_id 时拒绝全集群导出")
		return
	}

	// 查询软件包
	q := h.db.Model(&model.Software{}).Where("host_id = ?", hostID)

	var software []model.Software
	if err := q.Limit(50000).Find(&software).Error; err != nil {
		h.logger.Error("SBOM 导出查询软件失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 查询关联漏洞(单 host scope)
	var vulns []model.Vulnerability
	var hvs []model.HostVulnerability
	h.db.Where("host_id = ?", hostID).Find(&hvs)
	if len(hvs) > 0 {
		vulnIDs := make([]uint, 0, len(hvs))
		for _, hv := range hvs {
			vulnIDs = append(vulnIDs, hv.VulnID)
		}
		h.db.Where("id IN ?", vulnIDs).Find(&vulns)
	}

	// 构造 CycloneDX BOM
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{Vendor: "MxCwpp", Name: "mxcwpp", Version: "1.0.0"},
			},
		},
	}

	bom.Metadata.Component = &cdxComponent{
		Type: "device",
		Name: hostID,
	}

	// 组件去重 (name+version)
	seen := make(map[string]bool)
	for _, s := range software {
		key := s.Name + "@" + s.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		comp := cdxComponent{
			Type:    "library",
			Name:    s.Name,
			Version: s.Version,
			PURL:    s.PURL,
		}
		bom.Components = append(bom.Components, comp)
	}

	// 漏洞映射
	for _, v := range vulns {
		cv := cdxVulnerability{
			ID: v.CveID,
			Source: cdxSource{
				Name: "OSV",
				URL:  "https://osv.dev",
			},
			Description: v.Description,
		}

		if v.CvssScore > 0 {
			cv.Ratings = append(cv.Ratings, cdxRating{
				Severity: v.Severity,
				Score:    v.CvssScore,
				Method:   "CVSSv31",
			})
		} else {
			cv.Ratings = append(cv.Ratings, cdxRating{
				Severity: v.Severity,
			})
		}

		if v.PURL != "" {
			cv.Affects = append(cv.Affects, cdxAffect{Ref: v.PURL})
		}

		bom.Vulns = append(bom.Vulns, cv)
	}

	// 输出
	filename := fmt.Sprintf("sbom_%s.cdx.json", time.Now().Format("20060102150405"))
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/json; charset=utf-8")

	enc := json.NewEncoder(c.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bom); err != nil {
		h.logger.Warn("SBOM 导出写入失败", zap.Error(err))
	}
}
