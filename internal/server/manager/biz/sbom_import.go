package biz

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// SBOMImporter SBOM 导入器
type SBOMImporter struct {
	db      *gorm.DB
	logger  *zap.Logger
	scanner *VulnScanner
}

// NewSBOMImporter 创建 SBOM 导入器
func NewSBOMImporter(db *gorm.DB, logger *zap.Logger, scanner *VulnScanner) *SBOMImporter {
	return &SBOMImporter{
		db:      db,
		logger:  logger,
		scanner: scanner,
	}
}

// SBOMImportResult 导入结果
type SBOMImportResult struct {
	ProjectName    string `json:"projectName"`
	Format         string `json:"format"`
	ComponentCount int    `json:"componentCount"`
	VulnCount      int    `json:"vulnCount"`
	CriticalCount  int    `json:"criticalCount"`
	HighCount      int    `json:"highCount"`
}

// Import 解析 SBOM 文件并触发漏洞扫描
func (s *SBOMImporter) Import(file io.Reader, format string, projectName string) (*SBOMImportResult, error) {
	s.logger.Info("开始导入 SBOM", zap.String("project", projectName), zap.String("format", format))

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取 SBOM 文件失败: %w", err)
	}

	var components []sbomComponent
	switch strings.ToLower(format) {
	case "cyclonedx", "cdx":
		components, err = parseCycloneDX(data)
	case "spdx":
		components, err = parseSPDX(data)
	default:
		// 自动检测格式
		components, err = autoDetectAndParse(data)
	}
	if err != nil {
		return nil, fmt.Errorf("解析 SBOM 失败: %w", err)
	}

	s.logger.Info("SBOM 解析完成", zap.Int("components", len(components)))

	// 写入 software 表（host_id 使用 sbom: 前缀）
	hostID := "sbom:" + projectName
	for _, comp := range components {
		sw := model.Software{
			ID:          fmt.Sprintf("%s-%s-%s", hostID, comp.name, comp.version),
			HostID:      hostID,
			Name:        comp.name,
			Version:     comp.version,
			PackageType: comp.pkgType,
			PURL:        comp.purl,
			Ecosystem:   comp.ecosystem,
			SourceFile:  "SBOM:" + format,
			CollectedAt: model.Now(),
		}
		s.db.Where("id = ?", sw.ID).Assign(sw).FirstOrCreate(&sw)
	}

	result := &SBOMImportResult{
		ProjectName:    projectName,
		Format:         format,
		ComponentCount: len(components),
	}

	// 触发漏洞扫描
	if s.scanner != nil {
		go func() {
			if err := s.scanner.ScanAll(); err != nil {
				s.logger.Warn("SBOM 导入后漏洞扫描失败", zap.Error(err))
			}
		}()
	}

	// 统计该 SBOM 项目当前关联的漏洞
	var vulnCount, critCount, highCount int64
	s.db.Model(&model.Vulnerability{}).
		Joins("JOIN host_vulnerabilities hv ON hv.vuln_id = vulnerabilities.id").
		Where("hv.host_id = ? AND hv.status = ?", hostID, "unpatched").
		Count(&vulnCount)
	s.db.Model(&model.Vulnerability{}).
		Joins("JOIN host_vulnerabilities hv ON hv.vuln_id = vulnerabilities.id").
		Where("hv.host_id = ? AND hv.status = ? AND vulnerabilities.severity = ?", hostID, "unpatched", "critical").
		Count(&critCount)
	s.db.Model(&model.Vulnerability{}).
		Joins("JOIN host_vulnerabilities hv ON hv.vuln_id = vulnerabilities.id").
		Where("hv.host_id = ? AND hv.status = ? AND vulnerabilities.severity = ?", hostID, "unpatched", "high").
		Count(&highCount)

	result.VulnCount = int(vulnCount)
	result.CriticalCount = int(critCount)
	result.HighCount = int(highCount)

	s.logger.Info("SBOM 导入完成", zap.String("project", projectName), zap.Int("components", len(components)))
	return result, nil
}

// sbomComponent SBOM 组件信息
type sbomComponent struct {
	name      string
	version   string
	purl      string
	pkgType   string
	ecosystem string
}

// ========== CycloneDX 解析 ==========

type cycloneDXBOM struct {
	Components []cycloneDXComponent `json:"components" xml:"components>component"`
}

type cycloneDXComponent struct {
	Type    string `json:"type" xml:"type,attr"`
	Name    string `json:"name" xml:"name"`
	Version string `json:"version" xml:"version"`
	PURL    string `json:"purl" xml:"purl"`
	Group   string `json:"group" xml:"group"`
}

func parseCycloneDX(data []byte) ([]sbomComponent, error) {
	var bom cycloneDXBOM

	// 尝试 JSON
	if err := json.Unmarshal(data, &bom); err != nil {
		// 尝试 XML
		if err2 := xml.Unmarshal(data, &bom); err2 != nil {
			return nil, fmt.Errorf("CycloneDX 解析失败 (JSON: %v, XML: %v)", err, err2)
		}
	}

	var components []sbomComponent
	for _, c := range bom.Components {
		if c.Name == "" {
			continue
		}
		comp := sbomComponent{
			name:    c.Name,
			version: c.Version,
			purl:    c.PURL,
		}
		if c.Group != "" {
			comp.name = c.Group + ":" + c.Name
		}
		comp.ecosystem, comp.pkgType = detectEcosystemFromPURL(c.PURL)
		components = append(components, comp)
	}

	return components, nil
}

// ========== SPDX 解析 ==========

type spdxDocument struct {
	Packages []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
	DownloadLocation string            `json:"downloadLocation"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func parseSPDX(data []byte) ([]sbomComponent, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("SPDX JSON 解析失败: %w", err)
	}

	var components []sbomComponent
	for _, p := range doc.Packages {
		if p.Name == "" {
			continue
		}
		comp := sbomComponent{
			name:    p.Name,
			version: p.VersionInfo,
		}
		// 从 externalRefs 提取 PURL
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" {
				comp.purl = ref.ReferenceLocator
				break
			}
		}
		comp.ecosystem, comp.pkgType = detectEcosystemFromPURL(comp.purl)
		components = append(components, comp)
	}

	return components, nil
}

// autoDetectAndParse 自动检测格式并解析
func autoDetectAndParse(data []byte) ([]sbomComponent, error) {
	// 尝试 CycloneDX
	if comps, err := parseCycloneDX(data); err == nil && len(comps) > 0 {
		return comps, nil
	}
	// 尝试 SPDX
	if comps, err := parseSPDX(data); err == nil && len(comps) > 0 {
		return comps, nil
	}
	return nil, fmt.Errorf("无法识别 SBOM 格式")
}

// detectEcosystemFromPURL 从 PURL 推断生态系统
func detectEcosystemFromPURL(purl string) (ecosystem, pkgType string) {
	switch {
	case strings.HasPrefix(purl, "pkg:golang/"):
		return "Go", "golang"
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "npm", "npm"
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "PyPI", "pip"
	case strings.HasPrefix(purl, "pkg:maven/"):
		return "Maven", "jar"
	case strings.HasPrefix(purl, "pkg:cargo/"):
		return "Cargo", "cargo"
	case strings.HasPrefix(purl, "pkg:rpm/"):
		return "OS", "rpm"
	case strings.HasPrefix(purl, "pkg:deb/"):
		return "OS", "deb"
	default:
		return "", ""
	}
}
