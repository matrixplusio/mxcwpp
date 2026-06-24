// Package vex — VEX (Vulnerability Exploitability eXchange) 生成器 (B7).
//
// 给客户出具产品漏洞利用性声明:
//   - CycloneDX VEX 1.5 (JSON)
//   - CSAF 2.0 (Common Security Advisory Framework, OASIS 标准)
//
// 4 状态:
//   - not_affected: 产品不受影响 (代码未引用 vulnerable 函数)
//   - affected: 产品受影响, 需修复
//   - fixed: 已修复
//   - under_investigation: 调查中
//
// 用法:
//
//	gen := vex.NewGenerator(db, logger)
//	doc := gen.GenerateForProduct(ctx, productID, "2.0.0")
//	jsonBytes := gen.MarshalCycloneDX(doc)
//	xmlBytes := gen.MarshalCSAF(doc)
package vex

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Status VEX 状态.
type Status string

const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Justification not_affected 时的理由 (CycloneDX 规范).
type Justification string

const (
	JustifyCodeNotPresent               Justification = "code_not_present"
	JustifyCodeNotReachable             Justification = "code_not_reachable"
	JustifyRequiresConfiguration        Justification = "requires_configuration"
	JustifyRequiresDependency           Justification = "requires_dependency"
	JustifyRequiresEnvironment          Justification = "requires_environment"
	JustifyProtectedByCompiler          Justification = "protected_by_compiler"
	JustifyProtectedAtRuntime           Justification = "protected_at_runtime"
	JustifyProtectedAtPerimeter         Justification = "protected_at_perimeter"
	JustifyProtectedByMitigatingControl Justification = "protected_by_mitigating_control"
)

// Statement 单个 CVE 的 VEX 状态.
type Statement struct {
	CVE              string        `json:"cve"`
	Status           Status        `json:"status"`
	Justification    Justification `json:"justification,omitempty"`
	ImpactStatement  string        `json:"impact_statement,omitempty"`
	ActionStatement  string        `json:"action_statement,omitempty"`
	AffectedVersions []string      `json:"affected_versions,omitempty"`
	FixedInVersion   string        `json:"fixed_in_version,omitempty"`
}

// Document 完整 VEX 文档.
type Document struct {
	ProductID   string      `json:"product_id"`
	ProductName string      `json:"product_name"`
	ProductVer  string      `json:"product_version"`
	Vendor      string      `json:"vendor"`
	GeneratedAt time.Time   `json:"generated_at"`
	Statements  []Statement `json:"statements"`
}

// Generator 工厂.
type Generator struct {
	db     *gorm.DB
	logger *zap.Logger
	vendor string
}

// NewGenerator 构造.
func NewGenerator(db *gorm.DB, logger *zap.Logger, vendor string) *Generator {
	if logger == nil {
		logger = zap.NewNop()
	}
	if vendor == "" {
		vendor = "mxcwpp"
	}
	return &Generator{db: db, logger: logger, vendor: vendor}
}

// GenerateForProduct 给单产品生成 VEX 文档.
//
// 来源:
//   - SBOM (host_sboms) 查产品所有依赖包
//   - host_vulnerabilities 查关联 CVE
//   - vex_statements 表查人工标注的状态 (优先级最高)
func (g *Generator) GenerateForProduct(ctx context.Context, productID, version string) (*Document, error) {
	doc := &Document{
		ProductID:   productID,
		ProductVer:  version,
		Vendor:      g.vendor,
		GeneratedAt: time.Now(),
	}
	// 取人工标注 statements
	type vexRow struct {
		CVE             string `gorm:"column:cve"`
		Status          string `gorm:"column:status"`
		Justification   string `gorm:"column:justification"`
		ImpactStatement string `gorm:"column:impact_statement"`
		ActionStatement string `gorm:"column:action_statement"`
		FixedInVersion  string `gorm:"column:fixed_in_version"`
	}
	var rows []vexRow
	if err := g.db.WithContext(ctx).
		Table("vex_statements").
		Where("product_id = ?", productID).
		Find(&rows).Error; err != nil {
		g.logger.Debug("vex_statements query (table may not exist)", zap.Error(err))
	}
	manual := make(map[string]Statement, len(rows))
	for _, r := range rows {
		manual[r.CVE] = Statement{
			CVE:             r.CVE,
			Status:          Status(r.Status),
			Justification:   Justification(r.Justification),
			ImpactStatement: r.ImpactStatement,
			ActionStatement: r.ActionStatement,
			FixedInVersion:  r.FixedInVersion,
		}
	}

	// 拉关联 CVE 列表 (走 host_vulnerabilities 关联 SBOM)
	type cveRow struct {
		CVEID string `gorm:"column:cve_id"`
	}
	var cveRows []cveRow
	_ = g.db.WithContext(ctx).
		Table("host_vulnerabilities").
		Select("DISTINCT cve_id").
		Where("product_id = ?", productID).
		Find(&cveRows).Error
	for _, c := range cveRows {
		if s, ok := manual[c.CVEID]; ok {
			doc.Statements = append(doc.Statements, s)
		} else {
			doc.Statements = append(doc.Statements, Statement{
				CVE:    c.CVEID,
				Status: StatusUnderInvestigation,
			})
		}
	}
	// 补人工有但 host_vulns 没的 (e.g. 主动声明 not_affected)
	for _, s := range manual {
		found := false
		for _, x := range doc.Statements {
			if x.CVE == s.CVE {
				found = true
				break
			}
		}
		if !found {
			doc.Statements = append(doc.Statements, s)
		}
	}
	return doc, nil
}

// MarshalCycloneDX 输出 CycloneDX VEX 1.5 JSON.
func (g *Generator) MarshalCycloneDX(doc *Document) ([]byte, error) {
	cdx := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"version":      1,
		"serialNumber": fmt.Sprintf("urn:uuid:%s", doc.ProductID),
		"metadata": map[string]any{
			"timestamp": doc.GeneratedAt.Format(time.RFC3339),
			"tools": []map[string]any{
				{"vendor": g.vendor, "name": "mxcwpp-vex", "version": "1.0"},
			},
			"component": map[string]any{
				"type":    "application",
				"name":    doc.ProductName,
				"version": doc.ProductVer,
				"bom-ref": doc.ProductID,
			},
		},
		"vulnerabilities": buildCycloneDXVulns(doc),
	}
	return json.MarshalIndent(cdx, "", "  ")
}

func buildCycloneDXVulns(doc *Document) []map[string]any {
	out := make([]map[string]any, 0, len(doc.Statements))
	for _, s := range doc.Statements {
		entry := map[string]any{
			"id":     s.CVE,
			"source": map[string]any{"name": "NVD"},
			"analysis": map[string]any{
				"state":         mapStateCDX(s.Status),
				"justification": string(s.Justification),
				"detail":        s.ImpactStatement,
				"response":      []string{},
			},
			"affects": []map[string]any{
				{"ref": doc.ProductID},
			},
		}
		if s.ActionStatement != "" {
			entry["analysis"].(map[string]any)["response"] = []string{s.ActionStatement}
		}
		out = append(out, entry)
	}
	return out
}

func mapStateCDX(s Status) string {
	switch s {
	case StatusNotAffected:
		return "not_affected"
	case StatusAffected:
		return "exploitable"
	case StatusFixed:
		return "resolved"
	}
	return "in_triage"
}

// MarshalCSAF 输出 CSAF 2.0 JSON.
func (g *Generator) MarshalCSAF(doc *Document) ([]byte, error) {
	csaf := map[string]any{
		"document": map[string]any{
			"category":     "csaf_vex",
			"csaf_version": "2.0",
			"distribution": map[string]any{"tlp": map[string]any{"label": "WHITE"}},
			"title":        fmt.Sprintf("%s %s VEX", doc.ProductName, doc.ProductVer),
			"publisher": map[string]any{
				"category":  "vendor",
				"name":      g.vendor,
				"namespace": "https://mxcwpp.example.com",
			},
			"tracking": map[string]any{
				"id":                   doc.ProductID + "-vex",
				"initial_release_date": doc.GeneratedAt.Format(time.RFC3339),
				"current_release_date": doc.GeneratedAt.Format(time.RFC3339),
				"status":               "final",
				"version":              "1.0.0",
			},
		},
		"product_tree": map[string]any{
			"branches": []map[string]any{
				{
					"category": "vendor", "name": g.vendor,
					"branches": []map[string]any{
						{"category": "product_name", "name": doc.ProductName,
							"product": map[string]any{
								"product_id": doc.ProductID,
								"name":       doc.ProductName + " " + doc.ProductVer,
							}},
					},
				},
			},
		},
		"vulnerabilities": buildCSAFVulns(doc),
	}
	return json.MarshalIndent(csaf, "", "  ")
}

func buildCSAFVulns(doc *Document) []map[string]any {
	out := make([]map[string]any, 0, len(doc.Statements))
	for _, s := range doc.Statements {
		v := map[string]any{
			"cve": s.CVE,
			"product_status": map[string]any{
				mapStateCSAF(s.Status): []string{doc.ProductID},
			},
			"flags": []map[string]any{},
		}
		if s.Status == StatusNotAffected && s.Justification != "" {
			v["flags"] = []map[string]any{
				{"label": string(s.Justification), "product_ids": []string{doc.ProductID}},
			}
		}
		out = append(out, v)
	}
	return out
}

func mapStateCSAF(s Status) string {
	switch s {
	case StatusNotAffected:
		return "known_not_affected"
	case StatusAffected:
		return "known_affected"
	case StatusFixed:
		return "fixed"
	}
	return "under_investigation"
}
