// Package sbom 实现 SBOM CycloneDX 1.5 生成 (P2-4)。
//
// ref/06-漏洞 MVP P0-3: SBOM CycloneDX 标准 + 漏洞关联。
//
// CycloneDX 是工业级 SBOM 格式 (OWASP 维护), 主流 SCA/SAST 工具 (Trivy/Grype/
// Snyk/Dependency-Track/Anchore) 都支持。
//
// 生成流程:
//
//	输入: 主机 software 表 (Agent 上报) + advisory_packages 关联
//	输出: CycloneDX JSON v1.5 (含 components + vulnerabilities)
//
// 标准: https://cyclonedx.org/specification/overview/
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Format 是 CycloneDX SBOM 的根结构 (v1.5)。
type Format struct {
	BOMFormat       string          `json:"bomFormat"`    // "CycloneDX"
	SpecVersion     string          `json:"specVersion"`  // "1.5"
	SerialNumber    string          `json:"serialNumber"` // urn:uuid:<random>
	Version         int             `json:"version"`      // 1, 2, ... (每次重新生成递增)
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Metadata SBOM 元信息。
type Metadata struct {
	Timestamp string        `json:"timestamp"` // ISO8601
	Tools     []Tool        `json:"tools,omitempty"`
	Component MainComponent `json:"component,omitempty"` // 主体 (主机/镜像)
}

// Tool 生成工具.
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MainComponent 主体描述 (主机/镜像).
type MainComponent struct {
	Type    string `json:"type"` // "operating-system" / "container" / "device"
	Name    string `json:"name"` // host_id / image_name
	Version string `json:"version,omitempty"`
}

// Component 单条软件包/库。
type Component struct {
	Type        string    `json:"type"`    // "library" / "operating-system" / "application"
	BomRef      string    `json:"bom-ref"` // 唯一 ID (PURL hash)
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	PURL        string    `json:"purl,omitempty"` // pkg:rpm/centos/openssl@1.0.2k...
	CPE         string    `json:"cpe,omitempty"`
	Hashes      []Hash    `json:"hashes,omitempty"`
	Licenses    []License `json:"licenses,omitempty"`
	Description string    `json:"description,omitempty"`
}

// Hash 包文件 hash.
type Hash struct {
	Alg     string `json:"alg"` // "SHA-256"
	Content string `json:"content"`
}

// License license.
type License struct {
	License LicenseInfo `json:"license"`
}

// LicenseInfo SPDX ID 或 name.
type LicenseInfo struct {
	ID   string `json:"id,omitempty"` // SPDX (e.g. Apache-2.0)
	Name string `json:"name,omitempty"`
}

// Vulnerability CycloneDX VEX 漏洞.
type Vulnerability struct {
	BomRef      string       `json:"bom-ref"`
	ID          string       `json:"id"` // CVE-2024-3094
	Source      Source       `json:"source"`
	Ratings     []Rating     `json:"ratings,omitempty"`
	Description string       `json:"description,omitempty"`
	Affects     []AffectsRef `json:"affects"`
}

// Source 漏洞来源.
type Source struct {
	Name string `json:"name"` // NVD / RedHat / OSV / CNNVD
	URL  string `json:"url,omitempty"`
}

// Rating CVSS 评分.
type Rating struct {
	Source   Source  `json:"source"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"` // critical/high/medium/low/info
	Method   string  `json:"method"`   // CVSSv3 / CVSSv2
	Vector   string  `json:"vector,omitempty"`
}

// AffectsRef 受影响 component.
type AffectsRef struct {
	Ref string `json:"ref"` // bom-ref of component
}

// Package 输入: 主机软件包.
type Package struct {
	Name        string // openssl
	Version     string // 1.0.2k-26.el7
	Type        string // rpm / deb / pypi / npm / maven / golang
	OS          string // centos / ubuntu / alpine / ...
	License     string
	Description string
	SHA256      string
	// 关联 CVE (主机扫描已发现)
	CVEs []CVEInfo
}

// CVEInfo 单条 CVE 关联.
type CVEInfo struct {
	ID       string // CVE-2024-3094
	Severity string
	CVSS     float64
	Source   string // nvd / redhat / openeuler
}

// Generate 生成完整 CycloneDX SBOM.
//
// hostID 主机标识 (作为 main component name)。
// osName  OS 名称 (centos/ubuntu/...).
// packages 软件包清单 (按需带 CVEs)。
func Generate(hostID, osName, osVersion string, packages []Package) *Format {
	now := time.Now().UTC().Format(time.RFC3339)
	bom := &Format{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: now,
			Tools: []Tool{
				{Vendor: "mxcwpp", Name: "mxcwpp", Version: "2.0"},
			},
			Component: MainComponent{
				Type:    "operating-system",
				Name:    hostID,
				Version: osName + " " + osVersion,
			},
		},
	}
	vulnMap := make(map[string]*Vulnerability) // CVE → vuln
	for _, p := range packages {
		comp := pkgToComponent(p, osName)
		bom.Components = append(bom.Components, comp)
		for _, cve := range p.CVEs {
			v, ok := vulnMap[cve.ID]
			if !ok {
				v = &Vulnerability{
					BomRef: "vuln-" + cve.ID,
					ID:     cve.ID,
					Source: Source{Name: defaultSourceName(cve.Source)},
					Ratings: []Rating{{
						Source:   Source{Name: defaultSourceName(cve.Source)},
						Score:    cve.CVSS,
						Severity: strings.ToLower(cve.Severity),
						Method:   "CVSSv3",
					}},
					Affects: []AffectsRef{},
				}
				vulnMap[cve.ID] = v
			}
			v.Affects = append(v.Affects, AffectsRef{Ref: comp.BomRef})
		}
	}
	for _, v := range vulnMap {
		bom.Vulnerabilities = append(bom.Vulnerabilities, *v)
	}
	return bom
}

// pkgToComponent Package → Component 转换.
func pkgToComponent(p Package, osName string) Component {
	purl := buildPURL(p, osName)
	bomRef := hashRef(purl)
	c := Component{
		Type:    "library",
		BomRef:  bomRef,
		Name:    p.Name,
		Version: p.Version,
		PURL:    purl,
	}
	if p.SHA256 != "" {
		c.Hashes = []Hash{{Alg: "SHA-256", Content: p.SHA256}}
	}
	if p.License != "" {
		c.Licenses = []License{{License: LicenseInfo{ID: p.License}}}
	}
	if p.Description != "" {
		c.Description = p.Description
	}
	return c
}

// buildPURL 标准 PURL (Package URL) 字符串.
//
// pkg:rpm/centos/openssl@1.0.2k-26.el7?arch=x86_64
// pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.13?arch=amd64
// pkg:pypi/requests@2.31.0
// pkg:npm/lodash@4.17.21
// pkg:maven/org.apache.commons/commons-text@1.10.0
// pkg:golang/github.com/foo/bar@v1.0.0
func buildPURL(p Package, osName string) string {
	switch p.Type {
	case "rpm":
		return fmt.Sprintf("pkg:rpm/%s/%s@%s", osName, p.Name, p.Version)
	case "deb":
		return fmt.Sprintf("pkg:deb/%s/%s@%s", osName, p.Name, p.Version)
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", p.Name, p.Version)
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", p.Name, p.Version)
	case "maven":
		return fmt.Sprintf("pkg:maven/%s@%s", p.Name, p.Version)
	case "golang":
		return fmt.Sprintf("pkg:golang/%s@%s", p.Name, p.Version)
	}
	return fmt.Sprintf("pkg:generic/%s@%s", p.Name, p.Version)
}

func hashRef(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func defaultSourceName(s string) string {
	if s == "" {
		return "NVD"
	}
	return strings.ToUpper(s)
}
