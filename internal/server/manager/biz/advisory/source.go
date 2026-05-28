// Package advisory 提供商业级 CWPP 漏洞数据多源接入。
//
// 设计原则：
//   - 仅接受 OS 厂商权威 advisory（RHSA/Rocky/USN/Debian）+ OSV PURL 精确匹配，
//     拒绝 NVD substring keyword fallback。
//   - 每个 source 独立 Fetcher + Parser + Matcher，便于单测 fixture。
//   - Coordinator 按 confidence 优先级合并：high (OS Advisory) > medium (OSV) > low (NVD CPE)。
//   - 数据真实性目标 ≥99.99%，不准的 advisory 宁可缺失也不入库。
package advisory

import (
	"context"
	"time"
)

// Confidence 漏洞数据置信度等级。
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"   // OS Advisory，OS-specific 精确版本
	ConfidenceMedium Confidence = "medium" // OSV.dev PURL match
	ConfidenceLow    Confidence = "low"    // NVD CPE 严格匹配（仅 advisory 用途）
)

// Severity 严重等级（与上游 CVSS qualitative 对齐）。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
)

// Advisory 单条漏洞 advisory，承载多源统一的最小信息集。
type Advisory struct {
	AdvisoryID   string    // 上游 advisory ID，如 RHSA-2024:1234、USN-7890-1、DSA-5678-1
	CVEIDs       []string  // 关联 CVE 列表（一个 advisory 可修复多个 CVE）
	Severity     Severity  // 上游严重等级
	CVSSScore    float64   // CVSS v3.1 score，0 表示未给出
	CVSSVector   string    // CVSS v3.1 vector string
	Description  string    // 上游描述（短）
	ReferenceURL string    // 上游详情页
	IssuedAt     time.Time // advisory 发布时间
	UpdatedAt    time.Time // advisory 最后更新时间
	AffectedPkgs []PkgFix  // 受影响包 + 修复版本（OS-specific）
	OSFamily     string    // rhel / rocky / ubuntu / debian / alpine / null（OSV 通用）
	OSMajorVer   string    // OS 主版本号，如 "9"（RHEL 9 / Rocky 9）
}

// PkgFix 单个受影响 pkg 的修复版本。
type PkgFix struct {
	Name         string // OS 实际 pkg 名（如 openssl-libs，含 -libs/-devel 子包）
	Arch         string // amd64 / arm64 / noarch / src，空表示通用
	FixedVersion string // 已修复版本号（OS 实际 erratum 版本，如 "1:3.5.5-1.el9_4"）
	Module       string // RHEL Module Stream（如 "perl:5.32"），通常空
}

// Source 单一漏洞数据源契约。
//
// 实现方负责：
//  1. 从上游拉取 advisory 列表（增量优先）
//  2. 解析成统一 Advisory 结构
//  3. 处理速率限制 / 缓存 / 重试
type Source interface {
	// Name 数据源标识，写入 vuln.source 字段：rhsa / rocky-sig / usn / debian-tracker / osv。
	Name() string

	// Confidence 该源产出 vuln 的置信度等级。
	Confidence() Confidence

	// Fetch 拉取 since 之后的 advisory（增量）。since 为零值时全量拉取。
	// 实现需保证返回的 advisory 按 IssuedAt 升序，调用方据此设置 watermark。
	Fetch(ctx context.Context, since time.Time) ([]*Advisory, error)
}

// HostSoftware 单台主机的已装软件清单条目，供 Matcher 比对。
type HostSoftware struct {
	HostID   string
	Hostname string
	IP       string
	OSFamily string // rhel / rocky / centos / ubuntu / debian / alpine / null
	OSVer    string // 完整版本，如 "9.4"
	OSMajor  string // 主版本，如 "9"
	Arch     string // amd64 / arm64
	PkgName  string // 已装 pkg 名（须与 Advisory.AffectedPkgs[].Name 精确匹配）
	PkgArch  string // 已装 pkg arch
	PkgVer   string // 已装版本号（含 epoch:version-release.dist，如 "1:3.5.1-3.el9"）
	PURL     string // package URL，如 pkg:rpm/redhat/openssl@3.5.1-3.el9?arch=x86_64
}

// Matcher 将 advisory 与已装软件做精确版本比对，输出受影响 host 列表。
//
// 比对约定：
//   - OS 必须完全匹配：advisory.OSFamily/OSMajorVer == host.OSFamily/OSMajor
//   - pkg 名 + arch 完全匹配
//   - 已装版本 < advisory.FixedVersion → affected
//   - 已装版本 ≥ advisory.FixedVersion → 已修复，跳过
type Matcher interface {
	Match(adv *Advisory, hosts []HostSoftware) []AffectedHost
}

// AffectedHost 单条 advisory × host 的受影响判定结果。
type AffectedHost struct {
	HostID       string
	PkgName      string
	InstalledVer string
	FixedVersion string
	NeedsUpdate  bool // false 表示已修复（用于上报"已 patched"状态翻转）
}
