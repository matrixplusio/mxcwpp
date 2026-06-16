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
//
// 匹配 gate 二选一（互斥）：
//   - OS pkg advisory（RHSA/USN/DSA/Alpine secdb 等）：OSFamily + OSMajorVer 必填，Ecosystem 留空
//   - 语言包 advisory（OSV GHSA/PyPA/govulndb 等）：Ecosystem 必填（npm/PyPI/Maven/Go/...），OSFamily 留空
//
// 两个字段全空的 advisory 无法做主机过滤，会被 validateAdvisory 拒绝。
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
	AffectedPkgs []PkgFix  // 受影响包 + 修复版本（OS-specific 或语言生态版本）
	OSFamily     string    // OS pkg advisory: rhel / rocky / ubuntu / debian / alpine；语言包 advisory 留空
	OSMajorVer   string    // OS 主版本号，如 "9"（RHEL 9 / Rocky 9）；语言包 advisory 留空
	Ecosystem    string    // 语言包 advisory: npm / PyPI / Maven / Go / RubyGems / crates.io / Packagist / NuGet / Pub / Hex；OS pkg advisory 留空

	// PURL-source 专用字段（仅 OSV 等 PURL-based source 填写）
	OsvID            string // 上游 OSV vuln ID（如 GHSA-xxx / CVE-xxx）；非 OSV 留空
	PURL             string // 触发命中的 PURL（如 pkg:maven/io.netty/netty-codec@4.1.115.Final）；非 PURL source 留空
	AttackVector     string // 攻击向量（如 "network"/"local"），由 CVSS 推导；空表示未知
	VulnType         string // 漏洞类型（如 "buffer-overflow"/"injection"），由 CVSS 推导；空表示未知
	AffectedVersions string // 影响版本范围（如 ">= 1.0, < 1.5"）；空表示未提供
	CurrentVersion   string // 命中 host 当前装的版本（PURL @ 后段）；非 PURL source 留空
}

// PkgFix 单个受影响 pkg 的修复版本。
type PkgFix struct {
	Name         string // OS 实际 pkg 名（如 openssl-libs，含 -libs/-devel 子包）
	Arch         string // amd64 / arm64 / noarch / src，空表示通用
	FixedVersion string // 已修复版本号（OS 实际 erratum 版本，如 "1:3.5.5-1.el9_4"）
	Module       string // RHEL Module Stream（如 "perl:5.32"），通常空

	// 修复包的上游摘要（批4 完整性校验）：仅当源给出且格式合法时填充。
	// 供下游在应用修复时校验 RPM，防被投毒的包冒充已修复版本。
	Checksum     string // 十六进制摘要，空表示源未提供或格式非法
	ChecksumType string // sha256 / sha512 / sha1
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

// PURLSource 是 Source 的扩展接口，描述按 PURL 批量查询能力的 source。
//
// 与 Source.Fetch 的时间增量模式不同，PURLSource 由调用方按 host 软件清单驱动，
// 上游 OSV/GHSA 等 PURL-based vuln DB 适合走这条路径（避免下载全量 advisory）。
//
// 实现者：
//   - OSVSource：osv.dev /v1/querybatch + /v1/vulns/{id}
//   - 未来 GHSA / Snyk / GitLab Sec 同类生态可实现该接口
type PURLSource interface {
	Source

	// FetchByPURLs 按 PURL 批量查询 advisory。
	//
	// purls: 已去重的 PURL 列表（调用方负责按 ecosystem 过滤）
	// 返回 PURL → 该 PURL 命中的 advisory 列表；advisory.PURL 字段填命中 PURL。
	FetchByPURLs(ctx context.Context, purls []string) (map[string][]*Advisory, error)
}

// HostSoftware 单台主机的已装软件清单条目，供 Matcher 比对。
//
// PkgEcosystem 决定走哪个 advisory gate：
//   - OS pkg（rpm/deb/apk）：PkgEcosystem 留空，走 OSFamily/OSMajor gate
//   - 语言包（npm/PyPI/Maven/Go/...）：PkgEcosystem 必填，走 ecosystem gate
//
// NEVRA(Name/Epoch/Version/Release/Arch) 比较优先级（matcher 优先级降序）：
//  1. PkgEpoch / PkgVerRaw / PkgRelease 都非空 → 严格 NEVRA 比较
//  2. 任一为空 → 退回 PkgVer 字符串 RPM-vercmp（旧路径，可能漏 epoch）
type HostSoftware struct {
	HostID       string
	Hostname     string
	IP           string
	OSFamily     string // rhel / rocky / centos / ubuntu / debian / alpine / null
	OSVer        string // 完整版本，如 "9.4"
	OSMajor      string // 主版本，如 "9"
	Arch         string // amd64 / arm64
	PkgName      string // 已装 pkg 名（须与 Advisory.AffectedPkgs[].Name 精确匹配）
	PkgArch      string // 已装 pkg arch
	PkgVer       string // 已装版本号（旧字段，保持向后兼容；新数据用下面 3 个 NEVRA 字段）
	PkgEpoch     string // RPM EPOCH（不存在则空）。NEVRA 比较关键字段
	PkgVerRaw    string // RPM VERSION（不含 epoch/release，如 "3.5.1"）
	PkgRelease   string // RPM RELEASE（如 "3.el9_4"）
	PURL         string // package URL，如 pkg:rpm/redhat/openssl@3.5.1-3.el9?arch=x86_64
	PkgEcosystem string // 语言包 ecosystem（npm/PyPI/Maven/Go/...）；OS pkg 留空
	// PkgManager 决定 matcher 用哪种版本比较算法。
	//
	//	"rpm"  → CompareRPMVersion（RHEL/Rocky/CentOS/AlmaLinux 等）
	//	"dpkg" → CompareDpkgVersion（Debian/Ubuntu）
	//	""     → 退回 RPM 算法（向后兼容）
	PkgManager string
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
