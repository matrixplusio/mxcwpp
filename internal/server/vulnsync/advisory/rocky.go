package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/integrity"
)

// RockySource 拉取 Rocky Linux Apollo Errata API。
//
// API: https://apollo.build.resf.org/api/v3/advisories（公开 JSON）
// 提供 Rocky-specific errata（RLSA/RLBA/RLEA），含 OS-specific 包名 + 完整 NEVRA。
type RockySource struct {
	client  *http.Client
	baseURL string
	maxAdv  int
}

// NewRockySource 构造默认配置。
//
// maxAdv 默认 0 = 全量（Apollo API 累计 RLSA 数千条，但增量按 since 限制后实际拉数百）。
// 早期默认 50 仅覆盖最新一段时间，导致 Rocky 9/10 累积公告大量缺失 → 漏报。
func NewRockySource() *RockySource {
	return &RockySource{
		client:  &http.Client{Timeout: 60 * time.Second},
		baseURL: "https://apollo.build.resf.org/api/v3",
		maxAdv:  0, // 0 = unlimited
	}
}

// WithBaseURL 测试用。
func (r *RockySource) WithBaseURL(url string) *RockySource {
	r.baseURL = url
	return r
}

// WithHTTPClient 测试用。
func (r *RockySource) WithHTTPClient(c *http.Client) *RockySource {
	r.client = c
	return r
}

// WithMaxAdvisories 测试用。
func (r *RockySource) WithMaxAdvisories(n int) *RockySource {
	r.maxAdv = n
	return r
}

// Name 实现 Source。
func (r *RockySource) Name() string { return "rocky-apollo" }

// Confidence 实现 Source：Rocky errata 是 OS 厂商权威，high。
func (r *RockySource) Confidence() Confidence { return ConfidenceHigh }

// rockyResp 实际响应（与 API 结构对齐）。
type rockyResp struct {
	Advisories []rockyAdvisory `json:"advisories"`
	Page       int             `json:"page"`
	Size       int             `json:"size"`
	Total      int             `json:"total"`
}

// rockyAdvisory 单条 advisory（match 真实 schema）。
type rockyAdvisory struct {
	ID               int                    `json:"id"`
	Name             string                 `json:"name"` // RLSA-2026:19664
	Synopsis         string                 `json:"synopsis"`
	Description      string                 `json:"description"`
	Topic            string                 `json:"topic"`
	Kind             string                 `json:"kind"`     // Security / Bugfix / Enhancement
	Severity         string                 `json:"severity"` // Critical / Important / Moderate / Low
	PublishedAt      string                 `json:"published_at"`
	UpdatedAt        string                 `json:"updated_at"`
	AffectedProducts []rockyAffectedProduct `json:"affected_products"`
	CVEs             []rockyCVE             `json:"cves"`
	Packages         []rockyPackage         `json:"packages"`
}

type rockyAffectedProduct struct {
	ID           int    `json:"id"`
	Variant      string `json:"variant"` // Rocky Linux
	Name         string `json:"name"`    // Rocky Linux 8 x86_64
	MajorVersion int    `json:"major_version"`
	MinorVersion *int   `json:"minor_version"`
	Arch         string `json:"arch"` // x86_64 / aarch64 / src
}

type rockyCVE struct {
	ID          int    `json:"id"`
	CVE         string `json:"cve"`
	CVSS3Vector string `json:"cvss3_scoring_vector"`
	CVSS3Score  string `json:"cvss3_base_score"`
	CWE         string `json:"cwe"`
}

type rockyPackage struct {
	ID           int    `json:"id"`
	NEVRA        string `json:"nevra"` // kernel-rt-0:4.18.0-553.125.1.rt7.466.el8_10.src.rpm
	Checksum     string `json:"checksum"`
	ChecksumType string `json:"checksum_type"`
}

// Fetch 实现 Source。
func (r *RockySource) Fetch(ctx context.Context, since time.Time) ([]*Advisory, error) {
	var all []*Advisory
	pageNum := 1
	const pageSize = 100
	collected := 0

	for {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		url := fmt.Sprintf("%s/advisories?page=%d&size=%d", r.baseURL, pageNum, pageSize)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return all, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := DoWithBackoff(ctx, r.client, req, 3)
		if err != nil {
			return all, fmt.Errorf("Rocky errata HTTP: %w", err)
		}
		var resBody rockyResp
		decErr := json.NewDecoder(resp.Body).Decode(&resBody)
		resp.Body.Close()
		if decErr != nil {
			return all, fmt.Errorf("Rocky errata decode: %w", decErr)
		}
		if len(resBody.Advisories) == 0 {
			break
		}

		stop := false
		for _, ra := range resBody.Advisories {
			if !since.IsZero() {
				pub, _ := time.Parse(time.RFC3339, ra.PublishedAt)
				if pub.Before(since) {
					stop = true
					break
				}
			}
			adv := r.parseAdvisory(&ra)
			if adv != nil {
				all = append(all, adv)
				collected++
				// maxAdv=0 视为不限上限（全量拉取）
				if r.maxAdv > 0 && collected >= r.maxAdv {
					stop = true
					break
				}
			}
		}
		if stop || len(resBody.Advisories) < pageSize {
			break
		}
		// 切下一页（修了原本 page 变量被内层 var page rockyResp 遮蔽的 bug，
		// 当 maxAdv=0 unlimited 时旧代码会无限循环拉 page=1）
		pageNum++
	}
	return all, nil
}

func (r *RockySource) parseAdvisory(ra *rockyAdvisory) *Advisory {
	if ra == nil || !strings.EqualFold(ra.Kind, "Security") {
		return nil
	}

	// CVE + 最高 CVSS
	cveIDs := make([]string, 0, len(ra.CVEs))
	var maxScore float64
	var maxVector string
	for _, c := range ra.CVEs {
		if c.CVE != "" {
			cveIDs = append(cveIDs, c.CVE)
		}
		if s, err := strconv.ParseFloat(c.CVSS3Score, 64); err == nil && s > maxScore {
			maxScore = s
			maxVector = c.CVSS3Vector
		}
	}
	if len(cveIDs) == 0 {
		return nil
	}

	// pkg fixes（去 .src/.x86_64 等 .rpm 后缀）
	pkgFixes := make([]PkgFix, 0, len(ra.Packages))
	for _, p := range ra.Packages {
		fix := parseNEVRA(p.NEVRA)
		if fix == nil {
			continue
		}
		// 完整性：仅在上游摘要格式合法时带入下游，畸形摘要丢弃（数据损坏/篡改信号）。
		if p.Checksum != "" && integrity.ValidateChecksumFormat(p.ChecksumType, p.Checksum) == nil {
			fix.Checksum = strings.TrimSpace(p.Checksum)
			fix.ChecksumType = integrity.NormalizeChecksumType(p.ChecksumType)
		}
		pkgFixes = append(pkgFixes, *fix)
	}
	if len(pkgFixes) == 0 {
		return nil
	}

	// 主 OS（取 affected_products 第一条）
	var osMajor string
	if len(ra.AffectedProducts) > 0 {
		osMajor = strconv.Itoa(ra.AffectedProducts[0].MajorVersion)
	}

	issuedAt, _ := time.Parse(time.RFC3339, ra.PublishedAt)
	updatedAt, _ := time.Parse(time.RFC3339, ra.UpdatedAt)

	return &Advisory{
		AdvisoryID:   ra.Name,
		CVEIDs:       cveIDs,
		Severity:     normalizeRockySeverity(ra.Severity),
		CVSSScore:    maxScore,
		CVSSVector:   maxVector,
		Description:  firstNonEmpty(ra.Synopsis, ra.Topic, ra.Description),
		ReferenceURL: "https://errata.rockylinux.org/" + ra.Name,
		IssuedAt:     issuedAt,
		UpdatedAt:    updatedAt,
		AffectedPkgs: pkgFixes,
		OSFamily:     "rocky",
		OSMajorVer:   osMajor,
	}
}

// parseNEVRA 解析 Rocky packages[].nevra 如:
//
//	kernel-rt-0:4.18.0-553.125.1.rt7.466.el8_10.src.rpm  → name=kernel-rt fixed=0:4.18.0-553.125.1.rt7.466.el8_10
//	openssl-1:3.0.7-25.el9_2.x86_64.rpm                  → name=openssl fixed=1:3.0.7-25.el9_2
//
// NEVRA = Name-Epoch:Version-Release.Arch。
// `:` 严格只在 epoch 位置出现，用它定位 epoch 边界后即可拆 name vs version。
func parseNEVRA(nevra string) *PkgFix {
	s := strings.TrimSuffix(nevra, ".rpm")
	// 末尾 .arch
	lastDot := strings.LastIndex(s, ".")
	if lastDot < 0 {
		return nil
	}
	arch := s[lastDot+1:]
	if !isValidRPMArch(arch) {
		return nil
	}
	nameEvr := s[:lastDot] // kernel-rt-0:4.18.0-553.125.1.rt7.466.el8_10
	colonIdx := strings.Index(nameEvr, ":")
	if colonIdx < 0 {
		// 无 epoch，直接 dash 拆
		dashIdx := findRPMVersionDash(nameEvr)
		if dashIdx < 0 {
			return nil
		}
		return &PkgFix{Name: nameEvr[:dashIdx], Arch: arch, FixedVersion: nameEvr[dashIdx+1:]}
	}
	// 有 epoch：colon 前最后一个 dash 拆 name vs epoch
	leftOfColon := nameEvr[:colonIdx] // "kernel-rt-0"
	dashIdx := strings.LastIndex(leftOfColon, "-")
	if dashIdx < 0 {
		return nil
	}
	name := leftOfColon[:dashIdx]
	epoch := leftOfColon[dashIdx+1:]
	versionRelease := nameEvr[colonIdx+1:] // "4.18.0-553.125.1.rt7.466.el8_10"
	return &PkgFix{
		Name:         name,
		Arch:         arch,
		FixedVersion: epoch + ":" + versionRelease,
	}
}

func normalizeRockySeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "important":
		return SeverityHigh
	case "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	}
	return SeverityNone
}
