package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// UbuntuSource 拉取 Ubuntu Security Notices (USN)。
//
// API: https://ubuntu.com/security/notices.json
// 提供 USN-XXXX-Y advisory，含 OS-specific deb 包名 + 修复版本。
type UbuntuSource struct {
	client  *http.Client
	baseURL string
}

// NewUbuntuSource 构造默认配置。
func NewUbuntuSource() *UbuntuSource {
	return &UbuntuSource{
		client:  &http.Client{Timeout: 60 * time.Second},
		baseURL: "https://ubuntu.com/security",
	}
}

func (u *UbuntuSource) WithBaseURL(url string) *UbuntuSource {
	u.baseURL = url
	return u
}

func (u *UbuntuSource) WithHTTPClient(c *http.Client) *UbuntuSource {
	u.client = c
	return u
}

func (u *UbuntuSource) Name() string           { return "usn" }
func (u *UbuntuSource) Confidence() Confidence { return ConfidenceHigh }

type usnListResponse struct {
	Notices []usnNotice `json:"notices"`
	Total   int         `json:"total_results"`
	Offset  int         `json:"offset"`
	Limit   int         `json:"limit"`
}

type usnNotice struct {
	ID          string            `json:"id"` // USN-7890-1
	Title       string            `json:"title"`
	Published   string            `json:"published"`
	Summary     string            `json:"summary"`
	Description string            `json:"description"`
	Type        string            `json:"type"`
	CVEs        []string          `json:"cves"` // ["CVE-2024-1234"]
	References  []string          `json:"references"`
	Releases    map[string]usnRel `json:"releases"` // {"jammy": {...}, "noble": {...}}
	Notes       string            `json:"notes"`
}

type usnRel struct {
	Codename string            `json:"codename"`
	Version  string            `json:"version"`
	Sources  map[string]usnSrc `json:"sources"`  // 源码包修复
	Binaries map[string]usnBin `json:"binaries"` // 二进制包修复
}

type usnSrc struct {
	Version string `json:"version"` // 修复后版本
}

type usnBin struct {
	Version string `json:"version"`
}

// Fetch 实现 Source。
// USN list API 不支持 published_after，用 order=newest + 客户端按 since 过滤。
func (u *UbuntuSource) Fetch(ctx context.Context, since time.Time) ([]*Advisory, error) {
	var all []*Advisory
	offset := 0
	const limit = 20      // ubuntu.com USN API 上限为 20，超过返回 422 (HTML)
	const maxNotices = 50 // 防初次全量过载

	for collected := 0; collected < maxNotices; {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		url := fmt.Sprintf("%s/notices.json?limit=%d&offset=%d&order=newest", u.baseURL, limit, offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := u.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("USN HTTP: %w", err)
		}
		// 非 2xx 时响应体通常是 HTML 错误页，直接 JSON 解码会得到
		// "invalid character '<'"，错误信息无意义。先按状态码短路。
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("USN HTTP status %d (url=%s)", resp.StatusCode, url)
		}
		var page usnListResponse
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("USN decode: %w", err)
		}

		// USN 每条 notice 对每个 ubuntu release 都生成独立 Advisory
		stop := false
		for _, notice := range page.Notices {
			if !since.IsZero() {
				pub, _ := time.Parse(time.RFC3339, notice.Published)
				if pub.Before(since) {
					stop = true
					break
				}
			}
			for codename, rel := range notice.Releases {
				adv := u.parseNoticeForRelease(&notice, codename, &rel)
				if adv != nil {
					all = append(all, adv)
					collected++
				}
			}
		}
		if stop || len(page.Notices) < limit {
			break
		}
		offset += limit
	}
	return all, nil
}

func (u *UbuntuSource) parseNoticeForRelease(n *usnNotice, codename string, rel *usnRel) *Advisory {
	if n == nil || rel == nil || n.Type != "USN" {
		return nil
	}

	pkgFixes := make([]PkgFix, 0, len(rel.Binaries))
	for pkgName, bin := range rel.Binaries {
		if bin.Version == "" {
			continue
		}
		pkgFixes = append(pkgFixes, PkgFix{
			Name:         pkgName,
			FixedVersion: bin.Version,
		})
	}
	if len(pkgFixes) == 0 {
		// fallback: 用 source pkg
		for pkgName, src := range rel.Sources {
			if src.Version == "" {
				continue
			}
			pkgFixes = append(pkgFixes, PkgFix{
				Name:         pkgName,
				FixedVersion: src.Version,
			})
		}
	}
	if len(pkgFixes) == 0 {
		return nil
	}

	issuedAt, _ := time.Parse(time.RFC3339, n.Published)
	severity := severityFromUSNTitle(n.Title)

	var refURL string
	if len(n.References) > 0 {
		refURL = n.References[0]
	} else {
		refURL = "https://ubuntu.com/security/notices/" + n.ID
	}

	// codename → version: jammy=22.04, noble=24.04
	osMajor := ubuntuCodenameToVersion(codename)
	if osMajor == "" {
		osMajor = rel.Version
	}

	return &Advisory{
		AdvisoryID:   n.ID + "/" + codename,
		CVEIDs:       n.CVEs,
		Severity:     severity,
		Description:  firstNonEmpty(n.Summary, n.Description),
		ReferenceURL: refURL,
		IssuedAt:     issuedAt,
		UpdatedAt:    issuedAt,
		AffectedPkgs: pkgFixes,
		OSFamily:     "ubuntu",
		OSMajorVer:   osMajor,
	}
}

func severityFromUSNTitle(title string) Severity {
	lt := strings.ToLower(title)
	switch {
	case strings.Contains(lt, "critical"):
		return SeverityCritical
	case strings.Contains(lt, "high") || strings.Contains(lt, "important"):
		return SeverityHigh
	case strings.Contains(lt, "medium") || strings.Contains(lt, "moderate"):
		return SeverityMedium
	case strings.Contains(lt, "low"):
		return SeverityLow
	}
	return SeverityMedium // USN 默认 medium（保守）
}

func ubuntuCodenameToVersion(codename string) string {
	switch strings.ToLower(codename) {
	case "noble":
		return "24.04"
	case "jammy":
		return "22.04"
	case "focal":
		return "20.04"
	case "bionic":
		return "18.04"
	case "xenial":
		return "16.04"
	case "trusty":
		return "14.04"
	}
	return ""
}
