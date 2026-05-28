package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DebianSource 拉取 Debian Security Tracker JSON。
//
// API: https://security-tracker.debian.org/tracker/data/json
// 返回 {pkg_name: {cve_id: {releases: {bullseye:{status, fixed_version}, ...}}}}。
// 一次拉全量 ~150MB，按需缓存。
type DebianSource struct {
	client  *http.Client
	baseURL string
}

// NewDebianSource 构造默认配置。
func NewDebianSource() *DebianSource {
	return &DebianSource{
		client:  &http.Client{Timeout: 5 * time.Minute},
		baseURL: "https://security-tracker.debian.org/tracker",
	}
}

func (d *DebianSource) WithBaseURL(url string) *DebianSource {
	d.baseURL = url
	return d
}

func (d *DebianSource) WithHTTPClient(c *http.Client) *DebianSource {
	d.client = c
	return d
}

func (d *DebianSource) Name() string           { return "debian-tracker" }
func (d *DebianSource) Confidence() Confidence { return ConfidenceHigh }

// debianTrackerData：API 顶层结构。
// 形如:
//
//	{
//	  "openssl": {
//	    "CVE-2024-1234": {
//	      "scope": "remote",
//	      "releases": {
//	        "bullseye": {"status": "resolved", "fixed_version": "1.1.1n-0+deb11u1"},
//	        "bookworm": {"status": "resolved", "fixed_version": "3.0.11-1~deb12u1"}
//	      },
//	      "debianbug": 1234567
//	    }
//	  }
//	}
type debianTrackerData map[string]map[string]debianCVEEntry

type debianCVEEntry struct {
	Scope     string                        `json:"scope"`
	Releases  map[string]debianReleaseEntry `json:"releases"`
	DebianBug int                           `json:"debianbug,omitempty"`
}

type debianReleaseEntry struct {
	Status       string `json:"status"` // resolved / open / undetermined / not-affected
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"` // critical / high / medium / low / unimportant / not yet assigned
}

// Fetch 实现 Source。
// Debian Tracker 是全量快照，since 仅用于上层 cache。
func (d *DebianSource) Fetch(ctx context.Context, _ time.Time) ([]*Advisory, error) {
	url := d.baseURL + "/data/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Debian tracker HTTP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Debian tracker HTTP %d: %s", resp.StatusCode, body)
	}

	var data debianTrackerData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Debian tracker decode: %w", err)
	}

	return d.parseAdvisories(data), nil
}

// parseAdvisories 展开为单 CVE × release 的 Advisory 列表。
func (d *DebianSource) parseAdvisories(data debianTrackerData) []*Advisory {
	var all []*Advisory
	for pkgName, cves := range data {
		for cveID, entry := range cves {
			for codename, rel := range entry.Releases {
				if rel.Status != "resolved" || rel.FixedVersion == "" {
					// 只导出已修复的（resolved + 有 fixed_version）
					continue
				}
				osMajor := debianCodenameToVersion(codename)
				if osMajor == "" {
					continue
				}
				adv := &Advisory{
					AdvisoryID: fmt.Sprintf("DSA-%s/%s/%s", cveID, codename, pkgName),
					CVEIDs:     []string{cveID},
					Severity:   normalizeDebianUrgency(rel.Urgency),
					AffectedPkgs: []PkgFix{{
						Name:         pkgName,
						FixedVersion: rel.FixedVersion,
					}},
					OSFamily:     "debian",
					OSMajorVer:   osMajor,
					ReferenceURL: fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", cveID),
				}
				all = append(all, adv)
			}
		}
	}
	return all
}

func debianCodenameToVersion(codename string) string {
	switch strings.ToLower(codename) {
	case "trixie":
		return "13"
	case "bookworm":
		return "12"
	case "bullseye":
		return "11"
	case "buster":
		return "10"
	case "stretch":
		return "9"
	}
	return ""
}

func normalizeDebianUrgency(u string) Severity {
	switch strings.ToLower(u) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "unimportant", "end-of-life", "not yet assigned":
		return SeverityNone
	}
	return SeverityMedium
}
