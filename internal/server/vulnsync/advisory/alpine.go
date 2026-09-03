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

// AlpineSource 拉取 Alpine secdb（容器场景必备）。
//
// API: https://secdb.alpinelinux.org/{branch}/{repo}.json
// 实际拉 v3.20/main + community 等多 branch。本实现拉最近 3 个 stable branch（v3.20/v3.19/v3.18）+ main/community/edge。
type AlpineSource struct {
	client  *http.Client
	baseURL string
	maxAdv  int
}

// NewAlpineSource 构造默认。
func NewAlpineSource() *AlpineSource {
	return &AlpineSource{
		client:  &http.Client{Timeout: 60 * time.Second},
		baseURL: "https://secdb.alpinelinux.org",
		maxAdv:  2000,
	}
}

// WithBaseURL 测试。
func (a *AlpineSource) WithBaseURL(url string) *AlpineSource { a.baseURL = url; return a }

// WithHTTPClient 测试。
func (a *AlpineSource) WithHTTPClient(c *http.Client) *AlpineSource { a.client = c; return a }

// Name 实现 Source。
func (a *AlpineSource) Name() string { return "alpine" }

// Confidence 实现 Source。
func (a *AlpineSource) Confidence() Confidence { return ConfidenceHigh }

// alpineSecdb Alpine secdb JSON schema。
type alpineSecdb struct {
	APIVersion    string         `json:"apiversion"`
	Archs         []string       `json:"archs"`
	Reponame      string         `json:"reponame"`
	Urlprefix     string         `json:"urlprefix"`
	Distroversion string         `json:"distroversion"`
	Packages      []alpinePkgRef `json:"packages"`
}

type alpinePkgRef struct {
	Pkg alpinePkgFix `json:"pkg"`
}

type alpinePkgFix struct {
	Name     string              `json:"name"`
	Secfixes map[string][]string `json:"secfixes"` // {"1.2.3-r1": ["CVE-XXX","CVE-YYY"]}
}

// Fetch 实现 Source。
func (a *AlpineSource) Fetch(ctx context.Context, _ time.Time) ([]*Advisory, error) {
	branches := []string{"v3.21", "v3.20", "v3.19", "v3.18"}
	repos := []string{"main", "community"}
	var all []*Advisory
	collected := 0

	for _, branch := range branches {
		for _, repo := range repos {
			if collected >= a.maxAdv {
				return all, nil
			}
			url := fmt.Sprintf("%s/%s/%s.json", a.baseURL, branch, repo)
			secdb, err := a.fetchOne(ctx, url)
			if err != nil {
				continue
			}
			advs := a.parseSecdb(secdb, branch)
			all = append(all, advs...)
			collected += len(advs)
		}
	}
	return all, nil
}

func (a *AlpineSource) fetchOne(ctx context.Context, url string) (*alpineSecdb, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := DoWithBackoff(ctx, a.client, req, 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("alpine HTTP %d: %s", resp.StatusCode, body)
	}
	var s alpineSecdb
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("alpine decode: %w", err)
	}
	return &s, nil
}

func (a *AlpineSource) parseSecdb(secdb *alpineSecdb, branch string) []*Advisory {
	if secdb == nil {
		return nil
	}
	// 提取主版本号（v3.20 → 3.20）
	osMajor := strings.TrimPrefix(branch, "v")

	var all []*Advisory
	for _, pkgRef := range secdb.Packages {
		pkg := pkgRef.Pkg
		for fixedVer, cves := range pkg.Secfixes {
			if fixedVer == "" || len(cves) == 0 {
				continue
			}
			cveIDs := make([]string, 0, len(cves))
			for _, c := range cves {
				if strings.HasPrefix(c, "CVE-") {
					cveIDs = append(cveIDs, c)
				}
			}
			if len(cveIDs) == 0 {
				continue
			}
			all = append(all, &Advisory{
				AdvisoryID:   fmt.Sprintf("Alpine-%s-%s-%s", branch, pkg.Name, fixedVer),
				CVEIDs:       cveIDs,
				Severity:     SeverityMedium, // Alpine secdb 不带 severity
				ReferenceURL: secdb.Urlprefix + "/" + pkg.Name,
				AffectedPkgs: []PkgFix{{
					Name:         pkg.Name,
					FixedVersion: fixedVer,
				}},
				OSFamily:   "alpine",
				OSMajorVer: osMajor,
			})
		}
	}
	return all
}
