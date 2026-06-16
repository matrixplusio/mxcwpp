package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AlpineDriver 实现 Alpine secdb 抓取。
// 详见 https://secdb.alpinelinux.org/
//
// secdb 按 branch (edge/v3.18/v3.19/...) 分文件,
// 这里使用 main branch (community) 作为示例。
type AlpineDriver struct {
	BaseURL string // 默认 https://secdb.alpinelinux.org
	Branch  string // 默认 v3.19
	Client  *http.Client
}

// NewAlpineDriver 构造 Alpine driver。HTTP 走共享连接池（SharedHTTPClient）。
func NewAlpineDriver(branch string) *AlpineDriver {
	if branch == "" {
		branch = "v3.19"
	}
	return &AlpineDriver{
		BaseURL: "https://secdb.alpinelinux.org",
		Branch:  branch,
		Client:  SharedHTTPClient(),
	}
}

func (d *AlpineDriver) Name() string { return "alpine" }

func (d *AlpineDriver) Fetch(ctx context.Context, _ time.Time) (*FetchResult, error) {
	url := fmt.Sprintf("%s/%s/main.json", d.BaseURL, d.Branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("alpine: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("alpine: api %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Apkurl    string   `json:"apkurl"`
		Archs     []string `json:"archs"`
		Reponame  string   `json:"reponame"`
		Urlprefix string   `json:"urlprefix"`
		Packages  []struct {
			Pkg struct {
				Name     string              `json:"name"`
				Secfixes map[string][]string `json:"secfixes"`
			} `json:"pkg"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	res := &FetchResult{Source: "alpine", FetchedAt: time.Now()}
	for _, p := range raw.Packages {
		for version, cves := range p.Pkg.Secfixes {
			for _, cve := range cves {
				res.Advisories = append(res.Advisories, Advisory{
					Source:        "alpine",
					SourceID:      cve,
					CVE:           cve,
					AffectedPURLs: []string{fmt.Sprintf("pkg:apk/alpine/%s@%s?branch=%s", p.Pkg.Name, version, d.Branch)},
					FixedVersions: []string{version},
					URL:           fmt.Sprintf("%s/%s/main/%s", d.BaseURL, d.Branch, p.Pkg.Name),
				})
			}
		}
	}
	return res, nil
}

func (d *AlpineDriver) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/%s/main.json", d.BaseURL, d.Branch)
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

var _ Driver = (*AlpineDriver)(nil)
