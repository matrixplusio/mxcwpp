package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SUSEDriver 实现 SUSE Security CVE 抓取。
// API: https://www.suse.com/support/security/api/v1/sortedByVersion/
//
//	或 https://ftp.suse.com/pub/projects/security/yaml/suse-cvrf-master.yml
//
// 本 driver 使用 SUSE 的 OVAL JSON 兼容端点;
// 实际生产可能需要切换到 yaml/oval 全量 (留后续 PR 调整)。
type SUSEDriver struct {
	URL    string
	Client *http.Client
}

// NewSUSEDriver 构造 SUSE driver。
func NewSUSEDriver(timeout time.Duration) *SUSEDriver {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &SUSEDriver{
		URL:    "https://ftp.suse.com/pub/projects/security/json/suse-cvrf-cve-master.json",
		Client: SharedHTTPClient(),
	}
}

func (d *SUSEDriver) Name() string { return "suse" }

func (d *SUSEDriver) Fetch(ctx context.Context, _ time.Time) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("suse: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// 404 可能 endpoint 失效, 后续 PR 调整为 yaml 路径
		return nil, fmt.Errorf("suse: api %d (endpoint 可能需要更新, 见 docs/vulnsync-design.md)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var raw []struct {
		CVE       string  `json:"cve_id"`
		Title     string  `json:"title"`
		Score     float64 `json:"cvss_score"`
		Severity  string  `json:"severity"`
		Published string  `json:"published"`
		URL       string  `json:"url"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	res := &FetchResult{Source: "suse", FetchedAt: time.Now()}
	for _, r := range raw {
		adv := Advisory{
			Source:      "suse",
			SourceID:    r.CVE,
			CVE:         r.CVE,
			Title:       r.Title,
			Severity:    r.Severity,
			CVSSv3Score: r.Score,
			URL:         r.URL,
		}
		if t, err := time.Parse(time.RFC3339, r.Published); err == nil {
			adv.PublishedAt = t
		}
		res.Advisories = append(res.Advisories, adv)
	}
	return res, nil
}

func (d *SUSEDriver) HealthCheck(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, d.URL, nil)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

var _ Driver = (*SUSEDriver)(nil)
