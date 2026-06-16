package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OSVDriver 实现 OSV (Open Source Vulnerabilities, Google) 抓取。
// 详见 https://osv.dev/docs/
type OSVDriver struct {
	BaseURL string // https://api.osv.dev
	Client  *http.Client
}

// NewOSVDriver 构造 OSV driver。
func NewOSVDriver(baseURL string) *OSVDriver {
	if baseURL == "" {
		baseURL = "https://api.osv.dev"
	}
	return &OSVDriver{BaseURL: baseURL, Client: SharedHTTPClient()}
}

func (d *OSVDriver) Name() string { return "osv" }

// Fetch 实现增量抓取。OSV 不直接支持时间窗口查询,
// 而是按 ecosystem 拉取 vulns,这里只做按需精确 query (CVE/PURL) 的占位实现,
// 真正的批量同步建议走 osv-vulnerabilities.storage.googleapis.com (按 ecosystem 文件)。
func (d *OSVDriver) Fetch(_ context.Context, _ time.Time) (*FetchResult, error) {
	// 占位: 完整 ecosystem 拉取由 OSV bucket sync 实现 (留后续 PR)
	return &FetchResult{Source: "osv", FetchedAt: time.Now()}, nil
}

// QueryByCVE 按 CVE 单查 (在线 API)。
func (d *OSVDriver) QueryByCVE(ctx context.Context, cve string) (*Advisory, error) {
	body := fmt.Sprintf(`{"alias":"%s"}`, cve)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.BaseURL+"/v1/query", nil)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(strNewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("osv: api %d: %s", resp.StatusCode, string(raw))
	}
	var rb struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &rb); err != nil {
		return nil, err
	}
	if len(rb.Vulns) == 0 {
		return nil, nil
	}
	v := rb.Vulns[0]
	adv := &Advisory{
		Source:      "osv",
		SourceID:    v.ID,
		CVE:         cve,
		Title:       v.Summary,
		Description: v.Details,
		URL:         "https://osv.dev/vulnerability/" + v.ID,
	}
	if t, err := time.Parse(time.RFC3339, v.Modified); err == nil {
		adv.ModifiedAt = t
	}
	return adv, nil
}

func (d *OSVDriver) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+"/v1/vulns/CVE-2024-1", nil)
	if err != nil {
		return err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("osv: health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("osv: health %d", resp.StatusCode)
	}
	return nil
}

// strNewReader 私有 helper (避免 import strings 仅为 NewReader)。
type strReader struct {
	s string
	i int
}

func strNewReader(s string) *strReader { return &strReader{s: s} }
func (r *strReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

var _ Driver = (*OSVDriver)(nil)
