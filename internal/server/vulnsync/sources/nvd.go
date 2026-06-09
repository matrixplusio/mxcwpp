package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NVDDriver 实现 NVD JSON 2.0 API 抓取。
// 详见 https://nvd.nist.gov/developers/vulnerabilities
type NVDDriver struct {
	BaseURL string // 默认 https://services.nvd.nist.gov/rest/json/cves/2.0
	APIKey  string // 可选 (留空走无 key 6s 间隔限速)
	Client  *http.Client
}

// NewNVDDriver 构造 NVD driver。
func NewNVDDriver(baseURL, apiKey string, timeout time.Duration) *NVDDriver {
	if baseURL == "" {
		baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &NVDDriver{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client:  SharedHTTPClient(),
	}
}

func (d *NVDDriver) Name() string { return "nvd" }

func (d *NVDDriver) Fetch(ctx context.Context, since time.Time) (*FetchResult, error) {
	q := "?resultsPerPage=200"
	if !since.IsZero() {
		// NVD 接受 ISO8601 lastModStartDate / lastModEndDate (90d 窗口)
		end := time.Now().UTC()
		// 窗口最大 120 天 (NVD 文档)
		if end.Sub(since) > 90*24*time.Hour {
			since = end.Add(-90 * 24 * time.Hour)
		}
		q += "&lastModStartDate=" + since.UTC().Format(time.RFC3339)
		q += "&lastModEndDate=" + end.UTC().Format(time.RFC3339)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+q, nil)
	if err != nil {
		return nil, fmt.Errorf("nvd: new request: %w", err)
	}
	if d.APIKey != "" {
		req.Header.Set("apiKey", d.APIKey)
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nvd: api %d: %s", resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nvd: read: %w", err)
	}

	var raw struct {
		Vulnerabilities []struct {
			Cve struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							VectorString string  `json:"vectorString"`
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("nvd: unmarshal: %w", err)
	}

	res := &FetchResult{Source: "nvd", FetchedAt: time.Now()}
	for _, v := range raw.Vulnerabilities {
		adv := Advisory{
			Source:   "nvd",
			SourceID: v.Cve.ID,
			CVE:      v.Cve.ID,
			URL:      "https://nvd.nist.gov/vuln/detail/" + v.Cve.ID,
		}
		for _, dsc := range v.Cve.Descriptions {
			if dsc.Lang == "en" {
				adv.Description = dsc.Value
				adv.Title = strings.Split(dsc.Value, ".")[0]
				break
			}
		}
		if len(v.Cve.Metrics.CvssMetricV31) > 0 {
			m := v.Cve.Metrics.CvssMetricV31[0].CvssData
			adv.CVSSv3Vector = m.VectorString
			adv.CVSSv3Score = m.BaseScore
			adv.Severity = strings.ToLower(m.BaseSeverity)
		}
		if t, err := time.Parse(time.RFC3339, v.Cve.Published); err == nil {
			adv.PublishedAt = t
		}
		if t, err := time.Parse(time.RFC3339, v.Cve.LastModified); err == nil {
			adv.ModifiedAt = t
		}
		res.Advisories = append(res.Advisories, adv)
	}
	return res, nil
}

func (d *NVDDriver) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+"?resultsPerPage=1", nil)
	if err != nil {
		return err
	}
	if d.APIKey != "" {
		req.Header.Set("apiKey", d.APIKey)
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("nvd: health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("nvd: health bad status %d", resp.StatusCode)
	}
	return nil
}

var _ Driver = (*NVDDriver)(nil)
