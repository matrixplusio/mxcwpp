package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CISAKEVDriver 实现 CISA Known Exploited Vulnerabilities Catalog 抓取。
// 数据源: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
// JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
type CISAKEVDriver struct {
	URL    string
	Client *http.Client
}

// NewCISAKEVDriver 构造 KEV driver。
func NewCISAKEVDriver(timeout time.Duration) *CISAKEVDriver {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &CISAKEVDriver{
		URL:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		Client: SharedHTTPClient(),
	}
}

func (d *CISAKEVDriver) Name() string { return "cisa_kev" }

func (d *CISAKEVDriver) Fetch(ctx context.Context, _ time.Time) (*FetchResult, error) {
	// KEV 是全量 catalog,不支持增量
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("kev: new req: %w", err)
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kev: api %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kev: read: %w", err)
	}

	var raw struct {
		Vulnerabilities []struct {
			CveID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
			ShortDescription  string `json:"shortDescription"`
			RequiredAction    string `json:"requiredAction"`
			DueDate           string `json:"dueDate"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("kev: unmarshal: %w", err)
	}

	res := &FetchResult{Source: "cisa_kev", FetchedAt: time.Now()}
	for _, v := range raw.Vulnerabilities {
		adv := Advisory{
			Source:      "cisa_kev",
			SourceID:    v.CveID,
			CVE:         v.CveID,
			Title:       v.VulnerabilityName,
			Description: v.ShortDescription + " [required: " + v.RequiredAction + "]",
			KEVKnown:    true,
			Severity:    "high", // KEV 默认高危
			URL:         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog#" + v.CveID,
		}
		if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
			adv.PublishedAt = t
		}
		res.Advisories = append(res.Advisories, adv)
	}
	return res, nil
}

func (d *CISAKEVDriver) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, d.URL, nil)
	if err != nil {
		return err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("kev: health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("kev: health status %d", resp.StatusCode)
	}
	return nil
}

var _ Driver = (*CISAKEVDriver)(nil)
