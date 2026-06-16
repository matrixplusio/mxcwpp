package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// UbuntuDriver 实现 Ubuntu Security Notices (USN) 抓取。
// API: https://ubuntu.com/security/notices.json
type UbuntuDriver struct {
	BaseURL string
	Client  *http.Client
}

// NewUbuntuDriver 构造 Ubuntu USN driver。
func NewUbuntuDriver() *UbuntuDriver {
	return &UbuntuDriver{
		BaseURL: "https://ubuntu.com/security/notices.json",
		Client:  SharedHTTPClient(),
	}
}

func (d *UbuntuDriver) Name() string { return "ubuntu" }

func (d *UbuntuDriver) Fetch(ctx context.Context, since time.Time) (*FetchResult, error) {
	q := "?limit=200"
	if !since.IsZero() {
		q += "&order_by=date&since=" + since.UTC().Format("2006-01-02")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+q, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ubuntu: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ubuntu: api %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var raw struct {
		Notices []struct {
			ID          string   `json:"id"`
			Title       string   `json:"title"`
			Description string   `json:"description"`
			Published   string   `json:"published"`
			CVEs        []string `json:"cves"`
			Type        string   `json:"type"`
		} `json:"notices"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	res := &FetchResult{Source: "ubuntu", FetchedAt: time.Now()}
	for _, n := range raw.Notices {
		adv := Advisory{
			Source:      "ubuntu",
			SourceID:    n.ID,
			Title:       n.Title,
			Description: n.Description,
			URL:         "https://ubuntu.com/security/" + n.ID,
		}
		if len(n.CVEs) > 0 {
			adv.CVE = n.CVEs[0]
		}
		if t, err := time.Parse(time.RFC3339, n.Published); err == nil {
			adv.PublishedAt = t
		}
		res.Advisories = append(res.Advisories, adv)
	}
	return res, nil
}

func (d *UbuntuDriver) HealthCheck(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, d.BaseURL, nil)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

var _ Driver = (*UbuntuDriver)(nil)
