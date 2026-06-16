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

// DebianDriver 实现 Debian Security Tracker 抓取。
// JSON: https://security-tracker.debian.org/tracker/data/json
type DebianDriver struct {
	URL    string
	Client *http.Client
}

// NewDebianDriver 构造 Debian driver。
func NewDebianDriver() *DebianDriver {
	return &DebianDriver{
		URL:    "https://security-tracker.debian.org/tracker/data/json",
		Client: SharedHTTPClient(),
	}
}

func (d *DebianDriver) Name() string { return "debian" }

func (d *DebianDriver) Fetch(ctx context.Context, _ time.Time) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("debian: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("debian: api %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Debian tracker JSON: { "pkgname": { "CVE-xxx": { description, scope, releases: {...} } } }
	var raw map[string]map[string]struct {
		Description string `json:"description"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	res := &FetchResult{Source: "debian", FetchedAt: time.Now()}
	for pkg, cves := range raw {
		for cve, info := range cves {
			if !strings.HasPrefix(cve, "CVE-") {
				continue
			}
			res.Advisories = append(res.Advisories, Advisory{
				Source:        "debian",
				SourceID:      cve,
				CVE:           cve,
				Title:         info.Description,
				Description:   info.Description,
				AffectedPURLs: []string{fmt.Sprintf("pkg:deb/debian/%s", pkg)},
				URL:           "https://security-tracker.debian.org/tracker/" + cve,
			})
		}
	}
	return res, nil
}

func (d *DebianDriver) HealthCheck(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, d.URL, nil)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

var _ Driver = (*DebianDriver)(nil)
