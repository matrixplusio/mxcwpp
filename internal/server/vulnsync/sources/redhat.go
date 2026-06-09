package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RedHatDriver 实现 RedHat Security Data API 抓取 (RHSA)。
// 详见 https://access.redhat.com/labs/securitydataapi/
type RedHatDriver struct {
	BaseURL string
	Client  *http.Client
}

// NewRedHatDriver 构造 RedHat driver。
func NewRedHatDriver(timeout time.Duration) *RedHatDriver {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &RedHatDriver{
		BaseURL: "https://access.redhat.com/hydra/rest/securitydata",
		Client:  SharedHTTPClient(),
	}
}

func (d *RedHatDriver) Name() string { return "redhat" }

func (d *RedHatDriver) Fetch(ctx context.Context, since time.Time) (*FetchResult, error) {
	q := "/cve.json?per_page=200"
	if !since.IsZero() {
		q += "&after=" + since.UTC().Format("2006-01-02")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+q, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("redhat: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("redhat: api %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var raw []struct {
		CVE                 string   `json:"CVE"`
		Severity            string   `json:"severity"`
		PublicDate          string   `json:"public_date"`
		Advisories          []string `json:"advisories"`
		BugzillaDescription string   `json:"bugzilla_description"`
		CvssScore           float64  `json:"cvss3_score"`
		CvssVector          string   `json:"cvss3_scoring_vector"`
		ResourceURL         string   `json:"resource_url"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	res := &FetchResult{Source: "redhat", FetchedAt: time.Now()}
	for _, r := range raw {
		adv := Advisory{
			Source:       "redhat",
			SourceID:     r.CVE,
			CVE:          r.CVE,
			Title:        r.BugzillaDescription,
			Severity:     r.Severity,
			CVSSv3Score:  r.CvssScore,
			CVSSv3Vector: r.CvssVector,
			URL:          r.ResourceURL,
		}
		if t, err := time.Parse("2006-01-02T15:04:05Z", r.PublicDate); err == nil {
			adv.PublishedAt = t
		}
		res.Advisories = append(res.Advisories, adv)
	}
	return res, nil
}

func (d *RedHatDriver) HealthCheck(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, d.BaseURL+"/cve.json?per_page=1", nil)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

var _ Driver = (*RedHatDriver)(nil)
