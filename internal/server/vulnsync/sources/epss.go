package sources

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// EPSSDriver 实现 FIRST.org EPSS (Exploit Prediction Scoring System) 抓取。
// 详见 https://www.first.org/epss/
// 数据源: https://epss.cyentia.com/epss_scores-current.csv.gz
type EPSSDriver struct {
	URL    string
	Client *http.Client
}

// NewEPSSDriver 构造 EPSS driver。
func NewEPSSDriver() *EPSSDriver {
	return &EPSSDriver{
		URL:    "https://epss.cyentia.com/epss_scores-current.csv",
		Client: SharedHTTPClient(),
	}
}

func (d *EPSSDriver) Name() string { return "epss" }

// Fetch 拉取 EPSS CSV 全量 (EPSS 没增量,每日刷新一次足够)。
func (d *EPSSDriver) Fetch(ctx context.Context, _ time.Time) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("epss: api %d", resp.StatusCode)
	}

	res := &FetchResult{Source: "epss", FetchedAt: time.Now()}
	rd := csv.NewReader(resp.Body)
	rd.FieldsPerRecord = -1 // CSV 列数不固定 (注释行有 1 列)

	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			res.Errors = append(res.Errors, err)
			continue
		}
		if len(rec) < 3 {
			continue
		}
		// 跳过注释行 (#model_version) 与表头行 (cve,epss,percentile)
		if strings.HasPrefix(rec[0], "#") || rec[0] == "cve" {
			continue
		}
		score, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			continue
		}
		res.Advisories = append(res.Advisories, Advisory{
			Source:    "epss",
			SourceID:  rec[0],
			CVE:       rec[0],
			EPSSScore: score,
			URL:       "https://www.first.org/epss/data/" + rec[0],
		})
	}
	return res, nil
}

func (d *EPSSDriver) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, d.URL, nil)
	if err != nil {
		return err
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("epss: health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("epss: health %d", resp.StatusCode)
	}
	return nil
}

var _ Driver = (*EPSSDriver)(nil)
