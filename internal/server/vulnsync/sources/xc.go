package sources

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 信创 4 源 (openEuler CSA / Anolis ANSA / Kylin KYSA / UOS UOSEC)
// 都采用 RSS XML feed,共用 rssDriver 基类。
//
// 详见 docs/vulnsync-design.md 信创章节。

// rssDriver 是 RSS feed 抓取的通用 driver。
type rssDriver struct {
	name   string
	url    string
	client *http.Client
}

func (d *rssDriver) Name() string { return d.name }

func (d *rssDriver) Fetch(ctx context.Context, _ time.Time) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: do: %w", d.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: api %d", d.name, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rss struct {
		Channel struct {
			Items []struct {
				Title       string `xml:"title"`
				Link        string `xml:"link"`
				Description string `xml:"description"`
				PubDate     string `xml:"pubDate"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	if err := xml.Unmarshal(body, &rss); err != nil {
		return nil, fmt.Errorf("%s: unmarshal: %w", d.name, err)
	}

	res := &FetchResult{Source: d.name, FetchedAt: time.Now()}
	for _, item := range rss.Channel.Items {
		adv := Advisory{
			Source:      d.name,
			SourceID:    item.Link, // 用 URL 作为 ID
			Title:       item.Title,
			Description: stripHTML(item.Description),
			URL:         item.Link,
			Severity:    "unknown",
		}
		// 尝试从标题提取 CVE
		if i := strings.Index(item.Title, "CVE-"); i >= 0 {
			end := i + 4
			for end < len(item.Title) && (item.Title[end] == '-' || (item.Title[end] >= '0' && item.Title[end] <= '9')) {
				end++
			}
			adv.CVE = item.Title[i:end]
			adv.SourceID = item.Title[i:end]
		}
		if t, err := time.Parse(time.RFC1123Z, item.PubDate); err == nil {
			adv.PublishedAt = t
		}
		res.Advisories = append(res.Advisories, adv)
	}
	return res, nil
}

func (d *rssDriver) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, d.url, nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// stripHTML 简单 HTML 标签剔除 (信创 RSS 经常带 HTML)。
func stripHTML(s string) string {
	var out strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

// NewOpenEulerDriver 构造 openEuler CSA RSS driver。
func NewOpenEulerDriver() *rssDriver {
	return &rssDriver{
		name:   "openeuler",
		url:    "https://www.openeuler.org/zh/security/cve/rss/",
		client: SharedHTTPClient(),
	}
}

// NewAnolisDriver 构造 Anolis ANSA driver (RSS)。
func NewAnolisDriver() *rssDriver {
	return &rssDriver{
		name:   "anolis",
		url:    "https://anas.openanolis.cn/rss",
		client: SharedHTTPClient(),
	}
}

// NewKylinDriver 构造 Kylin KYSA driver。
func NewKylinDriver() *rssDriver {
	return &rssDriver{
		name:   "kylin",
		url:    "https://www.kylinos.cn/securityadvisory/rss.xml",
		client: SharedHTTPClient(),
	}
}

// NewUOSDriver 构造 UOS (统信) UOSEC driver。
func NewUOSDriver() *rssDriver {
	return &rssDriver{
		name:   "uos",
		url:    "https://security.deepin.com/rss.xml",
		client: SharedHTTPClient(),
	}
}
