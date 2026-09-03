// Package ti 实现 STIX/TAXII 2.x 威胁情报订阅 (P2-6)。
//
// ref/03-检测引擎 M2-P2-3: 多源威胁情报订阅。
//
// TAXII 2.x (Trusted Automated eXchange of Indicator Information):
//   - REST API 标准 (https://docs.oasis-open.org/cti/taxii/v2.1/)
//   - Endpoints:
//     GET /taxii2/                — Discovery
//     GET /api/collections/        — 列 collection
//     GET /api/collections/<id>/objects/ — 拉 STIX objects
//
// STIX 2.x: JSON 序列化的威胁情报对象 (Indicator/Malware/Campaign/...).
//
// 兼容源:
//   - MITRE CTI (mitre.org/data)
//   - 微步在线 ThreatBook (threatbook.cn API)
//   - 奇安信 TI (ti.qianxin.com)
//   - AlienVault OTX (otx.alienvault.com)
//   - VirusTotal Premium (vt.com)
package ti

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Source TAXII 源配置.
type Source struct {
	Name         string            `json:"name"`          // mitre / threatbook / qianxin / otx / vt
	BaseURL      string            `json:"base_url"`      // https://cti-taxii.mitre.org
	APIRoot      string            `json:"api_root"`      // /stix/
	CollectionID string            `json:"collection_id"` // 95ecc380-afe9-11e4-9b6c-751b66dd541e
	Headers      map[string]string `json:"headers"`       // Authorization 等
	PollInterval time.Duration     `json:"poll_interval"` // 默认 1h
}

// Client TAXII 2.x 客户端.
type Client struct {
	source Source
	http   *http.Client
	logger *zap.Logger
}

// NewClient 构造.
func NewClient(source Source, logger *zap.Logger) *Client {
	if logger == nil {
		logger = zap.NewNop()
	}
	if source.PollInterval <= 0 {
		source.PollInterval = time.Hour
	}
	return &Client{
		source: source,
		http:   &http.Client{Timeout: 60 * time.Second},
		logger: logger,
	}
}

// Discover 调 /taxii2/ 拿可用 API roots.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	var d Discovery
	if err := c.getJSON(ctx, "/taxii2/", &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ListCollections 列指定 api_root 下 collection.
func (c *Client) ListCollections(ctx context.Context, apiRoot string) (*Collections, error) {
	var cl Collections
	if err := c.getJSON(ctx, strings.TrimRight(apiRoot, "/")+"/collections/", &cl); err != nil {
		return nil, err
	}
	return &cl, nil
}

// FetchObjects 拉 collection 下 STIX objects (since 增量).
//
// since 留空表示全量初次拉取.
func (c *Client) FetchObjects(ctx context.Context, since string) (*ObjectEnvelope, error) {
	path := fmt.Sprintf("%s/collections/%s/objects/",
		strings.TrimRight(c.source.APIRoot, "/"), c.source.CollectionID)
	if since != "" {
		path += "?added_after=" + since
	}
	var env ObjectEnvelope
	if err := c.getJSON(ctx, path, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	url := strings.TrimRight(c.source.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/taxii+json;version=2.1")
	for k, v := range c.source.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("taxii get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("taxii status %d: %s", resp.StatusCode, string(body))
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("taxii decode: %w", err)
	}
	return nil
}

// ============ STIX 2.x objects (subset) ============

// Discovery TAXII 服务发现响应.
type Discovery struct {
	Title    string   `json:"title"`
	APIRoots []string `json:"api_roots"`
	Default  string   `json:"default,omitempty"`
}

// Collections collection 列表.
type Collections struct {
	Collections []Collection `json:"collections"`
}

// Collection 单 collection.
type Collection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	MediaTypes  []string `json:"media_types"`
}

// ObjectEnvelope STIX objects envelope.
type ObjectEnvelope struct {
	More    bool         `json:"more"`
	Next    string       `json:"next,omitempty"`
	Objects []StixObject `json:"objects"`
}

// StixObject 通用 STIX 对象 (subset, 仅取我们关心的字段).
type StixObject struct {
	Type     string `json:"type"` // indicator / malware / threat-actor / attack-pattern / ...
	ID       string `json:"id"`   // 例 indicator--abc-...
	Created  string `json:"created"`
	Modified string `json:"modified"`
	// Indicator 特有
	Pattern     string   `json:"pattern,omitempty"`      // [file:hashes.'SHA-256' = 'xxx'] 等
	PatternType string   `json:"pattern_type,omitempty"` // stix / pcre / sigma / snort
	ValidFrom   string   `json:"valid_from,omitempty"`
	Labels      []string `json:"labels,omitempty"` // malicious-activity / suspicious-activity
	// Malware 特有
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	IsFamily    bool     `json:"is_family,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	// 通用
	ExternalRefs []ExternalRef `json:"external_references,omitempty"`
}

// ExternalRef CVE/CWE 等外部引用.
type ExternalRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url,omitempty"`
}

// IOC 从 STIX Indicator pattern 提取的简化 IOC.
//
// 仅识别最常见的 SHA-256/MD5/SHA-1/domain-name/ipv4-addr/url pattern.
type IOC struct {
	Kind   string // hash_sha256 / hash_md5 / hash_sha1 / domain / ipv4 / url
	Value  string
	Label  string // malicious-activity / suspicious-activity
	StixID string
}

// ExtractIOCs 把 STIX object 列表转为简化 IOC.
//
// 不识别的 pattern 跳过 (返回的 IOC 数 ≤ 输入对象数).
func ExtractIOCs(objects []StixObject) []IOC {
	var out []IOC
	for _, o := range objects {
		if o.Type != "indicator" || o.Pattern == "" {
			continue
		}
		label := ""
		if len(o.Labels) > 0 {
			label = o.Labels[0]
		}
		kind, value := parsePattern(o.Pattern)
		if kind == "" || value == "" {
			continue
		}
		out = append(out, IOC{
			Kind: kind, Value: value, Label: label, StixID: o.ID,
		})
	}
	return out
}

// parsePattern 简单解析 STIX pattern.
//
// 支持:
//
//	[file:hashes.'SHA-256' = 'xxx']
//	[file:hashes.'MD5' = 'xxx']
//	[file:hashes.'SHA-1' = 'xxx']
//	[domain-name:value = 'xxx']
//	[ipv4-addr:value = 'xxx']
//	[url:value = 'xxx']
//
// 不支持 AND/OR/FOLLOWEDBY 等复合 (留 M2).
func parsePattern(p string) (kind, value string) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "[")
	p = strings.TrimSuffix(p, "]")
	// 切 = 两侧
	parts := strings.SplitN(p, "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	// 去掉两侧单引号
	right = strings.Trim(right, "'\"")
	switch {
	case strings.Contains(left, "file:hashes.'SHA-256'"), strings.Contains(left, "file:hashes.SHA-256"):
		return "hash_sha256", right
	case strings.Contains(left, "file:hashes.'MD5'"), strings.Contains(left, "file:hashes.MD5"):
		return "hash_md5", right
	case strings.Contains(left, "file:hashes.'SHA-1'"), strings.Contains(left, "file:hashes.SHA-1"):
		return "hash_sha1", right
	case strings.Contains(left, "domain-name:value"):
		return "domain", right
	case strings.Contains(left, "ipv4-addr:value"):
		return "ipv4", right
	case strings.Contains(left, "ipv6-addr:value"):
		return "ipv6", right
	case strings.Contains(left, "url:value"):
		return "url", right
	}
	return "", ""
}
