package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OSVSource 拉取 osv.dev API（Google maintained）。
//
// API: https://api.osv.dev/v1/querybatch（按 PURL 批量查询，无 keyword fallback）
//
// 与 RedHatSource 互补：OSV 覆盖跨平台软件包（npm/pypi/golang/maven），
// OS pkg 也支持但优先级低于 OS 厂商 advisory。confidence=medium。
type OSVSource struct {
	client  *http.Client
	baseURL string
}

// NewOSVSource 构造默认配置。
func NewOSVSource() *OSVSource {
	return &OSVSource{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: "https://api.osv.dev",
	}
}

// WithBaseURL 测试用：注入 mock server。
func (o *OSVSource) WithBaseURL(url string) *OSVSource {
	o.baseURL = url
	return o
}

// WithHTTPClient 测试用：注入定制 client。
func (o *OSVSource) WithHTTPClient(c *http.Client) *OSVSource {
	o.client = c
	return o
}

// Name 实现 Source。
func (o *OSVSource) Name() string { return "osv" }

// Confidence 实现 Source：OSV PURL match，medium。
func (o *OSVSource) Confidence() Confidence { return ConfidenceMedium }

// Fetch 实现 Source。
// OSV 没有"按时间增量"API，since 仅作上层 cache 提示，全量查询后由 coordinator 去重。
func (o *OSVSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	// OSV 推荐使用 PURL-based 查询而非时间增量；该 Fetch 仅返回空，
	// 真正查询走 QueryByPURLs（由 coordinator 按 host 软件清单驱动）。
	return nil, nil
}

// osvQueryBatchRequest 批量查询请求。
type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// osvQueryBatchResponse 批量响应。
type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVulnSummary `json:"vulns"`
}

type osvVulnSummary struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// osvVulnDetail 单条漏洞详情。
type osvVulnDetail struct {
	ID         string           `json:"id"`
	Summary    string           `json:"summary"`
	Details    string           `json:"details"`
	Aliases    []string         `json:"aliases"`
	Modified   string           `json:"modified"`
	Published  string           `json:"published"`
	Severity   []osvSeverityRef `json:"severity"`
	References []osvReference   `json:"references"`
	Affected   []osvAffected    `json:"affected"`
}

type osvSeverityRef struct {
	Type  string `json:"type"`  // CVSS_V3 / CVSS_V4
	Score string `json:"score"` // vector string
}

type osvReference struct {
	Type string `json:"type"` // ADVISORY / FIX / REPORT
	URL  string `json:"url"`
}

type osvAffected struct {
	Package           osvPackage      `json:"package"`
	Ranges            []osvRange      `json:"ranges"`
	Versions          []string        `json:"versions"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"` // ECOSYSTEM / SEMVER / GIT
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// QueryByPURLs 批量按 PURL 查询 osv.dev。
// 每批最多 1000 个 query（OSV 限制）。
// 返回 PURL → 受影响 advisory 列表。
func (o *OSVSource) QueryByPURLs(ctx context.Context, purls []string) (map[string][]*Advisory, error) {
	const batchSize = 1000
	result := make(map[string][]*Advisory, len(purls))

	for start := 0; start < len(purls); start += batchSize {
		end := start + batchSize
		if end > len(purls) {
			end = len(purls)
		}
		batch := purls[start:end]
		batchResult, err := o.queryBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		for k, v := range batchResult {
			result[k] = v
		}
	}
	return result, nil
}

func (o *OSVSource) queryBatch(ctx context.Context, purls []string) (map[string][]*Advisory, error) {
	req := osvQueryBatchRequest{Queries: make([]osvQuery, len(purls))}
	for i, p := range purls {
		req.Queries[i].Package.PURL = p
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OSV querybatch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV querybatch HTTP %d: %s", resp.StatusCode, raw)
	}

	var batchResp osvQueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("OSV querybatch decode: %w", err)
	}

	// querybatch 仅返回 vuln IDs；详情需单独 fetch
	result := make(map[string][]*Advisory)
	for i, qr := range batchResp.Results {
		if i >= len(purls) || len(qr.Vulns) == 0 {
			continue
		}
		purl := purls[i]
		for _, vs := range qr.Vulns {
			detail, err := o.fetchVulnDetail(ctx, vs.ID)
			if err != nil {
				continue
			}
			adv := o.parseDetail(detail, purl)
			if adv == nil {
				continue
			}
			result[purl] = append(result[purl], adv)
		}
	}
	return result, nil
}

func (o *OSVSource) fetchVulnDetail(ctx context.Context, id string) (*osvVulnDetail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		o.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV vuln detail %s HTTP %d", id, resp.StatusCode)
	}
	var d osvVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("OSV vuln detail decode: %w", err)
	}
	return &d, nil
}

// parseDetail 将 OSV detail 解析成 Advisory。
// purl 为查询时用的 PURL，确定 ecosystem + pkg name + arch。
func (o *OSVSource) parseDetail(d *osvVulnDetail, purl string) *Advisory {
	if d == nil {
		return nil
	}

	cveIDs := make([]string, 0, len(d.Aliases))
	for _, alias := range d.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveIDs = append(cveIDs, alias)
		}
	}

	cvssScore, cvssVector := highestCVSS(d.Severity)
	severity := scoreToSeverity(cvssScore)

	var refURL string
	for _, ref := range d.References {
		if ref.Type == "ADVISORY" || ref.Type == "WEB" {
			refURL = ref.URL
			break
		}
	}
	if refURL == "" && len(d.References) > 0 {
		refURL = d.References[0].URL
	}

	issuedAt, _ := time.Parse(time.RFC3339, d.Published)
	updatedAt, _ := time.Parse(time.RFC3339, d.Modified)

	// 提取 fixed version：取 PURL 匹配的 affected 段第一个 fixed event
	pkgFix := extractOSVFixedVersion(d.Affected, purl)
	var fixes []PkgFix
	if pkgFix != nil {
		fixes = []PkgFix{*pkgFix}
	}

	return &Advisory{
		AdvisoryID:   d.ID,
		CVEIDs:       cveIDs,
		Severity:     severity,
		CVSSScore:    cvssScore,
		CVSSVector:   cvssVector,
		Description:  firstNonEmpty(d.Summary, d.Details),
		ReferenceURL: refURL,
		IssuedAt:     issuedAt,
		UpdatedAt:    updatedAt,
		AffectedPkgs: fixes,
	}
}

// extractOSVFixedVersion 从 affected 段提取与 purl 匹配的 pkg 修复版本。
func extractOSVFixedVersion(affected []osvAffected, purl string) *PkgFix {
	wantPkg := purlPkgName(purl)
	wantEco := purlEcosystem(purl)

	for _, a := range affected {
		if a.Package.Name != wantPkg && wantPkg != "" {
			continue
		}
		if a.Package.Ecosystem != wantEco && wantEco != "" {
			continue
		}
		for _, rng := range a.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					return &PkgFix{
						Name:         a.Package.Name,
						FixedVersion: ev.Fixed,
					}
				}
			}
		}
	}
	return nil
}

// highestCVSS 取最高 CVSS 分数 + vector。
func highestCVSS(refs []osvSeverityRef) (float64, string) {
	var top float64
	var topVector string
	for _, r := range refs {
		score := parseCVSSBaseScore(r.Score)
		if score > top {
			top = score
			topVector = r.Score
		}
	}
	return top, topVector
}

// parseCVSSBaseScore 从 vector string 提取 base score（CVSS 不直接给数字，
// 这里采用简化策略：vector 中无 score 字段时返回 0，等 coordinator 补足）。
func parseCVSSBaseScore(_ string) float64 {
	return 0 // 由 coordinator 用 govulncheck 等工具补足
}

// scoreToSeverity CVSS 分数 → qualitative severity。
func scoreToSeverity(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityNone
}

// purlPkgName 从 PURL 提取 pkg name。
// pkg:rpm/redhat/openssl@3.5.1?arch=x86_64 → openssl
func purlPkgName(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	// rpm/redhat/openssl@3.5.1?arch=x86_64
	at := strings.Index(rest, "@")
	if at < 0 {
		return ""
	}
	beforeAt := rest[:at]
	lastSlash := strings.LastIndex(beforeAt, "/")
	if lastSlash < 0 {
		return ""
	}
	return beforeAt[lastSlash+1:]
}

// purlEcosystem 从 PURL 推导 OSV ecosystem。
func purlEcosystem(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return ""
	}
	switch rest[:slash] {
	case "rpm":
		return "Red Hat"
	case "deb":
		return "Debian"
	case "apk":
		return "Alpine"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "golang":
		return "Go"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
