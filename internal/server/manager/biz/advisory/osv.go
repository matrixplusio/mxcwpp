package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OSVSource osv.dev 数据源。
//
// 与 OS 厂商 advisory 不同，OSV 是按 PURL 查询的语言包漏洞库。
// 因此 Fetch（time-incremental）实现为空，真实查询走 FetchByPURLs（PURLSource 路径）。
//
// 上游 API:
//
//	POST /v1/querybatch        → 按 PURL 批量查 vuln IDs
//	GET  /v1/vulns/{id}        → 取详情（含 CVSS / aliases / affected ranges / refs）
//
// 内置能力（与 vuln_scanner.queryBatch 等价）：
//   - OSS-Fuzz ID (OSV-YYYY-N) 过滤：crash 记录非 CVE，入库会污染 vuln 表
//   - 跨批 detailCache：同一 vuln 多 PURL 命中只 fetch 一次
//   - knownVulnIDs skip：调用方传入已知 ID 集合，跳过 detail fetch
//   - CVSS v3.1 真实 base score 解析
//   - DetailCache 注入：支持 None/PreferOnline/OfflineOnly 三种缓存策略
type OSVSource struct {
	client        *http.Client
	baseURL       string
	cache         DetailCache
	cacheStrategy CacheStrategy
	batchSize     int
	detailConcur  int

	// knownVulnIDs 注入：已入库的 vuln ID 集合，跳过 detail fetch（加速 ScanAll）。
	// nil 表示不做 skip，每个 ID 都 fetch 详情。
	knownVulnIDs map[string]struct{}
}

// NewOSVSource 构造默认配置。
func NewOSVSource() *OSVSource {
	return &OSVSource{
		client:        &http.Client{Timeout: 60 * time.Second},
		baseURL:       "https://api.osv.dev",
		cacheStrategy: CacheStrategyNone,
		batchSize:     100, // OSV 单批最多 1000，保守 100 防超时
		detailConcur:  16,
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

// WithCache 注入详情缓存。strategy=CacheStrategyNone 等价不缓存。
func (o *OSVSource) WithCache(cache DetailCache, strategy CacheStrategy) *OSVSource {
	o.cache = cache
	o.cacheStrategy = strategy
	return o
}

// WithKnownVulnIDs 注入已入库 vuln ID 集合，FetchByPURLs 跳过它们的 detail HTTP。
func (o *OSVSource) WithKnownVulnIDs(ids map[string]struct{}) *OSVSource {
	o.knownVulnIDs = ids
	return o
}

// WithBatchSize 设置 querybatch 批大小（默认 100）。
func (o *OSVSource) WithBatchSize(n int) *OSVSource {
	if n > 0 {
		o.batchSize = n
	}
	return o
}

// WithDetailConcurrency 设置 detail GET 并发上限（默认 16）。
func (o *OSVSource) WithDetailConcurrency(n int) *OSVSource {
	if n > 0 {
		o.detailConcur = n
	}
	return o
}

// Name 实现 Source。
func (o *OSVSource) Name() string { return "osv" }

// Confidence 实现 Source。
func (o *OSVSource) Confidence() Confidence { return ConfidenceMedium }

// Fetch 实现 Source。OSV 走 PURL 模式，time-incremental 模式无意义，直接返空。
// 真实数据走 FetchByPURLs（由 Coordinator.SyncByPURLs 调用）。
func (o *OSVSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) {
	return nil, nil
}

// purlVulnHit 单个 PURL 命中的 OSV vuln ID 列表。
type purlVulnHit struct {
	purl    string
	vulnIDs []string
}

// FetchByPURLs 实现 PURLSource。
//
// 流程：
//  1. 按 batchSize 分批 POST querybatch 拿 vuln ID 列表（含 OSS-Fuzz 过滤）
//  2. 分离新 ID vs 已知 ID（按 knownVulnIDs）；已知跳过 detail
//  3. 并发 GET 新 ID detail（detailConcur 控制并发；cache 命中则跳 HTTP）
//  4. 把 detail × PURL 拼成 Advisory 返回（含 OsvID/PURL/CVSS/AttackVector 等完整字段）
//
// 已知 ID 仍返回（但 advisory 仅含 ID/PURL，无 detail），Coordinator 据此关联 host_vuln。
func (o *OSVSource) FetchByPURLs(ctx context.Context, purls []string) (map[string][]*Advisory, error) {
	if len(purls) == 0 {
		return nil, nil
	}

	var allHits []purlVulnHit
	for start := 0; start < len(purls); start += o.batchSize {
		end := start + o.batchSize
		if end > len(purls) {
			end = len(purls)
		}
		batch := purls[start:end]
		hits, err := o.queryBatchOnce(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("OSV querybatch (offset=%d): %w", start, err)
		}
		allHits = append(allHits, hits...)
	}

	// 收集所有需 fetch detail 的 ID
	needDetail := make(map[string]struct{})
	for _, h := range allHits {
		for _, id := range h.vulnIDs {
			if o.knownVulnIDs != nil {
				if _, known := o.knownVulnIDs[id]; known {
					continue
				}
			}
			needDetail[id] = struct{}{}
		}
	}
	detailIDs := make([]string, 0, len(needDetail))
	for id := range needDetail {
		detailIDs = append(detailIDs, id)
	}
	detailMap := o.fetchDetailsConcurrent(ctx, detailIDs)

	// 拼装结果
	out := make(map[string][]*Advisory)
	for _, h := range allHits {
		for _, id := range h.vulnIDs {
			if d, ok := detailMap[id]; ok {
				adv := o.detailToAdvisory(d, h.purl)
				if adv != nil {
					out[h.purl] = append(out[h.purl], adv)
				}
				continue
			}
			// 已知 ID：仅塞 minimal advisory 让 Coordinator 走 host 关联路径
			if o.knownVulnIDs != nil {
				if _, known := o.knownVulnIDs[id]; known {
					out[h.purl] = append(out[h.purl], &Advisory{
						AdvisoryID: id,
						OsvID:      id,
						PURL:       h.purl,
						Ecosystem:  purlEcosystem(h.purl),
						// 由 Coordinator 复用既有 vulnerabilities 行数据
					})
				}
			}
		}
	}
	return out, nil
}

// queryBatchOnce 单批 POST /v1/querybatch，返回每个 PURL 命中的 vuln ID 列表（OSS-Fuzz 已过滤）。
func (o *OSVSource) queryBatchOnce(ctx context.Context, purls []string) ([]purlVulnHit, error) {
	type qbReq struct {
		Queries []struct {
			Package struct {
				PURL string `json:"purl"`
			} `json:"package"`
		} `json:"queries"`
	}
	var req qbReq
	req.Queries = make([]struct {
		Package struct {
			PURL string `json:"purl"`
		} `json:"package"`
	}, len(purls))
	for i, p := range purls {
		req.Queries[i].Package.PURL = p
	}
	body, _ := json.Marshal(req)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", UserAgent)

	resp, err := DoWithBackoff(ctx, o.client, httpReq, 3)
	if err != nil {
		return nil, fmt.Errorf("querybatch HTTP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("querybatch HTTP %d: %s", resp.StatusCode, raw)
	}

	type qbResp struct {
		Results []struct {
			Vulns []struct {
				ID       string `json:"id"`
				Modified string `json:"modified"`
			} `json:"vulns"`
		} `json:"results"`
	}
	var qr qbResp
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return nil, fmt.Errorf("querybatch decode: %w", err)
	}

	hits := make([]purlVulnHit, 0, len(qr.Results))
	for i, r := range qr.Results {
		if i >= len(purls) {
			break
		}
		ids := make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			if isOSSFuzzID(v.ID) {
				continue
			}
			ids = append(ids, v.ID)
		}
		if len(ids) > 0 {
			hits = append(hits, purlVulnHit{purl: purls[i], vulnIDs: ids})
		}
	}
	return hits, nil
}

// fetchDetailsConcurrent 并发取 vuln detail，detailConcur 控制并发。
// 已注入 cache 时按 cacheStrategy 决定走 cache / API。
func (o *OSVSource) fetchDetailsConcurrent(ctx context.Context, ids []string) map[string]*osvDetailRaw {
	out := make(map[string]*osvDetailRaw, len(ids))
	if len(ids) == 0 {
		return out
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, o.detailConcur)

	for _, id := range ids {
		wg.Add(1)
		go func(vid string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d, err := o.fetchVulnDetail(ctx, vid)
			if err != nil || d == nil {
				return
			}
			mu.Lock()
			out[vid] = d
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

// fetchVulnDetail 取单个 vuln detail，按 cacheStrategy 走 cache / API。
func (o *OSVSource) fetchVulnDetail(ctx context.Context, id string) (*osvDetailRaw, error) {
	// 1. cache 优先（非 None）
	if o.cache != nil && o.cacheStrategy != CacheStrategyNone {
		if raw, ok := o.cache.Get(id); ok {
			var d osvDetailRaw
			if err := json.Unmarshal(raw, &d); err == nil {
				return &d, nil
			}
		}
	}
	// 2. OfflineOnly 缓存未命中报错
	if o.cacheStrategy == CacheStrategyOfflineOnly {
		return nil, fmt.Errorf("offline cache miss: %s", id)
	}

	// 3. 调上游 API
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := DoWithBackoff(ctx, o.client, req, 3)
	if err != nil {
		// PreferOnline + API 失败：回退过期 cache
		if o.cacheStrategy == CacheStrategyPreferOnline && o.cache != nil {
			if raw, ok := o.cache.GetIncludeExpired(id); ok {
				var d osvDetailRaw
				if json.Unmarshal(raw, &d) == nil {
					return &d, nil
				}
			}
		}
		return nil, fmt.Errorf("vuln detail HTTP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln detail HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vuln detail read: %w", err)
	}
	var d osvDetailRaw
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("vuln detail decode: %w", err)
	}
	if o.cache != nil {
		o.cache.Put(id, raw)
	}
	return &d, nil
}

// osvDetailRaw OSV /v1/vulns/{id} 响应结构（保留与上游一致字段，便于将来扩展）。
type osvDetailRaw struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Details   string `json:"details"`
	Aliases   []string
	Modified  string `json:"modified"`
	Published string `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// detailToAdvisory 把 OSV detail × PURL 拼成 Advisory，含完整字段。
func (o *OSVSource) detailToAdvisory(d *osvDetailRaw, purl string) *Advisory {
	if d == nil {
		return nil
	}

	// CVE 列表
	cveIDs := make([]string, 0, len(d.Aliases))
	for _, a := range d.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			cveIDs = append(cveIDs, a)
		}
	}

	// CVSS：取最高 v3 score
	var cvssScore float64
	var cvssVector string
	for _, s := range d.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V31" {
			sc := parseCVSSv3Vector(s.Score)
			if sc > cvssScore {
				cvssScore = sc
				cvssVector = s.Score
			}
		}
	}
	severity := scoreToSeverityMid(cvssScore)
	attackVector, vulnType := classifyFromCVSSVectorBasic(cvssVector)

	// fixed version：取与 PURL 匹配的 affected 段第一个 fixed event
	wantPkg := purlPkgName(purl)
	wantEco := purlEcosystem(purl)
	var fixedVer, affectedVer string
	for _, a := range d.Affected {
		if wantPkg != "" && a.Package.Name != wantPkg {
			continue
		}
		if wantEco != "" && a.Package.Ecosystem != wantEco {
			continue
		}
		for _, rng := range a.Ranges {
			var intro, fix string
			for _, ev := range rng.Events {
				if ev.Introduced != "" && ev.Introduced != "0" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					fix = ev.Fixed
				}
			}
			if fix != "" && fixedVer == "" {
				fixedVer = fix
			}
			switch {
			case fix != "" && intro != "":
				affectedVer = ">= " + intro + ", < " + fix
			case fix != "":
				if affectedVer == "" {
					affectedVer = "< " + fix
				}
			case intro != "" && affectedVer == "":
				affectedVer = ">= " + intro
			}
		}
		if fixedVer != "" {
			break
		}
	}

	// reference URL
	var refURL string
	for _, r := range d.References {
		if r.Type == "ADVISORY" || r.Type == "WEB" {
			refURL = r.URL
			break
		}
	}
	if refURL == "" && len(d.References) > 0 {
		refURL = d.References[0].URL
	}

	issuedAt, _ := time.Parse(time.RFC3339, d.Published)
	updatedAt, _ := time.Parse(time.RFC3339, d.Modified)

	pkgName := wantPkg
	currentVer := purlVersion(purl)

	pkgs := []PkgFix{}
	if fixedVer != "" {
		pkgs = append(pkgs, PkgFix{Name: pkgName, FixedVersion: fixedVer})
	}

	return &Advisory{
		AdvisoryID:       d.ID,
		CVEIDs:           cveIDs,
		Severity:         severity,
		CVSSScore:        cvssScore,
		CVSSVector:       cvssVector,
		Description:      firstNonEmpty(d.Summary, d.Details),
		ReferenceURL:     refURL,
		IssuedAt:         issuedAt,
		UpdatedAt:        updatedAt,
		AffectedPkgs:     pkgs,
		Ecosystem:        wantEco,
		OsvID:            d.ID,
		PURL:             purl,
		AttackVector:     attackVector,
		VulnType:         vulnType,
		AffectedVersions: affectedVer,
		CurrentVersion:   currentVer,
	}
}

// ossFuzzIDPattern 识别 osv.dev OSS-Fuzz 崩溃 ID（OSV-YYYY-NNN）。
// 这类是模糊测试 crash 记录，不是 CVE，入库会污染 vulnerabilities 表（实测 G02-UAT 占 ~49% FP）。
var ossFuzzIDPattern = regexp.MustCompile(`^OSV-\d{4}-\d+$`)

func isOSSFuzzID(id string) bool {
	return ossFuzzIDPattern.MatchString(id)
}

// purlEcosystem 从 PURL 推 OSV ecosystem 名（与 OSV 上游严格相等）。
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
	case "gem":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "pub":
		return "Pub"
	case "hex":
		return "Hex"
	}
	return ""
}

// purlPkgName 从 PURL @ 前段取 pkg 名。
// pkg:maven/io.netty/netty-codec@4.1.115.Final → io.netty/netty-codec? 注：OSV Maven package.name 用 group:artifact 格式
// 故对 maven 转 group:artifact，其余直接取 last segment。
func purlPkgName(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	at := strings.Index(rest, "@")
	if at < 0 {
		return ""
	}
	beforeAt := rest[:at]
	slash := strings.Index(beforeAt, "/")
	if slash < 0 {
		return ""
	}
	pkgType := beforeAt[:slash]
	rem := beforeAt[slash+1:]
	if pkgType == "maven" {
		// group/artifact → group:artifact (OSV Maven 命名)
		if i := strings.LastIndex(rem, "/"); i >= 0 {
			return rem[:i] + ":" + rem[i+1:]
		}
		return rem
	}
	// 其他生态：取 last segment（npm/pypi/golang 等）
	if i := strings.LastIndex(rem, "/"); i >= 0 {
		return rem[i+1:]
	}
	return rem
}

// purlVersion 取 PURL @ 后段（去 ?qualifier 部分）。
func purlVersion(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	at := strings.Index(rest, "@")
	if at < 0 {
		return ""
	}
	ver := rest[at+1:]
	if q := strings.Index(ver, "?"); q >= 0 {
		ver = ver[:q]
	}
	return ver
}

// osvLanguageEcosystems 列出 OSV.dev 适合的 PURL 类型（语言包生态）。
// OS 包（rpm/deb/apk）走对应 vendor advisory（RHSA/USN/Debian-tracker/Alpine secdb），
// OSV 的 OS 数据是上游转载，覆盖不全且无 backport 语义，不应走 OSV 路径。
var osvLanguageEcosystems = map[string]bool{
	"npm":      true,
	"pypi":     true,
	"golang":   true,
	"maven":    true,
	"gem":      true,
	"cargo":    true,
	"composer": true,
	"nuget":    true,
	"pub":      true,
	"hex":      true,
	"swift":    true,
	"conan":    true,
	"cran":     true,
	"hackage":  true,
}

// IsOSVLanguagePURL 判断 PURL 是否属于 OSV 应当查询的语言包生态。
// 暴露给 biz 包用作 filter（vuln_scanner 不再维护这份列表）。
func IsOSVLanguagePURL(purl string) bool {
	if !strings.HasPrefix(purl, "pkg:") {
		return false
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return false
	}
	return osvLanguageEcosystems[rest[:slash]]
}

// FilterOSVPURLs 过滤出适合 OSV 查询的 PURL 列表（仅语言包生态）。
func FilterOSVPURLs(purls []string) []string {
	out := make([]string, 0, len(purls))
	for _, p := range purls {
		if IsOSVLanguagePURL(p) {
			out = append(out, p)
		}
	}
	return out
}
