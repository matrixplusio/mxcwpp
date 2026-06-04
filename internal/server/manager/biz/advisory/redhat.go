package advisory

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RedHatSource 拉取 Red Hat CSAF v2 advisory（取代旧 hydra REST，因 hydra cvrf.json 已 404）。
//
// API:
//   - index: https://access.redhat.com/security/data/csaf/v2/advisories/index.txt
//   - detail: https://access.redhat.com/security/data/csaf/v2/advisories/{yyyy}/rhsa-{yyyy}_{nnnn}.json
//
// CSAF v2 JSON 含完整 product_tree + vulnerabilities[].product_status.fixed 列表，
// fixed product 编码 OS-specific NEVRA，是 RHEL/Rocky/Alma 等同源生态精确版本来源。
type RedHatSource struct {
	client         *http.Client
	baseURL        string
	maxAdv         int                 // 单次 sync 最大处理 advisory 数；0/正常 = 不限。测试用。
	concurrency    int                 // detail 拉取并发数
	skipAdvisoryID map[string]struct{} // 调用方注入：已入库的 advisory ID，跳过 detail HTTP
}

// NewRedHatSource 构造默认配置。
//
// 默认全量拉取（无 maxAdv 上限），detail 并发 8。初次全量大约 5w 条 advisory，
// 单线程 60s timeout 顺序拉不可接受，并发 8 可压到 30 分钟级。
// 后续 sync 通过 skipAdvisoryID 跳过已入库条目，增量极快。
func NewRedHatSource() *RedHatSource {
	return &RedHatSource{
		client:      &http.Client{Timeout: 60 * time.Second},
		baseURL:     "https://access.redhat.com/security/data/csaf/v2/advisories",
		maxAdv:      0, // 0 = 无上限
		concurrency: 8,
	}
}

// WithBaseURL 测试用：注入 mock server URL。
func (r *RedHatSource) WithBaseURL(url string) *RedHatSource {
	r.baseURL = url
	return r
}

// WithHTTPClient 测试用：注入定制 client。
func (r *RedHatSource) WithHTTPClient(c *http.Client) *RedHatSource {
	r.client = c
	return r
}

// WithMaxAdvisories 测试用：限制单次拉取数量。
// 生产用默认 0（无上限），仅 unit test 用此方法切小数据集。
func (r *RedHatSource) WithMaxAdvisories(n int) *RedHatSource {
	r.maxAdv = n
	return r
}

// WithConcurrency 设置 detail 拉取并发度。
func (r *RedHatSource) WithConcurrency(n int) *RedHatSource {
	if n > 0 {
		r.concurrency = n
	}
	return r
}

// WithSkipAdvisoryIDs 注入已入库的 advisory ID 集合（如 "RHSA-2024:1234"）。
// Fetch 时跳过这些条目，避免重复 HTTP 拉取已知 advisory。
// 集合由 Coordinator 在 Sync 前预查 vulnerabilities.reference_url 提取。
func (r *RedHatSource) WithSkipAdvisoryIDs(ids map[string]struct{}) *RedHatSource {
	r.skipAdvisoryID = ids
	return r
}

// Name 实现 Source。
func (r *RedHatSource) Name() string { return "rhsa" }

// Confidence 实现 Source：RHSA 是 OS 厂商权威，high。
func (r *RedHatSource) Confidence() Confidence { return ConfidenceHigh }

// csafDoc 是 CSAF v2 顶层结构（仅解析我们需要的字段）。
type csafDoc struct {
	Document        csafDocument        `json:"document"`
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafDocument struct {
	Title    string `json:"title"`
	Tracking struct {
		ID                 string `json:"id"`
		InitialReleaseDate string `json:"initial_release_date"`
		CurrentReleaseDate string `json:"current_release_date"`
	} `json:"tracking"`
	Distribution struct {
		TLP struct {
			Label string `json:"label"`
		} `json:"tlp"`
	} `json:"distribution"`
	Notes             []csafNote `json:"notes"`
	AggregateSeverity struct {
		Text string `json:"text"` // Low / Moderate / Important / Critical
	} `json:"aggregate_severity"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches"`
}

type csafBranch struct {
	Branches []csafBranch    `json:"branches,omitempty"`
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Product  *csafProductRef `json:"product,omitempty"`
}

type csafProductRef struct {
	ProductID                   string `json:"product_id"`
	Name                        string `json:"name"`
	ProductIdentificationHelper *struct {
		PURL string `json:"purl,omitempty"`
		CPE  string `json:"cpe,omitempty"`
	} `json:"product_identification_helper,omitempty"`
}

type csafVulnerability struct {
	CVE           string            `json:"cve"`
	Scores        []csafScore       `json:"scores"`
	ProductStatus csafProductStatus `json:"product_status"`
	Remediations  []csafRemediation `json:"remediations"`
	Notes         []csafNote        `json:"notes"`
}

type csafScore struct {
	CVSSv3 struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvss_v3"`
	Products []string `json:"products"`
}

type csafProductStatus struct {
	Fixed            []string `json:"fixed,omitempty"`
	KnownAffected    []string `json:"known_affected,omitempty"`
	KnownNotAffected []string `json:"known_not_affected,omitempty"`
}

type csafRemediation struct {
	Category string   `json:"category"`
	Details  string   `json:"details"`
	URL      string   `json:"url"`
	Product  []string `json:"product_ids"`
}

// Fetch 实现 Source。
//
// 流程：
//  1. 拉 index.txt 取 advisory 路径列表
//  2. 按 since 过滤（路径含年份）
//  3. 跳过已入库 advisory（skipAdvisoryID 集合）
//  4. maxAdv > 0 时限制为最新 maxAdv 条（仅测试用）
//  5. 并发拉 CSAF detail，concurrency 个 worker
func (r *RedHatSource) Fetch(ctx context.Context, since time.Time) ([]*Advisory, error) {
	paths, err := r.fetchIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("RHSA index 拉取失败: %w", err)
	}

	filtered := filterIndexByYear(paths, since)
	filtered = r.skipKnown(filtered)
	if r.maxAdv > 0 && len(filtered) > r.maxAdv {
		filtered = filtered[len(filtered)-r.maxAdv:] // 测试用：取最新的 maxAdv 条
	}

	return r.fetchDetailsConcurrent(ctx, filtered), nil
}

// skipKnown 过滤掉已入库的 advisory 路径（按调用方注入的 skipAdvisoryID 集合）。
//
// 路径形如 "2024/rhsa-2024_1234.json"，对应 advisory ID "RHSA-2024:1234"。
// 调用方在 Sync 前预查 DB reference_url（含 errata/{id}）拿到已入库 ID 集合。
func (r *RedHatSource) skipKnown(paths []string) []string {
	if len(r.skipAdvisoryID) == 0 {
		return paths
	}
	out := paths[:0]
	for _, p := range paths {
		if _, known := r.skipAdvisoryID[advisoryIDFromPath(p)]; known {
			continue
		}
		out = append(out, p)
	}
	return out
}

// advisoryIDFromPath 从 CSAF 索引相对路径反推 advisory ID。
// "2024/rhsa-2024_1234.json" → "RHSA-2024:1234"
// "2024/rhba-2024_0987.json" → "RHBA-2024:0987"（非 RHSA，但 ID 仍可还原）
// 不能精确还原时返回空串。
func advisoryIDFromPath(path string) string {
	base := path
	if slash := strings.LastIndex(base, "/"); slash >= 0 {
		base = base[slash+1:]
	}
	base = strings.TrimSuffix(base, ".json")
	// rhsa-2024_1234 → RHSA-2024:1234
	dash := strings.Index(base, "-")
	if dash <= 0 {
		return ""
	}
	prefix := strings.ToUpper(base[:dash])
	rest := base[dash+1:]
	und := strings.Index(rest, "_")
	if und <= 0 {
		return ""
	}
	return prefix + "-" + rest[:und] + ":" + rest[und+1:]
}

// fetchDetailsConcurrent 并发拉取 detail，按 r.concurrency 控制并发度。
// 单个 detail 失败不中断整体；ctx 取消时尽快退出。
func (r *RedHatSource) fetchDetailsConcurrent(ctx context.Context, paths []string) []*Advisory {
	if len(paths) == 0 {
		return nil
	}
	conc := r.concurrency
	if conc <= 0 {
		conc = 8
	}

	pathCh := make(chan string, conc)
	resultCh := make(chan *Advisory, conc)
	var wg sync.WaitGroup

	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range pathCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				doc, err := r.fetchDetail(ctx, p)
				if err != nil {
					continue
				}
				if adv := r.parseCSAF(doc); adv != nil {
					resultCh <- adv
				}
			}
		}()
	}

	go func() {
		defer close(pathCh)
		for _, p := range paths {
			select {
			case <-ctx.Done():
				return
			case pathCh <- p:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	out := make([]*Advisory, 0, len(paths))
	for adv := range resultCh {
		out = append(out, adv)
	}
	return out
}

// fetchIndex 拉 advisory 路径索引（每行一个相对路径，如 2024/rhsa-2024_0998.json）。
func (r *RedHatSource) fetchIndex(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/index.txt", nil)
	if err != nil {
		return nil, err
	}
	resp, err := DoWithBackoff(ctx, r.client, req, 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RHSA index HTTP %d", resp.StatusCode)
	}
	var paths []string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		paths = append(paths, line)
	}
	return paths, sc.Err()
}

// fetchDetail 拉单条 CSAF JSON。
func (r *RedHatSource) fetchDetail(ctx context.Context, relPath string) (*csafDoc, error) {
	url := r.baseURL + "/" + relPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := DoWithBackoff(ctx, r.client, req, 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CSAF detail HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc csafDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("CSAF decode: %w", err)
	}
	return &doc, nil
}

// parseCSAF 将 CSAF doc 转 Advisory。
func (r *RedHatSource) parseCSAF(doc *csafDoc) *Advisory {
	if doc == nil {
		return nil
	}
	advID := doc.Document.Tracking.ID
	if !strings.HasPrefix(strings.ToUpper(advID), "RHSA") {
		return nil // 仅处理 Security Advisory，跳过 RHBA/RHEA
	}

	cveSet := map[string]struct{}{}
	pkgFixes := []PkgFix{}
	var maxScore float64
	var maxVector string
	productPURL := buildProductPURLMap(doc.ProductTree.Branches)

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE != "" {
			cveSet[vuln.CVE] = struct{}{}
		}
		for _, sc := range vuln.Scores {
			if sc.CVSSv3.BaseScore > maxScore {
				maxScore = sc.CVSSv3.BaseScore
				maxVector = sc.CVSSv3.VectorString
			}
		}
		for _, prod := range vuln.ProductStatus.Fixed {
			fix := pkgFixFromProductID(prod, productPURL)
			if fix != nil {
				pkgFixes = append(pkgFixes, *fix)
			}
		}
	}

	cveIDs := make([]string, 0, len(cveSet))
	for c := range cveSet {
		cveIDs = append(cveIDs, c)
	}
	if len(cveIDs) == 0 || len(pkgFixes) == 0 {
		return nil
	}

	issuedAt, _ := time.Parse(time.RFC3339, doc.Document.Tracking.InitialReleaseDate)
	updatedAt, _ := time.Parse(time.RFC3339, doc.Document.Tracking.CurrentReleaseDate)

	var description string
	for _, n := range doc.Document.Notes {
		if n.Category == "summary" || n.Category == "description" {
			description = n.Text
			break
		}
	}

	return &Advisory{
		AdvisoryID:   advID,
		CVEIDs:       cveIDs,
		Severity:     normalizeRHSeverity(doc.Document.AggregateSeverity.Text),
		CVSSScore:    maxScore,
		CVSSVector:   maxVector,
		Description:  description,
		ReferenceURL: "https://access.redhat.com/errata/" + advID,
		IssuedAt:     issuedAt,
		UpdatedAt:    updatedAt,
		AffectedPkgs: dedupPkgFixes(pkgFixes),
		OSFamily:     "rhel",
		OSMajorVer:   detectRHELMajorFromPkgs(pkgFixes),
	}
}

// buildProductPURLMap 走 product_tree 提取 product_id → PURL 映射。
// CSAF v2 在叶子 branches 含 product.product_identification_helper.purl。
func buildProductPURLMap(branches []csafBranch) map[string]string {
	out := map[string]string{}
	var walk func(branches []csafBranch)
	walk = func(branches []csafBranch) {
		for _, b := range branches {
			if b.Product != nil && b.Product.ProductIdentificationHelper != nil {
				if b.Product.ProductIdentificationHelper.PURL != "" {
					out[b.Product.ProductID] = b.Product.ProductIdentificationHelper.PURL
				}
			}
			if len(b.Branches) > 0 {
				walk(b.Branches)
			}
		}
	}
	walk(branches)
	return out
}

// isOCIProductID 判断 product_id 是否指向 OCI image（非 RPM 包）。
// CSAF v2 同时含 RPM advisory + container image advisory，container 的 product_id
// 形如 "...console-mce-rhel9@sha256:...amd64"，不应作为主机 pkg vuln 入库。
func isOCIProductID(prod string) bool {
	return strings.Contains(prod, "@sha256:") || strings.Contains(prod, "/")
}

// pkgFixFromProductID 从 product_id 提取 PkgFix。
//
// CSAF v2 product_id 实际编码形如:
//
//	"AppStream-9.4.0.GA:ipa-0:4.11.0-9.el9_4.src"
//
// 3 段（`:` 分隔）：
//
//	[0] product 上下文 (AppStream-9.4.0.GA)
//	[1] {name}-{epoch}  (ipa-0)
//	[2] {version}-{release}.{arch}  (4.11.0-9.el9_4.src)
//
// 解析：name=ipa, epoch=0, version=4.11.0-9.el9_4, arch=src
// 最终 FixedVersion = "0:4.11.0-9.el9_4"（含 epoch）
//
// 优先用 PURL（更精确），fallback 解析 product_id。
func pkgFixFromProductID(prod string, productPURL map[string]string) *PkgFix {
	if purl, ok := productPURL[prod]; ok {
		fix := parseRPMPurl(purl)
		if fix != nil {
			return fix
		}
		// 有 PURL 但非 rpm:（如 oci/）— 不再 fallback product_id 解析，避免 OCI image 混入
		return nil
	}
	if isOCIProductID(prod) {
		return nil
	}
	parts := strings.Split(prod, ":")
	if len(parts) < 3 {
		return nil
	}

	nameEpoch := parts[len(parts)-2]  // "ipa-0"
	verRelArch := parts[len(parts)-1] // "4.11.0-9.el9_4.src"

	// name vs epoch：从右往左找第一个 `-`，右侧是 epoch（纯数字）
	dashIdx := strings.LastIndex(nameEpoch, "-")
	if dashIdx < 0 {
		return nil
	}
	name := nameEpoch[:dashIdx]
	epoch := nameEpoch[dashIdx+1:]
	if !allDigits(epoch) {
		// 不带 epoch 段（如 "ipa"）
		name = nameEpoch
		epoch = ""
	}

	// arch 在 verRelArch 末尾 .arch
	arch := ""
	verRel := verRelArch
	if lastDot := strings.LastIndex(verRelArch, "."); lastDot > 0 {
		candidate := verRelArch[lastDot+1:]
		if isValidRPMArch(candidate) {
			arch = candidate
			verRel = verRelArch[:lastDot]
		}
	}

	fixed := verRel
	if epoch != "" {
		fixed = epoch + ":" + verRel
	}
	return &PkgFix{
		Name:         name,
		Arch:         arch,
		FixedVersion: fixed,
	}
}

// parseRPMPurl 解析 PURL 如 pkg:rpm/redhat/openssl@3.5.5-1.el9_4?arch=x86_64&epoch=1
func parseRPMPurl(purl string) *PkgFix {
	if !strings.HasPrefix(purl, "pkg:rpm/") {
		return nil
	}
	rest := strings.TrimPrefix(purl, "pkg:rpm/")
	queryIdx := strings.Index(rest, "?")
	var queryStr string
	if queryIdx > 0 {
		queryStr = rest[queryIdx+1:]
		rest = rest[:queryIdx]
	}
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return nil
	}
	left := rest[:atIdx]
	version := rest[atIdx+1:]
	lastSlash := strings.LastIndex(left, "/")
	name := left
	if lastSlash >= 0 {
		name = left[lastSlash+1:]
	}
	// query 解析 arch + epoch
	arch := ""
	epoch := ""
	for _, kv := range strings.Split(queryStr, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			switch k {
			case "arch":
				arch = v
			case "epoch":
				epoch = v
			}
		}
	}
	if epoch != "" {
		version = epoch + ":" + version
	}
	return &PkgFix{Name: name, Arch: arch, FixedVersion: version}
}

// filterIndexByYear 按 since 过滤索引路径（路径首段为年份）。
func filterIndexByYear(paths []string, since time.Time) []string {
	if since.IsZero() {
		return paths
	}
	year := since.Format("2006")
	out := paths[:0]
	for _, p := range paths {
		yearPrefix := p
		if slash := strings.Index(p, "/"); slash > 0 {
			yearPrefix = p[:slash]
		}
		if yearPrefix >= year {
			out = append(out, p)
		}
	}
	return out
}

// detectRHELMajorFromPkgs 从 PkgFix.FixedVersion 提取 OS 主版本号（基于 .elN 标签）。
func detectRHELMajorFromPkgs(fixes []PkgFix) string {
	counts := map[string]int{}
	for _, f := range fixes {
		v := f.FixedVersion
		idx := strings.Index(v, ".el")
		if idx < 0 {
			continue
		}
		rest := v[idx+3:] // 跳 .el
		ver := ""
		for _, c := range rest {
			if c >= '0' && c <= '9' {
				ver += string(c)
			} else {
				break
			}
		}
		if ver != "" {
			counts[ver]++
		}
	}
	var top string
	var topN int
	for v, n := range counts {
		if n > topN {
			top = v
			topN = n
		}
	}
	return top
}

// dedupPkgFixes 按 (name, arch, fixed_version) 去重。
func dedupPkgFixes(in []PkgFix) []PkgFix {
	seen := map[string]struct{}{}
	out := make([]PkgFix, 0, len(in))
	for _, f := range in {
		k := f.Name + "|" + f.Arch + "|" + f.FixedVersion
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}

// findRPMVersionDash 找 NAME-VERSION 分隔符（第一个 dash 后紧跟数字或 epoch）。
func findRPMVersionDash(s string) int {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '-' {
			next := s[i+1]
			if (next >= '0' && next <= '9') ||
				(i+2 < len(s) && next >= '0' && next <= '9') {
				return i
			}
		}
	}
	return -1
}

func isValidRPMArch(s string) bool {
	switch s {
	case "src", "x86_64", "aarch64", "noarch", "i686", "ppc64le", "s390x":
		return true
	}
	return false
}

func normalizeRHSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "important":
		return SeverityHigh
	case "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	}
	return SeverityNone
}
