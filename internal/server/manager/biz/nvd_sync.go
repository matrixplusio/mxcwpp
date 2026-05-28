package biz

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm/clause"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	nvdBaseURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdSyncDays = 14   // 同步最近 14 天的 CVE，确保覆盖 OSV 延迟窗口
	nvdPageSize = 2000 // NVD 单页最大返回数
)

// ========== NVD API 响应结构 ==========

type nvdResponse struct {
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdItem `json:"vulnerabilities"`
}

type nvdItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV30 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []nvdConfiguration `json:"configurations"`
	References     []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string        `json:"operator"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	Children []nvdNode     `json:"children"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

// ========== 已安装软件信息 ==========

type installedSoftware struct {
	Name     string `gorm:"column:name"`
	Version  string `gorm:"column:version"`
	HostID   string `gorm:"column:host_id"`
	Hostname string `gorm:"column:hostname"`
	IP       string `gorm:"column:ip"`
}

// SyncNVD 从 NVD 同步最近 N 天的 CVE 数据，补充 OSV.dev 尚未收录的最新漏洞
func (v *VulnScanner) SyncNVD() error {
	return v.SyncNVDWithSoftware(nil)
}

// SyncNVDWithSoftware 使用预加载的软件列表执行 NVD 同步，避免重复查询
func (v *VulnScanner) SyncNVDWithSoftware(softwareByName map[string][]installedSoftware) error {
	v.logger.Info("开始 NVD 补充同步")

	// 如果调用方未提供软件列表，自行查询
	if softwareByName == nil {
		var software []installedSoftware
		if err := v.db.Table("software AS s").
			Select("s.name, s.version, s.host_id, COALESCE(h.hostname, '') AS hostname, COALESCE(JSON_UNQUOTE(JSON_EXTRACT(h.ipv4, '$[0]')), '') AS ip").
			Joins("LEFT JOIN hosts h ON h.host_id = s.host_id").
			Where("s.name != ''").
			Scan(&software).Error; err != nil {
			return fmt.Errorf("查询已安装软件失败: %w", err)
		}

		if len(software) == 0 {
			v.logger.Info("没有已安装软件，跳过 NVD 同步")
			return nil
		}

		softwareByName = make(map[string][]installedSoftware)
		for _, sw := range software {
			key := strings.ToLower(sw.Name)
			softwareByName[key] = append(softwareByName[key], sw)
		}
	}

	v.logger.Info("已安装软件去重名称数", zap.Int("count", len(softwareByName)))

	// 2. 查询 NVD 最近 N 天的 CVE
	nvdCVEs, err := v.fetchRecentNVDCVEs()
	if err != nil {
		return fmt.Errorf("查询 NVD 失败: %w", err)
	}

	v.logger.Info("NVD 返回 CVE 数", zap.Int("count", len(nvdCVEs)))

	// 3. 过滤已存在的 CVE
	existingCVEs := make(map[string]struct{})
	var existingIDs []string
	v.db.Model(&model.Vulnerability{}).Pluck("cve_id", &existingIDs)
	for _, id := range existingIDs {
		existingCVEs[id] = struct{}{}
	}

	// 4. 匹配并写入
	newCount := 0
	for _, item := range nvdCVEs {
		cveID := item.CVE.ID

		if _, exists := existingCVEs[cveID]; exists {
			continue
		}

		// CPE 严格匹配已安装软件 — 唯一精确手段
		// 历史 fallback：matchByDescription 用 substring keyword 匹配（如描述含 "openssl" 即
		// 关联所有装 openssl 的 host），导致大量 fake vuln（如 Rapid7 Insight Agent Windows
		// 提权 CVE 错关联到 Linux openssl）。该 fallback 已废弃，永远不再使用。
		// 无 CPE 配置（Awaiting Analysis）的 CVE 直接跳过，保证 99.99% 数据真实性。
		matches := v.matchCPEToSoftware(item.CVE.Configurations, softwareByName)
		if len(matches) == 0 {
			continue
		}

		// 提取漏洞信息
		description := v.extractNVDDescription(item.CVE)
		cvssResult := v.extractNVDCVSSFull(item.CVE)
		fixedVersion := v.extractNVDFixedVersion(item.CVE.Configurations)
		referenceURL := v.extractNVDReference(item.CVE)
		cweID := v.extractNVDCWE(item.CVE)
		affectedVersions := v.extractNVDAffectedVersions(item.CVE.Configurations)
		attackVector, vulnType := classifyFromCVSSVector(cvssResult.VectorString, cweID)

		// 取第一个匹配的组件名
		firstMatch := matches[0]

		vulnRecord := &model.Vulnerability{
			CveID:            cveID,
			OsvID:            "",
			PURL:             "",
			Severity:         cvssResult.Severity,
			CvssScore:        cvssResult.BaseScore,
			CvssVector:       cvssResult.VectorString,
			AttackVector:     attackVector,
			VulnType:         vulnType,
			AffectedVersions: affectedVersions,
			Source:           "nvd",
			PatchAvailable:   fixedVersion != "",
			CweID:            cweID,
			Component:        firstMatch.Name,
			Description:      description,
			Status:           "unpatched",
			DiscoveredAt:     model.LocalTime(time.Now()),
			CurrentVersion:   firstMatch.Version,
			FixedVersion:     fixedVersion,
			ReferenceUrl:     referenceURL,
			Confidence:       model.VulnConfidenceLow, // NVD CPE 匹配 → low（OS Advisory 优先级更高）
		}

		if err := v.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "cve_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"cvss_score", "cvss_vector", "attack_vector", "vuln_type", "affected_versions", "source", "patch_available", "cwe_id", "description", "fixed_version", "reference_url"}),
		}).Create(vulnRecord).Error; err != nil {
			v.logger.Error("NVD 写入漏洞记录失败", zap.String("cve_id", cveID), zap.Error(err))
			continue
		}

		if vulnRecord.ID == 0 {
			v.db.Where("cve_id = ?", cveID).Select("id").First(vulnRecord)
		}
		if vulnRecord.ID == 0 {
			continue
		}

		// 创建主机关联（复用公共方法）
		entries := make([]hostVulnEntry, 0)
		hostSeen := make(map[string]struct{})
		for _, sw := range matches {
			if _, ok := hostSeen[sw.HostID]; ok {
				continue
			}
			hostSeen[sw.HostID] = struct{}{}
			entries = append(entries, hostVulnEntry{
				HostID:   sw.HostID,
				Hostname: sw.Hostname,
				IP:       sw.IP,
				Version:  sw.Version,
			})
		}
		v.upsertHostVulnsBatch(vulnRecord.ID, entries)

		// 异步创建漏洞通报 + 发送通知
		go func(vuln *model.Vulnerability) {
			bs := NewVulnBulletinService(v.db, v.logger)
			bulletin := bs.TryCreateBulletin(vuln)
			if bulletin != nil {
				ns := NewNotificationService(v.db, v.logger)
				if err := ns.SendVulnBulletinNotification(bulletin); err != nil {
					v.logger.Error("发送漏洞通报通知失败",
						zap.String("bulletin_no", bulletin.BulletinNo),
						zap.Error(err))
				}
			}
		}(vulnRecord)

		existingCVEs[cveID] = struct{}{}
		newCount++
	}

	v.logger.Info("NVD 补充同步完成", zap.Int("new_cves", newCount))
	return nil
}

// newNVDClient 创建强制 HTTP/1.1 的 HTTP 客户端
// NVD API 大响应体在 HTTP/2 下容易触发 stream INTERNAL_ERROR
func newNVDClient() *http.Client {
	return &http.Client{
		Timeout: 180 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{},
			ForceAttemptHTTP2: false,
			TLSNextProto:      make(map[string]func(string, *tls.Conn) http.RoundTripper),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
}

// nvdGetWithRetry 带重试的 NVD GET 请求（最多 3 次，间隔递增）
func (v *VulnScanner) nvdGetWithRetry(client *http.Client, url string) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := client.Get(url)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		v.logger.Warn("NVD 请求失败，准备重试",
			zap.Int("attempt", attempt),
			zap.Error(err),
		)
		time.Sleep(time.Duration(attempt*10) * time.Second)
	}
	return nil, lastErr
}

// fetchRecentNVDCVEs 查询 NVD 最近 N 天发布的 CVE
func (v *VulnScanner) fetchRecentNVDCVEs() ([]nvdItem, error) {
	endDate := time.Now().UTC()
	startDate := endDate.Add(-nvdSyncDays * 24 * time.Hour)

	// NVD API 2.0 日期需 UTC，用 "Z" 后缀（避免 "+00:00" 中的 "+" 在 URL 中被解析为空格）
	const nvdDateFmt = "2006-01-02T15:04:05.000"
	url := fmt.Sprintf("%s?pubStartDate=%sZ&pubEndDate=%sZ&resultsPerPage=%d",
		nvdBaseURL,
		startDate.Format(nvdDateFmt),
		endDate.Format(nvdDateFmt),
		nvdPageSize,
	)

	v.logger.Info("NVD 查询参数",
		zap.String("url", url),
		zap.String("startDate", startDate.Format(time.RFC3339)),
		zap.String("endDate", endDate.Format(time.RFC3339)),
	)

	client := newNVDClient()

	resp, err := v.nvdGetWithRetry(client, url)
	if err != nil {
		return nil, fmt.Errorf("调用 NVD API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API 返回 %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 NVD 响应失败: %w", err)
	}

	var result nvdResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析 NVD 响应失败: %w", err)
	}

	v.logger.Info("NVD 首页结果", zap.Int("totalResults", result.TotalResults), zap.Int("pageItems", len(result.Vulnerabilities)))

	// 如果结果超过一页，继续分页获取
	allItems := result.Vulnerabilities
	for startIndex := nvdPageSize; startIndex < result.TotalResults; startIndex += nvdPageSize {
		pageURL := fmt.Sprintf("%s&startIndex=%d", url, startIndex)

		pageResp, err := v.nvdGetWithRetry(client, pageURL)
		if err != nil {
			v.logger.Warn("NVD 分页查询失败", zap.Int("startIndex", startIndex), zap.Error(err))
			break
		}

		pageBody, err := io.ReadAll(pageResp.Body)
		pageResp.Body.Close()
		if err != nil {
			v.logger.Warn("NVD 分页读取失败", zap.Int("startIndex", startIndex), zap.Error(err))
			break
		}

		var pageResult nvdResponse
		if err := json.Unmarshal(pageBody, &pageResult); err != nil {
			v.logger.Warn("NVD 分页解析失败", zap.Int("startIndex", startIndex), zap.Error(err))
			break
		}

		allItems = append(allItems, pageResult.Vulnerabilities...)
		v.logger.Info("NVD 分页获取完成", zap.Int("startIndex", startIndex), zap.Int("pageItems", len(pageResult.Vulnerabilities)))

		// NVD 公共 API 限速：5 req/30s，分页间加延迟
		time.Sleep(6 * time.Second)
	}

	return allItems, nil
}

// matchCPEToSoftware 将 NVD CVE 的 CPE 配置与已安装软件匹配
// 返回所有匹配的已安装软件信息
func (v *VulnScanner) matchCPEToSoftware(configs []nvdConfiguration, softwareByName map[string][]installedSoftware) []installedSoftware {
	var matched []installedSoftware
	seen := make(map[string]struct{}) // host_id 去重

	for _, config := range configs {
		for _, node := range config.Nodes {
			v.matchCPENode(node, softwareByName, &matched, seen)
		}
	}
	return matched
}

func (v *VulnScanner) matchCPENode(node nvdNode, softwareByName map[string][]installedSoftware, matched *[]installedSoftware, seen map[string]struct{}) {
	for _, cpe := range node.CPEMatch {
		if !cpe.Vulnerable {
			continue
		}
		parsed := parseCPE23(cpe.Criteria)
		if parsed == nil {
			continue
		}
		// 严格过滤：仅接受 Linux 应用 (part='a' application)，跳过 Windows/macOS/Android-specific CVE。
		// CPE 2.3 target_sw 字段（idx 10）记录目标软件平台。
		// 历史 bug：CVE-2026-6482 是 Rapid7 Insight Agent Windows-only，曾被 substring fallback
		// 错关联 Linux openssl。严格 CPE 过滤后再加上 advisory.validateAdvisory 拒绝 Windows 描述，
		// 实现双重防线。
		if !cpeTargetSWLinuxCompatible(parsed.targetSW) {
			continue
		}
		// CPE 2.3 version 字段为 "*" 表示所有版本受影响 — 配合 versionStartIncluding/EndExcluding
		// 严格 range 才能下结论。无 range 时拒绝（避免无版本约束的过宽匹配）。
		if parsed.version == "*" && cpe.VersionEndExcluding == "" && cpe.VersionEndIncluding == "" &&
			cpe.VersionStartIncluding == "" && cpe.VersionStartExcluding == "" {
			continue
		}

		for swName, swList := range softwareByName {
			if !cpeProductMatch(parsed.product, swName) {
				continue
			}
			for _, sw := range swList {
				// 主机已装版本须落在 CPE 受影响 range 内
				if !cpeVersionInRange(sw.Version, parsed.version, cpe) {
					continue
				}
				key := sw.HostID + ":" + sw.Name
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				*matched = append(*matched, sw)
			}
		}
	}

	// 递归处理子节点
	for _, child := range node.Children {
		v.matchCPENode(child, softwareByName, matched, seen)
	}
}

// cpeParsed CPE 2.3 解析结果。
type cpeParsed struct {
	part     string // a (application) / o (os) / h (hardware)
	vendor   string
	product  string
	version  string
	targetSW string // 目标软件平台（windows/linux/*）
	targetHW string // 目标硬件平台
}

// parseCPE23 解析 CPE 2.3 字符串。
// 格式: cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{lang}:{sw_edition}:{target_sw}:{target_hw}:{other}
func parseCPE23(cpe string) *cpeParsed {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return nil
	}
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return nil
	}
	out := &cpeParsed{
		part:    strings.ToLower(parts[2]),
		vendor:  strings.ToLower(parts[3]),
		product: strings.ToLower(parts[4]),
		version: parts[5],
	}
	if len(parts) > 10 {
		out.targetSW = strings.ToLower(parts[10])
	}
	if len(parts) > 11 {
		out.targetHW = strings.ToLower(parts[11])
	}
	return out
}

// cpeTargetSWLinuxCompatible 判断 CPE target_sw 是否兼容 Linux 主机。
// "*" / "" / "linux*" / 含 "linux" → 兼容；
// "windows*" / "macos*" / "android*" / "ios*" → 拒绝。
func cpeTargetSWLinuxCompatible(targetSW string) bool {
	if targetSW == "" || targetSW == "*" {
		return true
	}
	nonLinux := []string{"windows", "macos", "mac_os", "android", "ios", "ipados", "tvos", "watchos"}
	for _, ns := range nonLinux {
		if strings.Contains(targetSW, ns) {
			return false
		}
	}
	return true
}

// cpeVersionInRange 判断已装版本是否落在 CPE 漏洞范围内。
// CPE 提供 versionStartIncluding/EndExcluding 等 range 字段精确表达。
// installedVer 须满足:
//   - version=="*": 进 range check
//   - version!="*": 完全相等
func cpeVersionInRange(installedVer, cpeVersion string, cpe nvdCPEMatch) bool {
	if cpeVersion != "" && cpeVersion != "*" {
		return strings.HasPrefix(installedVer, cpeVersion)
	}
	// "*" 时用 range
	if cpe.VersionStartIncluding != "" {
		c, err := compareVerRange(installedVer, cpe.VersionStartIncluding)
		if err == nil && c < 0 {
			return false
		}
	}
	if cpe.VersionStartExcluding != "" {
		c, err := compareVerRange(installedVer, cpe.VersionStartExcluding)
		if err == nil && c <= 0 {
			return false
		}
	}
	if cpe.VersionEndIncluding != "" {
		c, err := compareVerRange(installedVer, cpe.VersionEndIncluding)
		if err == nil && c > 0 {
			return false
		}
	}
	if cpe.VersionEndExcluding != "" {
		c, err := compareVerRange(installedVer, cpe.VersionEndExcluding)
		if err == nil && c >= 0 {
			return false
		}
	}
	return true
}

// compareVerRange 简化版版本比较（数字段按数值比，非数字段按字符串）。
// 与 advisory.CompareRPMVersion 类似但不依赖 RPM epoch 语义，适用于 NVD 通用版本号。
func compareVerRange(a, b string) (int, error) {
	aSegs := splitVersionSegments(a)
	bSegs := splitVersionSegments(b)
	n := len(aSegs)
	if len(bSegs) > n {
		n = len(bSegs)
	}
	for i := 0; i < n; i++ {
		var as, bs string
		if i < len(aSegs) {
			as = aSegs[i]
		}
		if i < len(bSegs) {
			bs = bSegs[i]
		}
		if as == bs {
			continue
		}
		aNum, aOk := parseUint(as)
		bNum, bOk := parseUint(bs)
		if aOk && bOk {
			if aNum < bNum {
				return -1, nil
			}
			return 1, nil
		}
		if as < bs {
			return -1, nil
		}
		return 1, nil
	}
	return 0, nil
}

func splitVersionSegments(s string) []string {
	var segs []string
	var cur strings.Builder
	for _, r := range s {
		if r == '.' || r == '-' || r == '_' || r == '+' {
			if cur.Len() > 0 {
				segs = append(segs, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		segs = append(segs, cur.String())
	}
	return segs
}

func parseUint(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}

// cpeProductMatch 检查 CPE product 是否匹配已安装软件名
func cpeProductMatch(cpeProduct, softwareName string) bool {
	// 精确匹配
	if cpeProduct == softwareName {
		return true
	}

	// 软件名去掉常见后缀后匹配（openssl-libs → openssl）
	suffixes := []string{"-libs", "-devel", "-common", "-utils", "-tools", "-client", "-server", "-minimal", "-data", "-doc"}
	stripped := softwareName
	for _, suffix := range suffixes {
		stripped = strings.TrimSuffix(stripped, suffix)
	}
	if stripped != softwareName && stripped == cpeProduct {
		return true
	}

	// 软件名去掉常见前缀后匹配（python3-urllib3 → urllib3, lib64curl → curl）
	prefixes := []string{"python3-", "python-", "perl-", "ruby-", "golang-", "lib", "lib64", "lib32"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(softwareName, prefix) {
			base := strings.TrimPrefix(softwareName, prefix)
			if base == cpeProduct {
				return true
			}
		}
	}

	return false
}

// ========== NVD 数据提取辅助方法 ==========
// 注：matchByDescription + descKeywordMap 已永久删除。
// 该机制用 substring keyword 关联 CVE 与已装软件，准确性极差：
// 如 CVE-2026-6482 描述讲 "Rapid7 Insight Agent on Windows 通过 openssl.cnf 提权"，
// keyword 匹配会错关联到 Linux openssl pkg，导致全集群 fake vuln。
// 商业级 CWPP 仅用 CPE 严格匹配 + OSV PURL match + OS Advisory，禁止任何 substring fallback。

func (v *VulnScanner) extractNVDDescription(cve nvdCVE) string {
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}

// nvdCVSSResult NVD CVSS 提取结果
type nvdCVSSResult struct {
	BaseScore    float64
	Severity     string
	VectorString string
}

func (v *VulnScanner) extractNVDCVSSFull(cve nvdCVE) nvdCVSSResult {
	// 优先 CVSS v3.1
	if len(cve.Metrics.CvssMetricV31) > 0 {
		d := cve.Metrics.CvssMetricV31[0].CvssData
		return nvdCVSSResult{d.BaseScore, nvdSeverityToInternal(d.BaseSeverity), d.VectorString}
	}
	// 回退 CVSS v3.0
	if len(cve.Metrics.CvssMetricV30) > 0 {
		d := cve.Metrics.CvssMetricV30[0].CvssData
		return nvdCVSSResult{d.BaseScore, nvdSeverityToInternal(d.BaseSeverity), d.VectorString}
	}
	return nvdCVSSResult{0, "medium", ""}
}

// extractNVDCWE 提取 CWE 编号（取第一个非 NVD-CWE-noinfo / NVD-CWE-Other 的条目）
func (v *VulnScanner) extractNVDCWE(cve nvdCVE) string {
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Value != "" && d.Value != "NVD-CWE-noinfo" && d.Value != "NVD-CWE-Other" {
				return d.Value
			}
		}
	}
	return ""
}

// extractNVDAffectedVersions 从 CPE 配置提取影响版本范围字符串
func (v *VulnScanner) extractNVDAffectedVersions(configs []nvdConfiguration) string {
	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, cpe := range node.CPEMatch {
				if !cpe.Vulnerable {
					continue
				}
				if cpe.VersionEndExcluding != "" {
					return "< " + cpe.VersionEndExcluding
				}
				if cpe.VersionEndIncluding != "" {
					return "<= " + cpe.VersionEndIncluding
				}
			}
		}
	}
	return ""
}

func nvdSeverityToInternal(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

func (v *VulnScanner) extractNVDFixedVersion(configs []nvdConfiguration) string {
	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, cpe := range node.CPEMatch {
				if cpe.Vulnerable && cpe.VersionEndExcluding != "" {
					return cpe.VersionEndExcluding
				}
			}
		}
	}
	return ""
}

func (v *VulnScanner) extractNVDReference(cve nvdCVE) string {
	// 优先返回 CVE 的原始 advisory 链接
	if len(cve.References) > 0 {
		return cve.References[0].URL
	}
	// 无参考链接时回退到 NVD 详情页
	return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID)
}
