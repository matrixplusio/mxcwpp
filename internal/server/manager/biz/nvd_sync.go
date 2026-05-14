package biz

import (
	"encoding/json"
	"fmt"
	"io"
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
	Vulnerable          bool   `json:"vulnerable"`
	Criteria            string `json:"criteria"`
	VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding string `json:"versionEndIncluding,omitempty"`
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

		// CPE 匹配已安装软件
		matches := v.matchCPEToSoftware(item.CVE.Configurations, softwareByName)

		// 对于无 CPE 配置（Awaiting Analysis）的 CVE，使用描述关键词匹配
		if len(matches) == 0 {
			matches = v.matchByDescription(item.CVE, softwareByName)
		}
		if len(matches) == 0 {
			continue
		}

		// 提取漏洞信息
		description := v.extractNVDDescription(item.CVE)
		cvssScore, severity := v.extractNVDCVSS(item.CVE)
		fixedVersion := v.extractNVDFixedVersion(item.CVE.Configurations)
		referenceURL := v.extractNVDReference(item.CVE)

		// 取第一个匹配的组件名
		firstMatch := matches[0]

		vulnRecord := &model.Vulnerability{
			CveID:          cveID,
			OsvID:          "",
			PURL:           "",
			Severity:       severity,
			CvssScore:      cvssScore,
			Component:      firstMatch.Name,
			Description:    description,
			Status:         "unpatched",
			DiscoveredAt:   model.LocalTime(time.Now()),
			CurrentVersion: firstMatch.Version,
			FixedVersion:   fixedVersion,
			ReferenceUrl:   referenceURL,
		}

		if err := v.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "cve_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"cvss_score", "description", "fixed_version", "reference_url"}),
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

		// 发送漏洞告警通知
		if len(matches) > 0 {
			go func(vuln *model.Vulnerability, sw installedSoftware) {
				var affected int64
				v.db.Model(&model.HostVulnerability{}).Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").Count(&affected)
				ns := NewNotificationService(v.db, v.logger)
				_ = ns.SendVulnerabilityAlertNotification(&VulnerabilityAlertData{
					HostID: sw.HostID, Hostname: sw.Hostname, IP: sw.IP,
					CveID: vuln.CveID, Severity: vuln.Severity, CvssScore: vuln.CvssScore,
					Component: vuln.Component, CurrentVersion: vuln.CurrentVersion,
					FixedVersion: vuln.FixedVersion, Description: vuln.Description,
					AffectedHosts: int(affected),
				})
			}(vulnRecord, matches[0])
		}

		existingCVEs[cveID] = struct{}{}
		newCount++
	}

	v.logger.Info("NVD 补充同步完成", zap.Int("new_cves", newCount))
	return nil
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

	// NVD API 响应体较大（2000+ CVE），需要足够的超时来完成下载
	client := &http.Client{Timeout: 180 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("调用 NVD API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API 返回 %d: %s", resp.StatusCode, string(body))
	}

	var result nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析 NVD 响应失败: %w", err)
	}

	v.logger.Info("NVD 首页结果", zap.Int("totalResults", result.TotalResults), zap.Int("pageItems", len(result.Vulnerabilities)))

	// 如果结果超过一页，继续分页获取
	allItems := result.Vulnerabilities
	for startIndex := nvdPageSize; startIndex < result.TotalResults; startIndex += nvdPageSize {
		pageURL := fmt.Sprintf("%s&startIndex=%d", url, startIndex)
		pageResp, err := client.Get(pageURL)
		if err != nil {
			v.logger.Warn("NVD 分页查询失败", zap.Int("startIndex", startIndex), zap.Error(err))
			break
		}
		var pageResult nvdResponse
		if err := json.NewDecoder(pageResp.Body).Decode(&pageResult); err != nil {
			pageResp.Body.Close()
			v.logger.Warn("NVD 分页解析失败", zap.Int("startIndex", startIndex), zap.Error(err))
			break
		}
		pageResp.Body.Close()
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
		// CPE 2.3 格式: cpe:2.3:part:vendor:product:version:...
		parts := strings.Split(cpe.Criteria, ":")
		if len(parts) < 5 {
			continue
		}
		product := strings.ToLower(parts[4])
		if product == "*" || product == "" {
			continue
		}

		// 匹配策略：
		// 1. 精确匹配软件名
		// 2. 软件名包含 CPE product（如 openssl-libs 匹配 openssl）
		for swName, swList := range softwareByName {
			if !cpeProductMatch(product, swName) {
				continue
			}
			for _, sw := range swList {
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

// descKeywordMap 描述关键词 → 软件包名匹配规则
// 用于处理 NVD 中尚未完成 CPE 分析（Awaiting Analysis）的 CVE
var descKeywordMap = []struct {
	keyword  string   // 描述中的关键词（小写匹配）
	packages []string // 对应的软件包名（与 software 表中的 name 匹配）
}{
	{"linux kernel", []string{"kernel", "kernel-core", "kernel-modules", "kernel-tools"}},
	{"openssl", []string{"openssl", "openssl-libs"}},
	{"glibc", []string{"glibc", "glibc-common", "glibc-minimal-langpack"}},
	{"systemd", []string{"systemd", "systemd-libs"}},
	{"openssh", []string{"openssh", "openssh-server", "openssh-clients"}},
	{"curl", []string{"curl", "libcurl"}},
	{"sudo", []string{"sudo"}},
	{"bind", []string{"bind", "bind-libs", "bind-utils"}},
	{"nginx", []string{"nginx"}},
	{"apache", []string{"httpd"}},
}

// matchByDescription 通过描述关键词匹配已安装软件（处理无 CPE 的 CVE）
func (v *VulnScanner) matchByDescription(cve nvdCVE, softwareByName map[string][]installedSoftware) []installedSoftware {
	desc := strings.ToLower(v.extractNVDDescription(cve))
	if desc == "" {
		return nil
	}

	var matched []installedSoftware
	seen := make(map[string]struct{})

	for _, rule := range descKeywordMap {
		if !strings.Contains(desc, rule.keyword) {
			continue
		}
		for _, pkgName := range rule.packages {
			swList, ok := softwareByName[pkgName]
			if !ok {
				continue
			}
			for _, sw := range swList {
				key := sw.HostID + ":" + sw.Name
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				matched = append(matched, sw)
			}
		}
	}
	return matched
}

// ========== NVD 数据提取辅助方法 ==========

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

func (v *VulnScanner) extractNVDCVSS(cve nvdCVE) (float64, string) {
	// 优先 CVSS v3.1
	if len(cve.Metrics.CvssMetricV31) > 0 {
		d := cve.Metrics.CvssMetricV31[0].CvssData
		return d.BaseScore, nvdSeverityToInternal(d.BaseSeverity)
	}
	// 回退 CVSS v3.0
	if len(cve.Metrics.CvssMetricV30) > 0 {
		d := cve.Metrics.CvssMetricV30[0].CvssData
		return d.BaseScore, nvdSeverityToInternal(d.BaseSeverity)
	}
	return 0, "medium"
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
