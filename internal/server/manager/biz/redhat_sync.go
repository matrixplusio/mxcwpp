package biz

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm/clause"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	redhatCVEListURL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
	redhatSyncDays   = 14  // 同步最近 14 天
	redhatPageSize   = 500 // 每页条数
)

// Red Hat Security Data API CVE 列表项
type redhatCVEItem struct {
	CVE                 string   `json:"CVE"`
	Severity            string   `json:"severity"`
	PublicDate          string   `json:"public_date"`
	Advisories          []string `json:"advisories"`
	BugzillaDescription string   `json:"bugzilla_description"`
	CVSS3ScoringVector  string   `json:"cvss3_scoring_vector"`
	CVSS3Score          string   `json:"cvss3_score"`
	CWE                 string   `json:"cwe"`
	AffectedPackages    []string `json:"affected_packages"`
	ResourceURL         string   `json:"resource_url"`
}

var rpmNameRegexp = regexp.MustCompile(`^([a-zA-Z0-9_+.-]+?)-\d`)

// SyncRedHat 从 Red Hat Security Data API 同步最近的 CVE 数据
func (v *VulnScanner) SyncRedHat() error {
	return v.SyncRedHatWithSoftware(nil)
}

// SyncRedHatWithSoftware 使用预加载的软件列表执行 Red Hat 同步，避免重复查询
func (v *VulnScanner) SyncRedHatWithSoftware(softwareByName map[string][]installedSoftware) error {
	v.logger.Info("开始 Red Hat Security Data 同步")

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
			v.logger.Info("没有已安装软件，跳过 Red Hat 同步")
			return nil
		}

		softwareByName = make(map[string][]installedSoftware)
		for _, sw := range software {
			key := strings.ToLower(sw.Name)
			softwareByName[key] = append(softwareByName[key], sw)
		}
	}

	// 2. 查询 Red Hat API
	cves, err := v.fetchRedHatCVEs()
	if err != nil {
		return fmt.Errorf("查询 Red Hat API 失败: %w", err)
	}

	v.logger.Info("Red Hat API 返回 CVE 数", zap.Int("count", len(cves)))

	// 3. 过滤已存在的 CVE
	existingCVEs := make(map[string]struct{})
	var existingIDs []string
	v.db.Model(&model.Vulnerability{}).Pluck("cve_id", &existingIDs)
	for _, id := range existingIDs {
		existingCVEs[id] = struct{}{}
	}

	// 4. 匹配并写入
	newCount := 0
	for _, item := range cves {
		if _, exists := existingCVEs[item.CVE]; exists {
			continue
		}

		matches := v.matchRedHatPackages(item.AffectedPackages, softwareByName)
		if len(matches) == 0 {
			continue
		}

		severity := redhatSeverityToInternal(item.Severity)
		cvssScore := parseRedHatCVSSScore(item.CVSS3Score)
		if cvssScore == 0 && item.CVSS3ScoringVector != "" {
			cvssScore = parseCVSSv3Vector(item.CVSS3ScoringVector)
		}
		description := item.BugzillaDescription
		referenceURL := fmt.Sprintf("https://access.redhat.com/security/cve/%s", item.CVE)

		firstMatch := matches[0]
		vulnRecord := &model.Vulnerability{
			CveID:          item.CVE,
			Severity:       severity,
			CvssScore:      cvssScore,
			Component:      firstMatch.Name,
			Description:    description,
			Status:         "unpatched",
			DiscoveredAt:   model.LocalTime(time.Now()),
			CurrentVersion: firstMatch.Version,
			ReferenceUrl:   referenceURL,
			Source:         "redhat",
		}

		if err := v.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "cve_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"cvss_score", "description", "reference_url"}),
		}).Create(vulnRecord).Error; err != nil {
			v.logger.Error("Red Hat 写入漏洞记录失败", zap.String("cve_id", item.CVE), zap.Error(err))
			continue
		}

		if vulnRecord.ID == 0 {
			v.db.Where("cve_id = ?", item.CVE).Select("id").First(vulnRecord)
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

		// 创建漏洞通报 + 发送通知（与 OSV 扫描路径统一）
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

		existingCVEs[item.CVE] = struct{}{}
		newCount++
	}

	v.logger.Info("Red Hat 同步完成", zap.Int("new_cves", newCount))
	return nil
}

// fetchRedHatCVEs 分页获取 Red Hat Security Data API 的 CVE 列表
func (v *VulnScanner) fetchRedHatCVEs() ([]redhatCVEItem, error) {
	afterDate := time.Now().AddDate(0, 0, -redhatSyncDays).Format("2006-01-02")
	client := &http.Client{Timeout: 60 * time.Second}

	var allItems []redhatCVEItem
	page := 1

	for {
		url := fmt.Sprintf("%s?after=%s&per_page=%d&page=%d",
			redhatCVEListURL, afterDate, redhatPageSize, page)

		v.logger.Info("Red Hat API 请求", zap.String("url", url), zap.Int("page", page))

		resp, err := client.Get(url)
		if err != nil {
			return nil, fmt.Errorf("调用 Red Hat API 失败: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("Red Hat API 返回 %d: %s", resp.StatusCode, string(body))
		}

		var items []redhatCVEItem
		if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("解析 Red Hat API 响应失败: %w", err)
		}
		resp.Body.Close()

		allItems = append(allItems, items...)

		if len(items) < redhatPageSize {
			break
		}

		page++
		time.Sleep(1 * time.Second)
	}

	return allItems, nil
}

// matchRedHatPackages 匹配 Red Hat affected_packages 与已安装软件
func (v *VulnScanner) matchRedHatPackages(affectedPkgs []string, softwareByName map[string][]installedSoftware) []installedSoftware {
	var matched []installedSoftware
	seen := make(map[string]struct{})

	for _, pkg := range affectedPkgs {
		pkgName := extractRPMName(pkg)
		if pkgName == "" {
			continue
		}

		key := strings.ToLower(pkgName)
		swList, ok := softwareByName[key]
		if !ok {
			continue
		}

		for _, sw := range swList {
			hostKey := sw.HostID + ":" + sw.Name
			if _, exists := seen[hostKey]; exists {
				continue
			}
			seen[hostKey] = struct{}{}
			matched = append(matched, sw)
		}
	}

	return matched
}

// extractRPMName 从 RPM 完整包名中提取软件名
// 例: kernel-5.14.0-362.13.1.el9_3.x86_64 → kernel
// 例: openssl-libs-3.0.7-18.el9_2.x86_64 → openssl-libs
func extractRPMName(fullName string) string {
	for _, arch := range []string{".x86_64", ".i686", ".aarch64", ".noarch", ".ppc64le", ".s390x", ".src"} {
		fullName = strings.TrimSuffix(fullName, arch)
	}

	matches := rpmNameRegexp.FindStringSubmatch(fullName)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func redhatSeverityToInternal(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "important":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func parseRedHatCVSSScore(s string) float64 {
	if s == "" {
		return 0
	}
	score, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return score
}
