package biz

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/remediation"
)

// RemediationService 漏洞修复服务
type RemediationService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewRemediationService 创建修复服务
func NewRemediationService(db *gorm.DB, logger *zap.Logger) *RemediationService {
	return &RemediationService{db: db, logger: logger}
}

// RemediationAdvice 修复建议
type RemediationAdvice struct {
	VulnID       uint                 `json:"vulnId"`
	CveID        string               `json:"cveId"`
	Component    string               `json:"component"`
	FixedVersion string               `json:"fixedVersion"`
	Commands     []RemediationCommand `json:"commands"`
	References   []string             `json:"references"`
	Workaround   string               `json:"workaround"`
}

// RemediationCommand 修复命令
type RemediationCommand struct {
	PackageType string `json:"packageType"` // rpm / deb
	Command     string `json:"command"`
	Description string `json:"description"`
}

// GetAdvice 生成漏洞修复建议
func (s *RemediationService) GetAdvice(vuln *model.Vulnerability) *RemediationAdvice {
	advice := &RemediationAdvice{
		VulnID:       vuln.ID,
		CveID:        vuln.CveID,
		Component:    vuln.Component,
		FixedVersion: vuln.FixedVersion,
	}

	// 根据 PURL 判断包管理器类型并生成命令
	advice.Commands = s.generateCommands(vuln)

	// 提取参考链接
	if vuln.ReferenceUrl != "" {
		advice.References = strings.Split(vuln.ReferenceUrl, ",")
		for i := range advice.References {
			advice.References[i] = strings.TrimSpace(advice.References[i])
		}
	}

	// 生成临时缓解建议
	advice.Workaround = s.generateWorkaround(vuln)

	return advice
}

// generateCommands 根据 PURL 生成修复命令
func (s *RemediationService) generateCommands(vuln *model.Vulnerability) []RemediationCommand {
	var commands []RemediationCommand

	pkgType := s.detectPackageType(vuln.PURL)
	component := vuln.Component
	fixedVersion := vuln.FixedVersion

	switch pkgType {
	case "rpm":
		// OS pkg：始终用 latest（不带 version），让 yum/dnf 自动选满足 CVE 修复的版本
		// 原因：vuln DB 的 fixed_version 经常是 NVD 上游通用版本号（如 openssl 4.1.0.2），
		// 与 OS 实际可用的 erratum 版本不匹配（如 RHEL 实际 errata 是 openssl-3.5.5-1.el10），
		// 精确版本 install 会因 "No matching Packages" 失败
		desc := fmt.Sprintf("升级 %s 到最新可用版本", component)
		if fixedVersionValid(fixedVersion) {
			desc = fmt.Sprintf("升级 %s 到最新（目标 ≥%s 以修复 %s）", component, fixedVersion, vuln.CveID)
		}
		commands = append(commands,
			RemediationCommand{
				PackageType: "rpm-yum",
				Command:     fmt.Sprintf("yum update %s -y", component),
				Description: desc + "（CentOS 7/RHEL 7 yum）",
			},
			RemediationCommand{
				PackageType: "rpm-dnf",
				Command:     fmt.Sprintf("dnf upgrade %s -y", component),
				Description: desc + "（RHEL 8+/Rocky/Fedora dnf）",
			},
		)
	case "deb":
		// 同 rpm，apt-get --only-upgrade 让 apt 自选 latest
		desc := fmt.Sprintf("升级 %s 到最新可用版本", component)
		if fixedVersionValid(fixedVersion) {
			desc = fmt.Sprintf("升级 %s 到最新（目标 ≥%s 以修复 %s）", component, fixedVersion, vuln.CveID)
		}
		commands = append(commands, RemediationCommand{
			PackageType: "deb",
			Command:     fmt.Sprintf("apt-get install --only-upgrade %s -y", component),
			Description: desc,
		})
	case "golang":
		if fixedVersionValid(fixedVersion) {
			commands = append(commands, RemediationCommand{
				PackageType: "golang",
				Command:     fmt.Sprintf("go get %s@v%s", component, fixedVersion),
				Description: fmt.Sprintf("升级 Go 依赖 %s 到修复版本 %s（需在项目目录执行）", component, fixedVersion),
			})
		}
	case "npm":
		if fixedVersionValid(fixedVersion) {
			commands = append(commands, RemediationCommand{
				PackageType: "npm",
				Command:     fmt.Sprintf("npm install %s@%s", component, fixedVersion),
				Description: fmt.Sprintf("升级 npm 包 %s 到修复版本 %s", component, fixedVersion),
			})
		}
	case "pypi":
		if fixedVersionValid(fixedVersion) {
			commands = append(commands, RemediationCommand{
				PackageType: "pypi",
				Command:     fmt.Sprintf("pip install %s==%s --upgrade", component, fixedVersion),
				Description: fmt.Sprintf("升级 Python 包 %s 到修复版本 %s", component, fixedVersion),
			})
		}
	case "maven":
		if fixedVersionValid(fixedVersion) {
			commands = append(commands, RemediationCommand{
				PackageType: "maven",
				Command:     fmt.Sprintf("<!-- 修改 pom.xml 中 %s 的版本为 %s -->", component, fixedVersion),
				Description: fmt.Sprintf("更新 Maven 依赖 %s 到 %s（需手动修改 pom.xml）", component, fixedVersion),
			})
		}
	case "cargo":
		if fixedVersionValid(fixedVersion) {
			commands = append(commands, RemediationCommand{
				PackageType: "cargo",
				Command:     fmt.Sprintf("cargo update -p %s --precise %s", component, fixedVersion),
				Description: fmt.Sprintf("升级 Rust 依赖 %s 到修复版本 %s", component, fixedVersion),
			})
		}
	default:
		// PURL 缺失时，提供 latest 升级（不带版本号）让 OS pkg manager 自选 erratum 满足 CVE。
		// 不再拼接 fixed_version：upstream vuln DB 的版本号（如 Debian 的 6.1.170-1~deb11u1）
		// 在 CentOS 仓库不存在，必失败 "No match for argument"。
		desc := fmt.Sprintf("升级 %s 到最新可用版本", component)
		if fixedVersionValid(fixedVersion) {
			desc = fmt.Sprintf("升级 %s 到最新（目标 ≥%s 以修复 %s）", component, fixedVersion, vuln.CveID)
		}
		commands = append(commands,
			RemediationCommand{
				PackageType: "rpm-yum",
				Command:     fmt.Sprintf("yum update %s -y", component),
				Description: desc + "（CentOS 7/RHEL 7 yum）",
			},
			RemediationCommand{
				PackageType: "rpm-dnf",
				Command:     fmt.Sprintf("dnf upgrade %s -y", component),
				Description: desc + "（RHEL 8+/Rocky/Fedora dnf）",
			},
			RemediationCommand{
				PackageType: "deb",
				Command:     fmt.Sprintf("apt-get install --only-upgrade %s -y", component),
				Description: desc + "（Debian/Ubuntu apt）",
			},
		)
	}

	return commands
}

// fixedVersionValid 判断 fixed_version 是否可用于命令生成/校验。
// upstream vuln DB 的脏数据：空字符串 / "0" / "unknown" / "-" / "any" 不能拼到命令里，否则
// 生成 "dnf upgrade linux-0 -y" 等必失败命令。
func fixedVersionValid(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "", "0", "unknown", "-", "any", "n/a", "none", "null":
		return false
	}
	return true
}

// VulnApplicableToHost 判断漏洞是否适用于该主机的 OS family。
// vuln.Source 来自 OS Advisory 数据源（rhsa/rocky-apollo/usn/debian-tracker/alpine 等）—
// 这些是 OS 专属的，必须匹配主机 OS family；不匹配则跳过 task 创建，避免把 Debian 内核包
// 命令下发给 CentOS 主机（必失败 "No match for argument linux-6.1-6.1.170-1~deb11u1"）。
//
// 通用源（mitre-cve / nvd / osv / cisa-kev / exploit-db / cnnvd / cnvd）返回 true —
// 这些 source 没有 OS scope，由 PURL / pkg manager 推断包类型。
func VulnApplicableToHost(vulnSource, hostOSFamily string) bool {
	source := strings.ToLower(strings.TrimSpace(vulnSource))
	osFamily := strings.ToLower(strings.TrimSpace(hostOSFamily))
	rhelFamily := map[string]bool{"rhel": true, "centos": true, "rocky": true, "almalinux": true, "alma": true, "oracle": true, "fedora": true}

	switch source {
	case "rhsa", "rhel", "redhat":
		return rhelFamily[osFamily]
	case "rocky-apollo", "rocky":
		return osFamily == "rocky" || osFamily == "almalinux" || osFamily == "alma"
	case "centos":
		return osFamily == "centos"
	case "usn", "ubuntu":
		return osFamily == "ubuntu"
	case "debian-tracker", "debian":
		return osFamily == "debian"
	case "alpine":
		return osFamily == "alpine"
	}
	// 通用情报源（mitre-cve / nvd / osv / cisa-kev / exploit-db / cnnvd / cnvd / 空）
	// 没有 OS scope，由 PURL 推断包类型，统一放行
	return true
}

// detectPackageType 从 PURL 中检测包管理器类型
func (s *RemediationService) detectPackageType(purl string) string {
	switch {
	case strings.HasPrefix(purl, "pkg:rpm/"):
		return "rpm"
	case strings.HasPrefix(purl, "pkg:deb/"):
		return "deb"
	case strings.HasPrefix(purl, "pkg:golang/"):
		return "golang"
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "npm"
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "pypi"
	case strings.HasPrefix(purl, "pkg:maven/"):
		return "maven"
	case strings.HasPrefix(purl, "pkg:cargo/"):
		return "cargo"
	default:
		return ""
	}
}

// generateWorkaround 生成临时缓解建议
func (s *RemediationService) generateWorkaround(vuln *model.Vulnerability) string {
	if vuln.FixedVersion == "" {
		return "暂无官方修复版本，建议关注供应商安全公告，或通过网络层限制访问以降低风险。"
	}
	return ""
}

// RemediationStats 修复统计
type RemediationStats struct {
	TotalVulns      int64                  `json:"totalVulns"`
	PatchedVulns    int64                  `json:"patchedVulns"`
	UnpatchedVulns  int64                  `json:"unpatchedVulns"`
	IgnoredVulns    int64                  `json:"ignoredVulns"`
	RemediationRate float64                `json:"remediationRate"` // 百分比
	MTTR            float64                `json:"mttr"`            // 平均修复时间（小时）
	BySeverity      []SeverityStats        `json:"bySeverity"`
	TopUnpatched    []HostRemediationStats `json:"topUnpatched"` // Top 10 未修复最多的主机
}

// SeverityStats 按严重级别统计
type SeverityStats struct {
	Severity  string `json:"severity"`
	Total     int64  `json:"total"`
	Patched   int64  `json:"patched"`
	Unpatched int64  `json:"unpatched"`
}

// HostRemediationStats 主机修复统计
type HostRemediationStats struct {
	HostID   string `json:"hostId"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Total    int64  `json:"total"`
	Patched  int64  `json:"patched"`
}

// GetRemediationStats 获取修复统计概览
func (s *RemediationService) GetRemediationStats() (*RemediationStats, error) {
	stats := &RemediationStats{}

	// 统计口径 = host_vulnerabilities（主机实际命中的漏洞实例），不是 vulnerabilities（全局 CVE 目录）。
	// vulnerabilities 是所有通告拉进来的 CVE 全集（含大量从不影响任何主机、severity 未评级的条目），
	// 且其 status 永远停在 unpatched（修复发生在 per-host 层），拿它算修复率恒为 0、图表被数万条无关
	// "无级别" CVE 淹没。真实修复成果在 host_vulnerabilities.status。
	s.db.Model(&model.HostVulnerability{}).Where("status != ?", "ignored").Count(&stats.TotalVulns)
	s.db.Model(&model.HostVulnerability{}).Where("status = ?", "patched").Count(&stats.PatchedVulns)
	s.db.Model(&model.HostVulnerability{}).Where("status = ?", "unpatched").Count(&stats.UnpatchedVulns)
	s.db.Model(&model.HostVulnerability{}).Where("status = ?", "ignored").Count(&stats.IgnoredVulns)

	if stats.TotalVulns > 0 {
		stats.RemediationRate = float64(stats.PatchedVulns) / float64(stats.TotalVulns) * 100
	}

	// MTTR：已修复漏洞的平均修复时间（host_vuln 无 discovered_at，用 created_at 作发现时间）
	var mttrResult struct {
		AvgHours float64 `gorm:"column:avg_hours"`
	}
	s.db.Model(&model.HostVulnerability{}).
		Select("AVG(TIMESTAMPDIFF(HOUR, created_at, patched_at)) as avg_hours").
		Where("status = ? AND patched_at IS NOT NULL", "patched").
		Scan(&mttrResult)
	stats.MTTR = mttrResult.AvgHours

	// 按严重级别统计（severity 在 vulnerabilities 上，join 取）
	var severityRows []struct {
		Severity string `gorm:"column:severity"`
		Status   string `gorm:"column:status"`
		Count    int64  `gorm:"column:count"`
	}
	s.db.Table("host_vulnerabilities AS hv").
		Select("v.severity AS severity, hv.status AS status, COUNT(*) as count").
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Where("hv.status IN ?", []string{"unpatched", "patched"}).
		Group("v.severity, hv.status").
		Scan(&severityRows)

	severityMap := make(map[string]*SeverityStats)
	for _, row := range severityRows {
		ss, ok := severityMap[row.Severity]
		if !ok {
			ss = &SeverityStats{Severity: row.Severity}
			severityMap[row.Severity] = ss
		}
		ss.Total += row.Count
		switch row.Status {
		case "patched":
			ss.Patched = row.Count
		case "unpatched":
			ss.Unpatched = row.Count
		}
	}
	for _, ss := range severityMap {
		stats.BySeverity = append(stats.BySeverity, *ss)
	}

	// Top 10 未修复漏洞最多的主机
	var hostRows []struct {
		HostID   string `gorm:"column:host_id"`
		Hostname string `gorm:"column:hostname"`
		IP       string `gorm:"column:ip"`
		Total    int64  `gorm:"column:total"`
		Patched  int64  `gorm:"column:patched"`
	}
	s.db.Table("host_vulnerabilities").
		Select("host_id, hostname, ip, COUNT(*) as total, SUM(CASE WHEN status = 'patched' THEN 1 ELSE 0 END) as patched").
		Where("status IN ?", []string{"unpatched", "patched"}).
		Group("host_id, hostname, ip").
		Order("(COUNT(*) - SUM(CASE WHEN status = 'patched' THEN 1 ELSE 0 END)) DESC").
		Limit(10).
		Scan(&hostRows)

	for _, row := range hostRows {
		stats.TopUnpatched = append(stats.TopUnpatched, HostRemediationStats{
			HostID:   row.HostID,
			Hostname: row.Hostname,
			IP:       row.IP,
			Total:    row.Total,
			Patched:  row.Patched,
		})
	}

	return stats, nil
}

// DailyTrend 每日修复趋势
type DailyTrend struct {
	Date       string `json:"date"`
	Patched    int64  `json:"patched"`
	Discovered int64  `json:"discovered"`
}

// GetRemediationTrend 获取近 N 天修复趋势
func (s *RemediationService) GetRemediationTrend(days int) ([]DailyTrend, error) {
	if days <= 0 {
		days = 30
	}

	startDate := time.Now().AddDate(0, 0, -days).Format("2006-01-02")

	// 每日新发现漏洞数
	var discoveredRows []struct {
		Date  string `gorm:"column:date"`
		Count int64  `gorm:"column:count"`
	}
	s.db.Model(&model.Vulnerability{}).
		Select("DATE(discovered_at) as date, COUNT(*) as count").
		Where("discovered_at >= ?", startDate).
		Group("DATE(discovered_at)").
		Scan(&discoveredRows)

	// 每日修复漏洞数
	var patchedRows []struct {
		Date  string `gorm:"column:date"`
		Count int64  `gorm:"column:count"`
	}
	s.db.Model(&model.Vulnerability{}).
		Select("DATE(patched_at) as date, COUNT(*) as count").
		Where("patched_at >= ? AND status = ?", startDate, "patched").
		Group("DATE(patched_at)").
		Scan(&patchedRows)

	// 合并为每日趋势
	discoveredMap := make(map[string]int64)
	for _, r := range discoveredRows {
		discoveredMap[r.Date] = r.Count
	}
	patchedMap := make(map[string]int64)
	for _, r := range patchedRows {
		patchedMap[r.Date] = r.Count
	}

	var trend []DailyTrend
	for i := days; i >= 0; i-- {
		date := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		trend = append(trend, DailyTrend{
			Date:       date,
			Patched:    patchedMap[date],
			Discovered: discoveredMap[date],
		})
	}

	return trend, nil
}

// PatchVulnerability 标记漏洞已修复（委托到中立 remediation 包，逻辑跨服务共享）。
func (s *RemediationService) PatchVulnerability(vulnID uint, hostIDs []string) error {
	return remediation.PatchVulnerability(s.db, vulnID, hostIDs)
}
