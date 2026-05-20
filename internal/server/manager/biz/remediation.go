package biz

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
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
		if fixedVersion != "" {
			commands = append(commands,
				RemediationCommand{
					PackageType: "rpm-yum",
					Command:     fmt.Sprintf("yum update %s-%s -y", component, fixedVersion),
					Description: fmt.Sprintf("使用 yum 升级 %s 到修复版本 %s（CentOS 7/RHEL 7）", component, fixedVersion),
				},
				RemediationCommand{
					PackageType: "rpm-dnf",
					Command:     fmt.Sprintf("dnf upgrade %s-%s -y", component, fixedVersion),
					Description: fmt.Sprintf("使用 dnf 升级 %s 到修复版本 %s（RHEL 8+/Rocky/Fedora）", component, fixedVersion),
				},
			)
		} else {
			commands = append(commands,
				RemediationCommand{
					PackageType: "rpm-yum",
					Command:     fmt.Sprintf("yum update %s -y", component),
					Description: fmt.Sprintf("使用 yum 升级 %s 到最新可用版本", component),
				},
				RemediationCommand{
					PackageType: "rpm-dnf",
					Command:     fmt.Sprintf("dnf upgrade %s -y", component),
					Description: fmt.Sprintf("使用 dnf 升级 %s 到最新可用版本", component),
				},
			)
		}
	case "deb":
		if fixedVersion != "" {
			commands = append(commands, RemediationCommand{
				PackageType: "deb",
				Command:     fmt.Sprintf("apt-get install --only-upgrade %s=%s -y", component, fixedVersion),
				Description: fmt.Sprintf("使用 apt 升级 %s 到修复版本 %s", component, fixedVersion),
			})
		} else {
			commands = append(commands, RemediationCommand{
				PackageType: "deb",
				Command:     fmt.Sprintf("apt-get install --only-upgrade %s -y", component),
				Description: fmt.Sprintf("升级 %s 到最新可用版本", component),
			})
		}
	case "golang":
		if fixedVersion != "" {
			commands = append(commands, RemediationCommand{
				PackageType: "golang",
				Command:     fmt.Sprintf("go get %s@v%s", component, fixedVersion),
				Description: fmt.Sprintf("升级 Go 依赖 %s 到修复版本 %s（需在项目目录执行）", component, fixedVersion),
			})
		}
	case "npm":
		if fixedVersion != "" {
			commands = append(commands, RemediationCommand{
				PackageType: "npm",
				Command:     fmt.Sprintf("npm install %s@%s", component, fixedVersion),
				Description: fmt.Sprintf("升级 npm 包 %s 到修复版本 %s", component, fixedVersion),
			})
		}
	case "pypi":
		if fixedVersion != "" {
			commands = append(commands, RemediationCommand{
				PackageType: "pypi",
				Command:     fmt.Sprintf("pip install %s==%s --upgrade", component, fixedVersion),
				Description: fmt.Sprintf("升级 Python 包 %s 到修复版本 %s", component, fixedVersion),
			})
		}
	case "maven":
		if fixedVersion != "" {
			commands = append(commands, RemediationCommand{
				PackageType: "maven",
				Command:     fmt.Sprintf("<!-- 修改 pom.xml 中 %s 的版本为 %s -->", component, fixedVersion),
				Description: fmt.Sprintf("更新 Maven 依赖 %s 到 %s（需手动修改 pom.xml）", component, fixedVersion),
			})
		}
	case "cargo":
		if fixedVersion != "" {
			commands = append(commands, RemediationCommand{
				PackageType: "cargo",
				Command:     fmt.Sprintf("cargo update -p %s --precise %s", component, fixedVersion),
				Description: fmt.Sprintf("升级 Rust 依赖 %s 到修复版本 %s", component, fixedVersion),
			})
		}
	default:
		// 无法判断包管理器时，同时提供三种 OS 包修复方案
		if fixedVersion != "" {
			commands = append(commands,
				RemediationCommand{
					PackageType: "rpm-yum",
					Command:     fmt.Sprintf("yum update %s-%s -y", component, fixedVersion),
					Description: fmt.Sprintf("RPM 系统 (yum)：升级 %s 到 %s", component, fixedVersion),
				},
				RemediationCommand{
					PackageType: "rpm-dnf",
					Command:     fmt.Sprintf("dnf upgrade %s-%s -y", component, fixedVersion),
					Description: fmt.Sprintf("RPM 系统 (dnf)：升级 %s 到 %s", component, fixedVersion),
				},
				RemediationCommand{
					PackageType: "deb",
					Command:     fmt.Sprintf("apt-get install --only-upgrade %s=%s -y", component, fixedVersion),
					Description: fmt.Sprintf("DEB 系统：升级 %s 到 %s", component, fixedVersion),
				},
			)
		} else {
			commands = append(commands,
				RemediationCommand{
					PackageType: "rpm-yum",
					Command:     fmt.Sprintf("yum update %s -y", component),
					Description: fmt.Sprintf("RPM 系统 (yum)：升级 %s 到最新版本", component),
				},
				RemediationCommand{
					PackageType: "rpm-dnf",
					Command:     fmt.Sprintf("dnf upgrade %s -y", component),
					Description: fmt.Sprintf("RPM 系统 (dnf)：升级 %s 到最新版本", component),
				},
				RemediationCommand{
					PackageType: "deb",
					Command:     fmt.Sprintf("apt-get install --only-upgrade %s -y", component),
					Description: fmt.Sprintf("DEB 系统：升级 %s 到最新版本", component),
				},
			)
		}
	}

	return commands
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

	// 总漏洞数（不含 ignored）
	s.db.Model(&model.Vulnerability{}).Where("status != ?", "ignored").Count(&stats.TotalVulns)
	s.db.Model(&model.Vulnerability{}).Where("status = ?", "patched").Count(&stats.PatchedVulns)
	s.db.Model(&model.Vulnerability{}).Where("status = ?", "unpatched").Count(&stats.UnpatchedVulns)
	s.db.Model(&model.Vulnerability{}).Where("status = ?", "ignored").Count(&stats.IgnoredVulns)

	if stats.TotalVulns > 0 {
		stats.RemediationRate = float64(stats.PatchedVulns) / float64(stats.TotalVulns) * 100
	}

	// MTTR：已修复漏洞的平均修复时间
	var mttrResult struct {
		AvgHours float64 `gorm:"column:avg_hours"`
	}
	s.db.Model(&model.Vulnerability{}).
		Select("AVG(TIMESTAMPDIFF(HOUR, discovered_at, patched_at)) as avg_hours").
		Where("status = ? AND patched_at IS NOT NULL", "patched").
		Scan(&mttrResult)
	stats.MTTR = mttrResult.AvgHours

	// 按严重级别统计
	var severityRows []struct {
		Severity string `gorm:"column:severity"`
		Status   string `gorm:"column:status"`
		Count    int64  `gorm:"column:count"`
	}
	s.db.Model(&model.Vulnerability{}).
		Select("severity, status, COUNT(*) as count").
		Where("status IN ?", []string{"unpatched", "patched"}).
		Group("severity, status").
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

// PatchVulnerability 标记漏洞已修复
func (s *RemediationService) PatchVulnerability(vulnID uint, hostIDs []string) error {
	now := model.Now()

	return s.db.Transaction(func(tx *gorm.DB) error {
		if len(hostIDs) > 0 {
			// 标记指定主机上的漏洞为已修复
			if err := tx.Model(&model.HostVulnerability{}).
				Where("vuln_id = ? AND host_id IN ? AND status = ?", vulnID, hostIDs, "unpatched").
				Updates(map[string]any{
					"status":     "patched",
					"patched_at": now,
				}).Error; err != nil {
				return err
			}
		} else {
			// 标记该漏洞所有主机为已修复
			if err := tx.Model(&model.HostVulnerability{}).
				Where("vuln_id = ? AND status = ?", vulnID, "unpatched").
				Updates(map[string]any{
					"status":     "patched",
					"patched_at": now,
				}).Error; err != nil {
				return err
			}
		}

		// 统计已修复主机数
		var patchedCount int64
		tx.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vulnID, "patched").
			Count(&patchedCount)

		// 检查是否所有主机都已修复
		var unpatchedCount int64
		tx.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vulnID, "unpatched").
			Count(&unpatchedCount)

		updates := map[string]any{
			"patched_hosts": patchedCount,
		}
		if unpatchedCount == 0 {
			updates["status"] = "patched"
			updates["patched_at"] = now
		}

		if err := tx.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Updates(updates).Error; err != nil {
			return err
		}

		return nil
	})
}
