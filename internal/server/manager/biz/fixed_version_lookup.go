// Package biz — host OS-specific fixed_version lookup
package biz

import "gorm.io/gorm"

// ResolveFixedVersionForHost 按 host OS family + major + pkg 精确匹配 advisory_packages
// 对应的 fixed_version。匹配失败返回空字符串（调用方应兜底用 vulnerabilities.fixed_version）。
//
// 优先级：
//  1. 精准匹配 host OS family + major
//  2. RHEL 兼容族（rhel/rocky/centos/almalinux/oraclelinux/centos-stream）互通匹配
//
// 性能：使用 idx_ap_lookup(os_family, os_major, pkg_name) 索引。
func ResolveFixedVersionForHost(db *gorm.DB, cveID, pkgName, hostID string) string {
	if cveID == "" || pkgName == "" || hostID == "" {
		return ""
	}
	type hostRow struct {
		OSFamily  string
		OSVersion string
	}
	var h hostRow
	if err := db.Table("hosts").
		Select("os_family, os_version").
		Where("host_id = ?", hostID).
		Scan(&h).Error; err != nil {
		return ""
	}
	if h.OSFamily == "" || h.OSVersion == "" {
		return ""
	}
	// os_major = SUBSTRING_INDEX(os_version, '.', 1)
	osMajor := majorOf(h.OSVersion)
	if osMajor == "" {
		return ""
	}

	type ver struct {
		FixedVersion string
		Confidence   string
		Source       string
	}
	var rows []ver
	err := db.Table("advisory_packages").
		Select("fixed_version, confidence, source").
		Where(
			"cve_id = ? AND pkg_name = ? AND os_major = ? AND "+
				"(LOWER(os_family) = LOWER(?) OR "+
				" (LOWER(os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux') "+
				"  AND LOWER(?) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')))",
			cveID, pkgName, osMajor, h.OSFamily, h.OSFamily,
		).
		Scan(&rows).Error
	if err != nil || len(rows) == 0 {
		return ""
	}
	// 优先按 confidence 排：high > medium > low
	for _, want := range []string{"high", "medium", "low"} {
		for _, r := range rows {
			if r.Confidence == want && r.FixedVersion != "" {
				return r.FixedVersion
			}
		}
	}
	// 兜底取第一条非空
	for _, r := range rows {
		if r.FixedVersion != "" {
			return r.FixedVersion
		}
	}
	return ""
}

// majorOf 提取版本号主版本：9.6 → 9 / 10.1 → 10 / 9 → 9
func majorOf(version string) string {
	out := ""
	for _, c := range version {
		if c >= '0' && c <= '9' {
			out += string(c)
			continue
		}
		break
	}
	return out
}
