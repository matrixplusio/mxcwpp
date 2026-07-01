package advisory

import (
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// CleanupHostVulnFP 清理 host_vulnerabilities 中的已知 FP 类别。
//
// 同时被 migration（启动时一次性清理 legacy 数据）和 Coordinator.Sync（每次 sync
// 后清理 mergeByConfidence 翻新 source 字段引入的新 FP）调用，保持单一真源。
//
// 清理类别：
//  1. OS family 不兼容(debian-tracker → rocky host 等)
//  2. OS major 不兼容(.elN advisory → 异 N host)
//  3. component 未装在 host 上
//  4. RHEL 家族 host 上的非 RHEL distro 后缀(.hum/.ky10/.uos/.oe/.amzn/.an/.tlinux)
//  5. NVD 源落在 vendor-covered OS 家族(NVD backport-blind)
//  6. OSV 源落在 RHEL 家族 + RPM-format fixed_version(RHSA 应主导)
//
// 幂等。
func CleanupHostVulnFP(db *gorm.DB, logger *zap.Logger) {
	cleanupCrossOSFamily(db, logger)
	cleanupCrossOSMajor(db, logger)
	cleanupComponentNotInstalled(db, logger)
	cleanupNonRHELDistroSuffix(db, logger)
	cleanupNVDOnVendorOS(db, logger)
	cleanupOSVOnRHELRPM(db, logger)
}

// CleanupAlreadyPatched 用 RPM 版本比对清掉 host 实际已修复版本但仍报漏洞的条目。
//
// NEVRA-aware：拼 s.epoch + s.version + s.release 成完整 NEVRA 字符串，
// 与 fixed_version 比较。若 installed >= fixed → host 实际已修复，删除。
//
// V2 升级：fixed_version 优先取 advisory_packages 按 host OS（family+major）精准
// 匹配的行，兜底退回 vulnerabilities.fixed_version。解决 RHSA fixed_version 仅
// el10 编码导致 Rocky 9 host 误判的问题。
//
// 单独函数因实现需 Go 端 loop + RPM-vercmp。
func CleanupAlreadyPatched(db *gorm.DB, logger *zap.Logger) {
	type row struct {
		HostVulnID    uint   `gorm:"column:hv_id"`
		Epoch         string `gorm:"column:epoch"`
		Version       string `gorm:"column:version"`
		ReleaseString string `gorm:"column:release"`
		FixedVersion  string `gorm:"column:fixed_version"`
	}
	const batchSize = 5000
	var lastID uint = 0
	var totalDeleted int64
	for {
		var batch []row
		err := db.Raw(`
SELECT hv.id AS hv_id, s.epoch, s.version, s.`+"`release`"+`,
       COALESCE(ap.fixed_version, v.fixed_version) AS fixed_version
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
LEFT JOIN advisory_packages ap
  ON ap.cve_id = v.cve_id
  AND ap.pkg_name = v.component
  AND ap.os_major = SUBSTRING_INDEX(h.os_version, '.', 1)
  AND (
    LOWER(ap.os_family) = LOWER(h.os_family)
    OR (LOWER(ap.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')
        AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux'))
  )
WHERE v.source IN ('rhsa','rocky-apollo','centos','osv')
  AND COALESCE(ap.fixed_version, v.fixed_version) <> ''
  AND s.version <> ''
  AND hv.id > ?
ORDER BY hv.id ASC
LIMIT ?`, lastID, batchSize).Scan(&batch).Error
		if err != nil {
			logger.Warn("拉 host_vuln 批失败", zap.Error(err))
			return
		}
		if len(batch) == 0 {
			break
		}
		var toDelete []uint
		for _, r := range batch {
			lastID = r.HostVulnID
			// 拼 NEVRA 字符串：epoch=空时退回 ver-rel；release 空时退回 ver
			installed := r.Version
			if r.ReleaseString != "" {
				installed = installed + "-" + r.ReleaseString
			}
			if r.Epoch != "" {
				installed = r.Epoch + ":" + installed
			}
			cmp, err := CompareRPMVersion(installed, r.FixedVersion)
			if err != nil {
				continue
			}
			if cmp >= 0 {
				toDelete = append(toDelete, r.HostVulnID)
			}
		}
		if len(toDelete) > 0 {
			r := db.Exec("DELETE FROM host_vulnerabilities WHERE id IN ?", toDelete)
			if r.Error != nil {
				logger.Warn("已修复 host_vuln 批删除失败",
					zap.Int("batch_size", len(toDelete)), zap.Error(r.Error))
				continue
			}
			totalDeleted += r.RowsAffected
		}
		if len(batch) < batchSize {
			break
		}
	}
	if totalDeleted > 0 {
		logger.Info("已修复版本 host_vuln 清理完成", zap.Int64("deleted", totalDeleted))
	}
}

func cleanupCrossOSFamily(db *gorm.DB, logger *zap.Logger) {
	xrefRules := []struct {
		source     string
		compatible string
	}{
		{"debian-tracker", "'debian','ubuntu'"},
		{"usn", "'debian','ubuntu'"},
		{"alpine", "'alpine'"},
		{"rhsa", "'rhel','rocky','centos','centos-stream','almalinux','oraclelinux'"},
		{"rocky-apollo", "'rhel','rocky','centos','centos-stream','almalinux','oraclelinux'"},
		{"centos", "'rhel','rocky','centos','centos-stream','almalinux','oraclelinux'"},
	}
	// 守卫：多发行版 CVE 的 vulnerabilities.source 会被 mergeByConfidence 按全局
	// confidence 覆盖成异 OS 源（如 rocky 匹配的 CentOS 链被标 debian-tracker），若仅按
	// v.source 判跨 OS 会误删合法链。故仅当该 CVE 对本机 OS **无任何覆盖性 advisory_packages
	// 行**时才删——advisory_packages 是 per-OS 修复权威源，rhel 家族互兼容。
	const hasCoveringAdvisory = `
  AND NOT EXISTS (
    SELECT 1 FROM advisory_packages ap
    WHERE ap.cve_id = v.cve_id
      AND ap.pkg_name = v.component
      AND ap.os_major = SUBSTRING_INDEX(h.os_version, '.', 1)
      AND (
        LOWER(ap.os_family) = LOWER(h.os_family)
        OR (LOWER(ap.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')
            AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux'))
      )
  )`
	var total int64
	for _, rule := range xrefRules {
		sql := fmt.Sprintf(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = ?
  AND LOWER(h.os_family) NOT IN (%s)%s`, rule.compatible, hasCoveringAdvisory)
		r := db.Exec(sql, rule.source)
		if r.Error == nil && r.RowsAffected > 0 {
			total += r.RowsAffected
		}
	}
	if total > 0 {
		logger.Info("跨 OS family host_vuln 已清理", zap.Int64("deleted", total))
	}
}

func cleanupCrossOSMajor(db *gorm.DB, logger *zap.Logger) {
	rhelMajors := []string{"7", "8", "9", "10"}
	var total int64
	for _, major := range rhelMajors {
		r := db.Exec(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source IN ('rhsa','rocky-apollo','centos','osv')
  AND v.fixed_version REGEXP CONCAT('[.+]el', ?, '([^0-9]|$)')
  AND SUBSTRING_INDEX(h.os_version, '.', 1) <> ?`, major, major)
		if r.Error == nil && r.RowsAffected > 0 {
			total += r.RowsAffected
		}
	}
	if total > 0 {
		logger.Info("跨 OS major host_vuln 已清理", zap.Int64("deleted", total))
	}
}

func cleanupComponentNotInstalled(db *gorm.DB, logger *zap.Logger) {
	r := db.Exec(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
LEFT JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
WHERE v.source IN ('rhsa','rocky-apollo','centos','debian-tracker','usn','alpine','osv')
  AND v.component <> ''
  AND s.id IS NULL`)
	if r.Error == nil && r.RowsAffected > 0 {
		logger.Info("component 未装 host_vuln 已清理", zap.Int64("deleted", r.RowsAffected))
	}
}

func cleanupNonRHELDistroSuffix(db *gorm.DB, logger *zap.Logger) {
	regex := `[.+](hum[0-9]*|ky10|uos[0-9]*|oe[0-9]+|amzn[0-9]*|al[0-9]+|an[789]|anolis|tl[0-9]+|tlinux)([^a-zA-Z0-9]|$)`
	r := db.Exec(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')
  AND v.fixed_version REGEXP ?`, regex)
	if r.Error == nil && r.RowsAffected > 0 {
		logger.Info("非 RHEL distro 后缀 host_vuln 已清理", zap.Int64("deleted", r.RowsAffected))
	}
}

func cleanupNVDOnVendorOS(db *gorm.DB, logger *zap.Logger) {
	r := db.Exec(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = 'nvd'
  AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux','ubuntu','debian','alpine','sles','opensuse')`)
	if r.Error == nil && r.RowsAffected > 0 {
		logger.Info("NVD 在 vendor OS host_vuln 已清理(backport-blind)", zap.Int64("deleted", r.RowsAffected))
	}
}

func cleanupOSVOnRHELRPM(db *gorm.DB, logger *zap.Logger) {
	r := db.Exec(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = 'osv'
  AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')
  AND v.fixed_version REGEXP '[.+]el[0-9]+'`)
	if r.Error == nil && r.RowsAffected > 0 {
		logger.Info("RHEL 家族 OSV RPM-format host_vuln 已清理", zap.Int64("deleted", r.RowsAffected))
	}
}
