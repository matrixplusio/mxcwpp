package advisory

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// CleanupScope 限定一次 FP 清理要检查哪些关联。
//
// 全量检查要把全部 host_vulnerabilities 与漏洞、主机、软件清单关联一遍，一条关联都不用删
// 也得花上秒级。而两次清理之间真正可能变成 FP 的只有两类：新建的关联，以及漏洞本身
// （来源、修复版本、组件）被入库更新过的关联。增量范围就取这两类。
// 主机换系统、卸载软件这类不经过入库的变化靠周期性的全量检查兜底。
type CleanupScope struct {
	// Full 为真时检查全部关联，忽略下面两个字段。
	Full bool
	// MinHostVulnID 只检查 id 大于它的关联（上次清理开始时的最大 id）。
	MinHostVulnID uint
	// VulnUpdatedSince 另外检查这一时刻之后更新过的漏洞名下的关联。
	VulnUpdatedSince time.Time
}

// fpDeleteBatch 按主键删除时每批的条数。
const fpDeleteBatch = 1000

// 各清理条件的 FROM 片段都以 hvFirstJoin 开头。按「漏洞最近更新过」筛选时要换成 vulnFirstJoin：
// 优化器默认仍从关联表（或主机表）驱动，把全部关联读一遍再去比漏洞的更新时间；
// 更新过的漏洞通常远少于关联数，从漏洞表驱动、再按 vuln_id 找关联，要快得多。
// STRAIGHT_JOIN 是 MySQL 语法，其它方言（测试库）保持原样。
const (
	hvFirstJoin   = "FROM host_vulnerabilities hv\nJOIN vulnerabilities v ON hv.vuln_id = v.id"
	vulnFirstJoin = "FROM vulnerabilities v\nSTRAIGHT_JOIN host_vulnerabilities hv ON hv.vuln_id = v.id"
)

// vulnDriven 把 FROM 片段改成从漏洞表驱动；片段不是预期的写法时原样返回（慢，但结果不变）。
func vulnDriven(db *gorm.DB, fromWhere string) string {
	if db.Dialector.Name() != "mysql" {
		return fromWhere
	}
	return toVulnFirst(fromWhere)
}

func toVulnFirst(fromWhere string) string {
	return strings.Replace(fromWhere, hvFirstJoin, vulnFirstJoin, 1)
}

// purgeHostVulnFP 先查出命中条件的关联 id，再按主键分批删除，返回删除条数。
//
// 不用多表 DELETE：它会给关联到的 hosts / vulnerabilities / software 行一并加锁并持有到语句结束，
// 全量时会锁住大量行并持续较长时间，主机心跳对 hosts 的更新在这期间排队甚至死锁。
// 普通 SELECT 是一致性读、不加锁，删除只锁要删的那几行。
//
// fromWhere 是「FROM … WHERE …」片段，表别名必须是 hv（host_vulnerabilities）与 v（vulnerabilities）。
func purgeHostVulnFP(db *gorm.DB, logger *zap.Logger, sc CleanupScope, fromWhere string, args ...any) (n int64, err error) {
	defer func() {
		if err != nil {
			logger.Warn("host_vuln FP 清理失败", zap.Error(err))
		}
	}()
	var ids []uint
	if sc.Full {
		if err := db.Raw("SELECT hv.id "+fromWhere, args...).Scan(&ids).Error; err != nil {
			return 0, err
		}
	} else {
		var fresh, touched []uint
		if err := db.Raw("SELECT hv.id "+fromWhere+" AND hv.id > ?",
			append(append([]any{}, args...), sc.MinHostVulnID)...).Scan(&fresh).Error; err != nil {
			return 0, err
		}
		if err := db.Raw("SELECT hv.id "+vulnDriven(db, fromWhere)+" AND v.updated_at >= ?",
			append(append([]any{}, args...), sc.VulnUpdatedSince)...).Scan(&touched).Error; err != nil {
			return 0, err
		}
		seen := make(map[uint]struct{}, len(fresh)+len(touched))
		for _, id := range append(fresh, touched...) {
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}

	var deleted int64
	for start := 0; start < len(ids); start += fpDeleteBatch {
		end := min(start+fpDeleteBatch, len(ids))
		r := db.Exec("DELETE FROM host_vulnerabilities WHERE id IN ?", ids[start:end])
		if r.Error != nil {
			return deleted, r.Error
		}
		deleted += r.RowsAffected
	}
	return deleted, nil
}

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
// 幂等。检查全部关联；入库后的例行清理用 CleanupHostVulnFPScoped 只看增量。
func CleanupHostVulnFP(db *gorm.DB, logger *zap.Logger) {
	CleanupHostVulnFPScoped(db, logger, CleanupScope{Full: true})
}

// CleanupHostVulnFPScoped 按给定范围清理 FP，类别与 CleanupHostVulnFP 相同。
func CleanupHostVulnFPScoped(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
	// 与入库共用写锁：清理在 host_vulnerabilities 上批量删改、JOIN advisory_packages，
	// 与正在写入的批次并发时互相等锁。
	writeMu.Lock()
	defer writeMu.Unlock()
	cleanupCrossOSFamily(db, logger, sc)
	cleanupCrossOSMajor(db, logger, sc)
	cleanupComponentNotInstalled(db, logger, sc)
	cleanupNonRHELDistroSuffix(db, logger, sc)
	cleanupNVDOnVendorOS(db, logger, sc)
	cleanupOSVOnRHELRPM(db, logger, sc)
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
	// 与入库共用写锁：清理在 host_vulnerabilities 上批量删改、JOIN advisory_packages，
	// 与正在写入的批次并发时互相等锁。
	writeMu.Lock()
	defer writeMu.Unlock()
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

func cleanupCrossOSFamily(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
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
		fromWhere := fmt.Sprintf(`
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = ?
  AND LOWER(h.os_family) NOT IN (%s)%s`, rule.compatible, hasCoveringAdvisory)
		if n, err := purgeHostVulnFP(db, logger, sc, fromWhere, rule.source); err == nil {
			total += n
		}
	}
	if total > 0 {
		logger.Info("跨 OS family host_vuln 已清理", zap.Int64("deleted", total))
	}
}

func cleanupCrossOSMajor(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
	rhelMajors := []string{"7", "8", "9", "10"}
	var total int64
	for _, major := range rhelMajors {
		// 按 per-host 匹配到的 fixed_version(matched_fixed_version)判 OS-major；老数据空时回退
		// v.fixed_version。避免 CVE 级 fixed_version 塌成异 major(如 el10)导致 el9 主机被误删。
		if n, err := purgeHostVulnFP(db, logger, sc, `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source IN ('rhsa','rocky-apollo','centos','osv')
  AND COALESCE(NULLIF(hv.matched_fixed_version, ''), v.fixed_version) REGEXP CONCAT('[.+]el', ?, '([^0-9]|$)')
  AND SUBSTRING_INDEX(h.os_version, '.', 1) <> ?`, major, major); err == nil {
			total += n
		}
	}
	if total > 0 {
		logger.Info("跨 OS major host_vuln 已清理", zap.Int64("deleted", total))
	}
}

func cleanupComponentNotInstalled(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
	// 按 per-host 匹配到的真实包名(matched_component)判是否安装；老数据 matched_component 空时
	// 回退 v.component。避免 CVE 级 component 塌成主机未装的子包(如 glibc-langpack-el)导致误删。
	//
	// 拆两条 DELETE：JOIN 键须为「裸列」才能命中 software(host_id,name) 索引——若用
	// COALESCE(NULLIF(matched_component,''),v.component) 做 join 键，函数化后索引失效，
	// 单条 DELETE 全表扫达 85s，饿死 consumer。故分「有 matched」「无 matched」两路各走等值。
	const src = `v.source IN ('rhsa','rocky-apollo','centos','debian-tracker','usn','alpine','osv')`
	var total int64

	// ① 有 matched_component：按 matched_component 判安装
	if n, err := purgeHostVulnFP(db, logger, sc, `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
LEFT JOIN software s ON s.host_id = hv.host_id AND s.name = hv.matched_component
WHERE `+src+`
  AND hv.matched_component <> ''
  AND s.id IS NULL`); err == nil {
		total += n
	}

	// ② 无 matched_component（老数据）：回退 v.component 判安装
	if n, err := purgeHostVulnFP(db, logger, sc, `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
LEFT JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
WHERE `+src+`
  AND (hv.matched_component IS NULL OR hv.matched_component = '')
  AND v.component <> ''
  AND s.id IS NULL`); err == nil {
		total += n
	}

	if total > 0 {
		logger.Info("component 未装 host_vuln 已清理", zap.Int64("deleted", total))
	}
}

func cleanupNonRHELDistroSuffix(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
	regex := `[.+](hum[0-9]*|ky10|uos[0-9]*|oe[0-9]+|amzn[0-9]*|al[0-9]+|an[789]|anolis|tl[0-9]+|tlinux)([^a-zA-Z0-9]|$)`
	n, err := purgeHostVulnFP(db, logger, sc, `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')
  AND v.fixed_version REGEXP ?`, regex)
	if err == nil && n > 0 {
		logger.Info("非 RHEL distro 后缀 host_vuln 已清理", zap.Int64("deleted", n))
	}
}

func cleanupNVDOnVendorOS(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
	n, err := purgeHostVulnFP(db, logger, sc, `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = 'nvd'
  AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux','ubuntu','debian','alpine','sles','opensuse')`)
	if err == nil && n > 0 {
		logger.Info("NVD 在 vendor OS host_vuln 已清理(backport-blind)", zap.Int64("deleted", n))
	}
}

func cleanupOSVOnRHELRPM(db *gorm.DB, logger *zap.Logger, sc CleanupScope) {
	n, err := purgeHostVulnFP(db, logger, sc, `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = 'osv'
  AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux')
  AND v.fixed_version REGEXP '[.+]el[0-9]+'`)
	if err == nil && n > 0 {
		logger.Info("RHEL 家族 OSV RPM-format host_vuln 已清理", zap.Int64("deleted", n))
	}
}
