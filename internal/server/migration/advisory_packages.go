package migration

import (
	"regexp"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// migrateAdvisoryPackagesSourceAdvisoryID 把 source_advisory_id 从 varchar(64) 扩到 varchar(255)。
//
// 历史 schema varchar(64) 太短：Alpine source 拼 "Alpine-<branch>-<pkgName>-<fixedVer>" 容易超 64
// 字符，导致 bulk upsert Error 1406 Data too long 整批 fail。
// GORM AutoMigrate 不一定会扩展已有列长度，需显式 ALTER TABLE。
//
// 幂等：先查 INFORMATION_SCHEMA.CHARACTER_MAXIMUM_LENGTH，已 >=255 跳过。
func migrateAdvisoryPackagesSourceAdvisoryID(db *gorm.DB, logger *zap.Logger) error {
	if !db.Migrator().HasTable("advisory_packages") {
		return nil
	}
	var curLen int
	if err := db.Raw(`
SELECT COALESCE(CHARACTER_MAXIMUM_LENGTH, 0)
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'advisory_packages'
  AND COLUMN_NAME = 'source_advisory_id'
`).Scan(&curLen).Error; err != nil {
		return err
	}
	if curLen >= 255 {
		return nil
	}
	if err := db.Exec(
		"ALTER TABLE advisory_packages MODIFY COLUMN source_advisory_id VARCHAR(255) DEFAULT NULL",
	).Error; err != nil {
		return err
	}
	logger.Info("已扩 advisory_packages.source_advisory_id 列长度",
		zap.Int("old", curLen), zap.Int("new", 255))
	return nil
}

// ensureAdvisoryPackagesIndex 创建 advisory_packages 唯一组合索引，幂等。
//
// AutoMigrate 不创建多列 UNIQUE，需要显式 ALTER TABLE。
//
// 唯一性：(cve_id, source, os_family, os_major, pkg_name, arch) 保证同 OS × 同 source
// 同包同架构只会有一行 fix（多次 sync 重复入库走 UPDATE）。
func ensureAdvisoryPackagesIndex(db *gorm.DB, logger *zap.Logger) error {
	if !db.Migrator().HasTable("advisory_packages") {
		return nil
	}
	const idxName = "uk_advisory_packages"
	if db.Migrator().HasIndex("advisory_packages", idxName) {
		return nil
	}
	stmt := "CREATE UNIQUE INDEX " + idxName +
		" ON advisory_packages (cve_id, source, os_family, os_major, pkg_name, arch)"
	if err := db.Exec(stmt).Error; err != nil {
		logger.Warn("创建 advisory_packages 唯一索引失败（可能已存在）", zap.Error(err))
		return nil
	}
	logger.Info("已创建 advisory_packages 唯一索引")
	return nil
}

// elRegex 提取 fixed_version 末尾 .elN 的 OS 主版本号。
//
// 匹配示例：
//
//	1:3.5.1-7.el10_1        → 10
//	0:5.14.0-687.12.1.el9_8 → 9
//	1:1.20.7-30.el9         → 9
//	非 RHEL 系（如 1.2.3-1.deb12u1）→ 无匹配
var elRegex = regexp.MustCompile(`\.el(\d+)(?:_\d+)?`)

// backfillAdvisoryPackages 把现有 vulnerabilities.fixed_version 拆到 advisory_packages。
//
// 设计：
//   - 仅处理 fixed_version 非空 + source 已知（rhsa/rocky-apollo/centos/debian/ubuntu/alpine/osv）
//   - 按 source 推 OS family（rhsa→rhel, rocky-apollo→rocky, ...）
//   - OS major 优先从 fixed_version 提（.elN / -debN / 3.18 等），失败留空
//   - pkg name 从 component 字段取
//   - 幂等：基于 INSERT IGNORE，已存在不重复
//
// 注意：这是单次回填，不是双写。新数据应由 advisory.Coordinator 直接写 advisory_packages。
func backfillAdvisoryPackages(db *gorm.DB, logger *zap.Logger) error {
	if !db.Migrator().HasTable("advisory_packages") || !db.Migrator().HasTable("vulnerabilities") {
		return nil
	}
	// 仅在 advisory_packages 为空时回填（避免后续 sync 后再跑这个会覆盖新数据）
	var count int64
	if err := db.Table("advisory_packages").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		logger.Info("advisory_packages 已有数据，跳过回填", zap.Int64("rows", count))
		return nil
	}

	type row struct {
		CveID        string
		Source       string
		Component    string
		FixedVersion string
		Confidence   string
		Severity     string
	}
	var rows []row
	err := db.Raw(`
SELECT cve_id, source, component, fixed_version, confidence, severity
FROM vulnerabilities
WHERE fixed_version <> '' AND fixed_version IS NOT NULL
  AND component <> '' AND component IS NOT NULL
  AND cve_id <> ''
  AND deleted_at IS NULL
`).Scan(&rows).Error
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		logger.Info("vulnerabilities 无可回填行")
		return nil
	}

	inserted := 0
	for _, r := range rows {
		osFamily, osMajor := inferOSFromSource(r.Source, r.FixedVersion)
		if osFamily == "" && r.Source != "osv" {
			continue
		}
		// 以 INSERT IGNORE 形式插入（依赖唯一索引去重）
		insErr := db.Exec(`
INSERT IGNORE INTO advisory_packages
  (cve_id, source, source_advisory_id, os_family, os_major, ecosystem, pkg_name, arch,
   fixed_version, confidence, severity, created_at, updated_at)
VALUES (?, ?, '', ?, ?, '', ?, '', ?, ?, ?, NOW(3), NOW(3))
`, r.CveID, r.Source, osFamily, osMajor, r.Component, r.FixedVersion, r.Confidence, r.Severity).Error
		if insErr != nil {
			continue
		}
		inserted++
	}
	logger.Info("advisory_packages 回填完成",
		zap.Int("source_rows", len(rows)),
		zap.Int("inserted", inserted))
	return nil
}

// inferOSFromSource 按 source + fixed_version 推 OS family / major。
//
// 优先级：
//  1. source 名 → OS family（rhsa→rhel, rocky-apollo→rocky, alpine→alpine, debian-tracker→debian,
//     usn→ubuntu, centos→centos, openeuler-sa→openeuler, anolis-ansa→anolis, kylin-sa→kylin, uos-sa→uos）
//  2. fixed_version 末尾 .elN → OS major
//  3. fixed_version 含 alpine/debian/ubuntu 风格后缀 → 推 major
//
// 兜底：source 未知 → 返回空，调用方跳过该行。
func inferOSFromSource(source, fixedVersion string) (osFamily, osMajor string) {
	switch source {
	case "rhsa":
		osFamily = "rhel"
	case "rocky-apollo":
		osFamily = "rocky"
	case "centos":
		osFamily = "centos"
	case "usn":
		osFamily = "ubuntu"
	case "debian-tracker":
		osFamily = "debian"
	case "alpine":
		osFamily = "alpine"
	case "openeuler-sa":
		osFamily = "openeuler"
	case "anolis-ansa":
		osFamily = "anolis"
	case "kylin-sa":
		osFamily = "kylin"
	case "uos-sa":
		osFamily = "uos"
	default:
		return "", ""
	}
	if m := elRegex.FindStringSubmatch(fixedVersion); len(m) >= 2 {
		osMajor = m[1]
		return
	}
	// alpine fixed 类似 "1.2.3-r0"；debian "1.2.3-1+deb12u1"
	switch osFamily {
	case "alpine":
		// alpine secdb 通常按 branch (3.18, 3.19, edge) 划分，fixed_version 不含 OS major，留空
	case "debian":
		// 找 +deb<N>uX
		if idx := strings.Index(fixedVersion, "+deb"); idx >= 0 {
			rest := fixedVersion[idx+4:]
			var d string
			for _, c := range rest {
				if c >= '0' && c <= '9' {
					d += string(c)
				} else {
					break
				}
			}
			osMajor = d
		}
	case "ubuntu":
		// USN fixed_version 通常含 ubuntu0.20.04 等
		if idx := strings.Index(fixedVersion, "ubuntu"); idx >= 0 {
			rest := fixedVersion[idx+6:]
			var v string
			for _, c := range rest {
				if (c >= '0' && c <= '9') || c == '.' {
					v += string(c)
				} else {
					break
				}
			}
			if dot := strings.Index(v, "."); dot >= 0 {
				osMajor = v[:dot]
			}
		}
	}
	return
}
