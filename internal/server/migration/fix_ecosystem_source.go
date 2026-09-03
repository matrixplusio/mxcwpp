package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// migrateFixOverwrittenEcosystemSource 修历史 vulnerabilities.source 被 OS source 错误覆盖。
//
// Bug 背景：advisory.Coordinator.upsertVuln 旧版本会把 ecosystem source（osv）
// 的 vuln.source 覆盖为 OS source（debian-tracker/alpine/usn 等 confidence=high）。
// 后续 CleanupHostVulnFP 看到 debian source 关联 rocky host → 误判跨 OS → 删 host_vuln。
// 结果 OSV 发现的 Java/npm/Go 漏洞被错删。
//
// 识别：vulnerabilities.purl LIKE 'pkg:maven/%' OR 'pkg:npm/%' OR 'pkg:pypi/%' OR
// 'pkg:golang/%' OR 'pkg:gem/%' OR 'pkg:cargo/%' OR 'pkg:nuget/%' OR 'pkg:composer/%'
// → purl 是语言包 ecosystem，source 应该是 'osv'
//
// 幂等：基于 source IN(OS) AND purl LIKE 'pkg:<lang>/%' 条件，多次运行无副作用
// （已修复行不再匹配条件）。
func migrateFixOverwrittenEcosystemSource(db *gorm.DB, logger *zap.Logger) error {
	if !db.Migrator().HasTable("vulnerabilities") {
		return nil
	}
	result := db.Exec(`
UPDATE vulnerabilities
SET source = 'osv'
WHERE source IN ('debian-tracker','alpine','usn','rhsa','rocky-apollo','centos')
  AND (purl LIKE 'pkg:maven/%'
       OR purl LIKE 'pkg:npm/%'
       OR purl LIKE 'pkg:pypi/%'
       OR purl LIKE 'pkg:golang/%'
       OR purl LIKE 'pkg:gem/%'
       OR purl LIKE 'pkg:cargo/%'
       OR purl LIKE 'pkg:nuget/%'
       OR purl LIKE 'pkg:composer/%'
       OR purl LIKE 'pkg:pub/%'
       OR purl LIKE 'pkg:hex/%')
  AND deleted_at IS NULL
`)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("修复历史 vuln source 字段（OS source → osv，purl=语言包）",
			zap.Int64("rows", result.RowsAffected))
	}
	return nil
}
