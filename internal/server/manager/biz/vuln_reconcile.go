package biz

import (
	"strings"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// effectiveFixedVersion 优先用 per-host matched_fixed_version（针对该主机 OS-major/包分支的
// 适用修复版本），为空才回退 CVE 级 fixed_version（跨包跨发行版塌缩值，对多数主机不准）。
func effectiveFixedVersion(hv *model.HostVulnerability, cveFixed string) string {
	if hv.MatchedFixedVersion != "" {
		return hv.MatchedFixedVersion
	}
	return cveFixed
}

// purlIdentity 去掉 PURL 里的版本与限定符，只保留「这是哪个包」。
//
// 漏洞记录里的 PURL 嵌的是**易受攻击版本**（如 …/buildkit@v0.23.2），
// 主机 software 表里的 PURL 嵌的是**已安装版本**（如 …/buildkit@v0.23.5）。
// 两者只有在「装的正好是被记录的那个版本」时才相等——也就是说，
// 按完整 PURL 判断包是否还在，绝大多数情况下都会得到「不在」。
//
// 全机群首次核对时，误标 vanished 的量级比真正 patched 高两个数量级，
// 横跨 os / app / middleware / unknown 全部资产类型。
//
// 因此存在性只按名称判断，版本另行用 software.version 列比较。
func purlIdentity(purl string) string {
	if i := strings.IndexByte(purl, '?'); i >= 0 { // 去限定符 ?arch=x86_64
		purl = purl[:i]
	}
	if i := strings.IndexByte(purl, '#'); i >= 0 { // 去子路径
		purl = purl[:i]
	}
	// 版本分隔符是最后一个 '@'：包名本身可能含 '@'（如 npm scope @scope/name）。
	if i := strings.LastIndexByte(purl, '@'); i >= 0 {
		purl = purl[:i]
	}
	return purl
}

// isOSPackagePURL 判断是否 OS 系统包（RPM/dpkg/apk）。仅这类适用 NEVRA 权威比较；
// 语言包（golang/npm/pypi 等 semver，带 v 前缀等）走通用比较器。
func isOSPackagePURL(purl string) bool {
	return strings.HasPrefix(purl, "pkg:rpm/") ||
		strings.HasPrefix(purl, "pkg:deb/") ||
		strings.HasPrefix(purl, "pkg:apk/")
}

// compareInstalledVsFix 比较当前版本与修复版：OS 包用按 OS family 的权威 NEVRA 比较
// （正确处理 el9_4 等 release 后缀，修旧弱比较器吞后缀误判已修）；语言包用通用比较器。
func compareInstalledVsFix(osFamily, purl, current, fixed string) (int, error) {
	if isOSPackagePURL(purl) {
		return advisory.CompareVersionByOS(osFamily, current, fixed)
	}
	return compareVersionStrings(current, fixed), nil
}

// VulnReconciler 漏洞陈旧记录核对器
//
// 职责：对比 software 表当前状态，把 host_vulnerabilities 中陈旧的 unpatched 记录迁移到
//   - vanished：包从 software 表消失（卸载或扫描漏采）
//   - patched：当前版本 >= fix_version（自动版本匹配）
//   - 否则保持 unpatched，但更新 current_version 跟踪
type VulnReconciler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// ReconcileResult 单次 reconcile 统计
type ReconcileResult struct {
	Vanished int
	Patched  int
	Scanned  int
}

// NewVulnReconciler 构造
func NewVulnReconciler(db *gorm.DB, logger *zap.Logger) *VulnReconciler {
	return &VulnReconciler{db: db, logger: logger}
}

// ReconcileHosts 对指定 host_id 集合做陈旧核对
//
// 算法：
//  1. 一次性 load 这些 host 的 software 快照（按 host_id+purl 索引）
//  2. 分批 load 这些 host 的 unpatched host_vulnerabilities
//  3. 逐条判定状态迁移并 UPDATE
//
// HostBatchSize 单批处理的主机数。
//
// 核对要把这批主机的 software 快照整个读进内存（每台数百到上千个包），
// 内存占用随主机数线性增长。分批让占用与机群规模脱钩，
// 调用方因此不必再自己切批——此前 228 台的机群必须手工拆成 200+28 两次调用。
const HostBatchSize = 200

// ReconcileHosts 对指定 host_id 集合做陈旧核对，内部自动分批。
func (r *VulnReconciler) ReconcileHosts(hostIDs []string) (*ReconcileResult, error) {
	total := &ReconcileResult{}
	for start := 0; start < len(hostIDs); start += HostBatchSize {
		end := min(start+HostBatchSize, len(hostIDs))
		batch, err := r.reconcileBatch(hostIDs[start:end])
		if err != nil {
			// 已完成批次的结果已经落库，直接返回错误会让调用方以为一条都没处理。
			return total, err
		}
		total.Scanned += batch.Scanned
		total.Patched += batch.Patched
		total.Vanished += batch.Vanished
	}
	return total, nil
}

func (r *VulnReconciler) reconcileBatch(hostIDs []string) (*ReconcileResult, error) {
	result := &ReconcileResult{}
	if len(hostIDs) == 0 {
		return result, nil
	}

	currentPkgs, err := r.loadCurrentPURLsByHosts(hostIDs)
	if err != nil {
		return nil, err
	}
	osFam := r.loadHostOSFamilies(hostIDs)

	const batchSize = 500
	offset := 0
	for {
		var hvs []model.HostVulnerability
		err := r.db.
			Where("host_id IN ? AND status = ?", hostIDs, model.HostVulnStatusUnpatched).
			Limit(batchSize).
			Offset(offset).
			Find(&hvs).Error
		if err != nil {
			return nil, err
		}
		if len(hvs) == 0 {
			break
		}

		for i := range hvs {
			r.reconcileOne(&hvs[i], currentPkgs, osFam[hvs[i].HostID], result)
		}
		offset += batchSize
	}

	return result, nil
}

// loadHostOSFamilies 取这些 host 的 os_family，供选 RPM/dpkg 权威版本比较器。
func (r *VulnReconciler) loadHostOSFamilies(hostIDs []string) map[string]string {
	m := make(map[string]string, len(hostIDs))
	var rows []struct {
		HostID   string
		OsFamily string
	}
	r.db.Table("hosts").Select("host_id, os_family").
		Where("host_id IN ?", hostIDs).Scan(&rows)
	for _, x := range rows {
		m[x.HostID] = x.OsFamily
	}
	return m
}

// reconcileOne 处理单条 host_vulnerability
func (r *VulnReconciler) reconcileOne(
	hv *model.HostVulnerability,
	currentPkgs map[string]map[string]string,
	osFamily string,
	result *ReconcileResult,
) {
	result.Scanned++

	var vuln model.Vulnerability
	if err := r.db.Select("purl, fixed_version").First(&vuln, hv.VulnID).Error; err != nil {
		r.logger.Warn("reconcile: 取 vulnerability 失败",
			zap.Uint("vuln_id", hv.VulnID), zap.Error(err))
		return
	}

	hostPkgs := currentPkgs[hv.HostID]
	currentVersion, exists := hostPkgs[purlIdentity(vuln.PURL)]

	if !exists {
		r.markVanished(hv, model.PatchedReasonPackageRemoved)
		result.Vanished++
		return
	}

	// 优先用 per-host matched_fixed_version + OS 包权威 NEVRA 比较；
	// 比较出错（版本串异常）时保守处理：不自动核销，避免误标已修掩盖真实漏洞。
	fixed := effectiveFixedVersion(hv, vuln.FixedVersion)
	if fixed != "" {
		if cmp, err := compareInstalledVsFix(osFamily, vuln.PURL, currentVersion, fixed); err == nil && cmp >= 0 {
			r.markPatched(hv, model.PatchedReasonAutoVersionMatch, currentVersion)
			result.Patched++
			return
		}
	}

	if currentVersion != "" && currentVersion != hv.CurrentVersion {
		r.db.Model(hv).Update("current_version", currentVersion)
	}
}

func (r *VulnReconciler) markVanished(hv *model.HostVulnerability, reason string) {
	now := model.LocalTime(time.Now())
	r.db.Model(hv).Updates(map[string]any{
		"status":         model.HostVulnStatusVanished,
		"prev_status":    hv.Status,
		"patched_reason": reason,
		"vanished_at":    &now,
	})
}

func (r *VulnReconciler) markPatched(hv *model.HostVulnerability, reason, newVersion string) {
	now := model.LocalTime(time.Now())
	r.db.Model(hv).Updates(map[string]any{
		"status":          model.HostVulnStatusPatched,
		"prev_status":     hv.Status,
		"patched_reason":  reason,
		"patched_at":      &now,
		"current_version": newVersion,
	})
}

// loadCurrentPURLsByHosts 取这些 host 的 software 快照，返回 map[host_id]map[purl]version
func (r *VulnReconciler) loadCurrentPURLsByHosts(hostIDs []string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string, len(hostIDs))
	for _, h := range hostIDs {
		result[h] = make(map[string]string)
	}

	type row struct {
		HostID  string `gorm:"column:host_id"`
		PURL    string `gorm:"column:purl"`
		Version string `gorm:"column:version"`
	}
	var rows []row
	err := r.db.Model(&model.Software{}).
		Select("host_id, purl, version").
		Where("host_id IN ? AND purl != '' AND purl IS NOT NULL", hostIDs).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}

	for _, rec := range rows {
		if _, ok := result[rec.HostID]; !ok {
			result[rec.HostID] = make(map[string]string)
		}
		// 按包身份（去版本、去限定符）建索引；同名多版本时保留最高版本，
		// 与「主机是否已经装上了修复版」这个判断口径一致。
		key := purlIdentity(rec.PURL)
		if existing, ok := result[rec.HostID][key]; !ok || compareVersionStrings(rec.Version, existing) > 0 {
			result[rec.HostID][key] = rec.Version
		}
	}

	return result, nil
}

// DetectResurfaced 检测之前 patched/vanished 现在又匹配上的漏洞 → resurfaced
//
// 触发条件：
//   - status IN (patched, vanished)
//   - software 表中 PURL 重新出现
//   - 之前 vanished → 总是 resurfaced（包又出现了）
//   - 之前 patched → 仅当当前版本退回未达 fix 时 resurfaced（依赖回滚等场景）
//
// 返回标记的数量。每条 resurface 会写 warn 日志（v2 接 alerting 模块）。
func (r *VulnReconciler) DetectResurfaced(hostIDs []string) int {
	if len(hostIDs) == 0 {
		return 0
	}

	currentPkgs, err := r.loadCurrentPURLsByHosts(hostIDs)
	if err != nil {
		r.logger.Error("DetectResurfaced: 取 software 快照失败", zap.Error(err))
		return 0
	}
	osFam := r.loadHostOSFamilies(hostIDs)

	var hvs []model.HostVulnerability
	err = r.db.
		Where("host_id IN ? AND status IN ?", hostIDs,
			[]string{model.HostVulnStatusPatched, model.HostVulnStatusVanished}).
		Find(&hvs).Error
	if err != nil {
		r.logger.Error("DetectResurfaced: 取历史 host_vuln 失败", zap.Error(err))
		return 0
	}

	count := 0
	now := model.LocalTime(time.Now())
	for i := range hvs {
		hv := &hvs[i]

		var vuln model.Vulnerability
		if err := r.db.Select("purl, fixed_version, cve_id").First(&vuln, hv.VulnID).Error; err != nil {
			continue
		}

		hostPkgs := currentPkgs[hv.HostID]
		currentVersion, exists := hostPkgs[purlIdentity(vuln.PURL)]
		if !exists {
			continue
		}

		// 之前 vanished → 总是 resurface
		// 之前 patched → 仅当 version 退回未达 fix 时 resurface（用 per-host fixed + 权威比较器）
		shouldResurface := hv.Status == model.HostVulnStatusVanished
		if !shouldResurface && hv.Status == model.HostVulnStatusPatched {
			if fixed := effectiveFixedVersion(hv, vuln.FixedVersion); fixed != "" {
				if cmp, err := compareInstalledVsFix(osFam[hv.HostID], vuln.PURL, currentVersion, fixed); err == nil && cmp < 0 {
					shouldResurface = true
				}
			}
		}

		if shouldResurface {
			r.db.Model(hv).Updates(map[string]any{
				"status":          model.HostVulnStatusResurfaced,
				"prev_status":     hv.Status,
				"resurfaced_at":   &now,
				"current_version": currentVersion,
			})
			r.logger.Warn("vulnerability resurfaced",
				zap.String("host_id", hv.HostID),
				zap.String("cve_id", vuln.CveID),
				zap.String("prev_status", hv.Status),
				zap.String("current_version", currentVersion),
			)
			count++
		}
	}
	return count
}
