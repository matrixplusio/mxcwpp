package biz

import (
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

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
func (r *VulnReconciler) ReconcileHosts(hostIDs []string) (*ReconcileResult, error) {
	result := &ReconcileResult{}
	if len(hostIDs) == 0 {
		return result, nil
	}

	currentPkgs, err := r.loadCurrentPURLsByHosts(hostIDs)
	if err != nil {
		return nil, err
	}

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
			r.reconcileOne(&hvs[i], currentPkgs, result)
		}
		offset += batchSize
	}

	return result, nil
}

// reconcileOne 处理单条 host_vulnerability
func (r *VulnReconciler) reconcileOne(
	hv *model.HostVulnerability,
	currentPkgs map[string]map[string]string,
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
	currentVersion, exists := hostPkgs[vuln.PURL]

	switch {
	case !exists:
		r.markVanished(hv, model.PatchedReasonPackageRemoved)
		result.Vanished++
	case vuln.FixedVersion != "" &&
		compareVersionStrings(currentVersion, vuln.FixedVersion) >= 0:
		r.markPatched(hv, model.PatchedReasonAutoVersionMatch, currentVersion)
		result.Patched++
	default:
		if currentVersion != "" && currentVersion != hv.CurrentVersion {
			r.db.Model(hv).Update("current_version", currentVersion)
		}
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
		if existing, ok := result[rec.HostID][rec.PURL]; !ok || compareVersionStrings(rec.Version, existing) > 0 {
			result[rec.HostID][rec.PURL] = rec.Version
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
		currentVersion, exists := hostPkgs[vuln.PURL]
		if !exists {
			continue
		}

		// 之前 vanished → 总是 resurface
		// 之前 patched → 仅当 version 退回未达 fix 时 resurface
		shouldResurface := hv.Status == model.HostVulnStatusVanished ||
			(hv.Status == model.HostVulnStatusPatched && vuln.FixedVersion != "" &&
				compareVersionStrings(currentVersion, vuln.FixedVersion) < 0)

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
