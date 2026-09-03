// Package remediation — 漏洞修复状态回写。
package remediation

import (
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PatchVulnerability 将指定漏洞在给定主机（hostIDs 为空则全部主机）上标记为已修复，
// 并同步漏洞的 patched_hosts 计数；当无剩余未修复主机时整体置为 patched。
//
// 抽为独立函数置于中立包，供 manager 漏洞域与 Agent 修复结果回写路径（PreCheckResultHandler）
// 共用，避免下游服务为此反向 import manager/biz。
func PatchVulnerability(db *gorm.DB, vulnID uint, hostIDs []string) error {
	now := model.Now()

	return db.Transaction(func(tx *gorm.DB) error {
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

		return tx.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Updates(updates).Error
	})
}
