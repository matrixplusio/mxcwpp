// Package biz — host_vulnerability pre-check 结果回写。
//
// agent 上报 DataType 9201 (kind=precheck_result)，agentcenter Service 路由到这里，
// 写回 host_vulnerabilities.precheck_*。
package biz

import (
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PreCheckResultHandler 处理 agent 上报的 pre-check 结果
type PreCheckResultHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewPreCheckResultHandler(db *gorm.DB, logger *zap.Logger) *PreCheckResultHandler {
	return &PreCheckResultHandler{db: db, logger: logger}
}

// HandleResult fields 来自 agent dataTypePreCheckResult Payload.Fields
//
//	kind         = "precheck_result"
//	request_id   = pc-<id>-<ts>
//	host_vuln_id = uint
//	status       = available / not_installed / outdated_repo / ...
//	message      = 给 UI 的人读提示
//	packages     = JSON: [{name, installed_version, available_version, repo, action}]
func (h *PreCheckResultHandler) HandleResult(agentID string, fields map[string]string) error {
	hvIDStr := fields["host_vuln_id"]
	if hvIDStr == "" {
		return fmt.Errorf("missing host_vuln_id")
	}
	hvID, err := strconv.ParseUint(hvIDStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid host_vuln_id: %s", hvIDStr)
	}

	// 安全校验：上报 agent 必须就是 host_vulnerability 关联的 host_id
	var hv model.HostVulnerability
	if err := h.db.First(&hv, uint(hvID)).Error; err != nil {
		return fmt.Errorf("host_vuln_id %d not found: %w", hvID, err)
	}
	if hv.HostID != agentID {
		return fmt.Errorf("agent %s 无权上报 host_vuln_id %d 的 precheck（属于 %s）",
			agentID, hvID, hv.HostID)
	}

	status := fields["status"]
	if status == "" {
		status = model.PreCheckStatusFailed
	}

	updates := map[string]any{
		"precheck_status":             status,
		"precheck_message":            truncate(fields["message"], 500),
		"precheck_packages":           fields["packages"],
		"precheck_affected_processes": fields["affected_processes"],
		"precheck_checked_at":         model.LocalTime(time.Now()),
	}
	if err := h.db.Model(&model.HostVulnerability{}).Where("id = ?", hvID).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("写回 precheck 结果失败: %w", err)
	}

	h.logger.Info("[PRECHECK] result stored",
		zap.Uint64("host_vuln_id", hvID),
		zap.String("agent_id", agentID),
		zap.String("status", status),
		zap.String("request_id", fields["request_id"]))

	// P5.6: 检查该 host_vuln 是否有处于 main_verifying 状态的修复任务，更新 verify_status
	// 复测判定逻辑：
	//   not_installed / not_in_repo (已升级合并/包已删除) → verified（真修复）
	//   available / available_epel (仍有新版可升) → verify_failed（修复未生效）
	//   outdated_repo / failed                    → verify_blocked（仓库源问题）
	if err := h.applyVerifyResult(uint(hvID), status, fields["message"]); err != nil {
		h.logger.Warn("[PRECHECK] verify task 更新失败", zap.Error(err))
	}
	return nil
}

// applyVerifyResult P5.6: pre-check 结果联动更新 main_verifying 的 task。
// 一个 host_vuln 同时最多 1 个 verifying task（lifecycle 不允许重复），但代码用 batch update 保守处理。
func (h *PreCheckResultHandler) applyVerifyResult(hvID uint, precheckStatus, precheckMessage string) error {
	var hv model.HostVulnerability
	if err := h.db.Select("id, vuln_id, host_id").First(&hv, hvID).Error; err != nil {
		return err
	}

	var verifyStatus, verifyMsg, finalTaskStatus string
	switch precheckStatus {
	case model.PreCheckStatusNotInstalled, model.PreCheckStatusNotInRepo:
		verifyStatus = "verified"
		verifyMsg = "复测通过：" + precheckMessage
		finalTaskStatus = model.RemTaskMainVerified
	case model.PreCheckStatusAvailable, model.PreCheckStatusAvailableEPEL:
		verifyStatus = "verify_failed"
		verifyMsg = "复测失败：仓库仍有可升级版本，说明修复命令未生效。" + precheckMessage
		finalTaskStatus = model.RemTaskMainVerifyFailed
	case model.PreCheckStatusOutdatedRepo, model.PreCheckStatusFailed:
		verifyStatus = "verify_blocked"
		verifyMsg = "复测无法判定：" + precheckMessage
		finalTaskStatus = model.RemTaskMainVerifyBlocked
	default:
		// not_applicable / unchecked 等不更新 task
		return nil
	}

	now := model.Now()
	result := h.db.Model(&model.RemediationTask{}).
		Where("vuln_id = ? AND host_id = ? AND status = ?",
			hv.VulnID, hv.HostID, model.RemTaskMainVerifying).
		Updates(map[string]any{
			"status":         finalTaskStatus,
			"verify_status":  verifyStatus,
			"verify_message": truncate(verifyMsg, 500),
			"verified_at":    now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		// verified 的 task 同时更新 vulnerabilities patched_hosts（复用 remediation service）
		if finalTaskStatus == model.RemTaskMainVerified {
			remSvc := NewRemediationService(h.db, h.logger)
			if err := remSvc.PatchVulnerability(hv.VulnID, []string{hv.HostID}); err != nil {
				h.logger.Warn("[VERIFY] PatchVulnerability 失败",
					zap.Uint("host_vuln_id", hvID), zap.Error(err))
			}
		}
		h.logger.Info("[VERIFY] task 复测结果已更新",
			zap.Uint("host_vuln_id", hvID),
			zap.String("verify_status", verifyStatus),
			zap.Int64("tasks_updated", result.RowsAffected))
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
