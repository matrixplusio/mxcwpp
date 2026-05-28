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

	"github.com/imkerbos/mxsec-platform/internal/server/model"
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
		"precheck_status":     status,
		"precheck_message":    truncate(fields["message"], 500),
		"precheck_packages":   fields["packages"],
		"precheck_checked_at": model.LocalTime(time.Now()),
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
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
