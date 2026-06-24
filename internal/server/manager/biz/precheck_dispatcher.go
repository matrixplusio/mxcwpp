// Package biz — Pre-check 派发统一逻辑。
//
// 复用于：API 单条 trigger / 批量 trigger / cron 周期 / P5.6 task verify。
package biz

import (
	"encoding/json"
	"fmt"
	"time"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"gorm.io/gorm"
)

// PreCheckDispatcher 与 sd.ACDispatcher 抽象接口（precheck_cron.go 已声明同名，重用）

// PreCheckDispatchPayload server → agent pre-check 任务
type PreCheckDispatchPayload struct {
	RequestID              string `json:"request_id"`
	HostVulnID             uint   `json:"host_vuln_id"`
	Component              string `json:"component"`
	FixedVersion           string `json:"fixed_version"`
	CheckAffectedProcesses bool   `json:"check_affected_processes,omitempty"`
}

// DispatchPreCheckForHostVuln 给指定 host_vulnerability 派发 pre-check 任务到 agent。
// 用于 P5.6 task 复测 + cron / API 触发。
//
// requestIDPrefix 用于区分调用源 ("pc" / "pc-cron" / "pc-verify")，便于 log 排查。
func DispatchPreCheckForHostVuln(
	db *gorm.DB,
	dispatcher PreCheckDispatcher,
	hvID uint,
	requestIDPrefix string,
) (requestID string, err error) {
	var hv model.HostVulnerability
	if err := db.First(&hv, hvID).Error; err != nil {
		return "", fmt.Errorf("host_vuln %d 不存在: %w", hvID, err)
	}
	var vuln model.Vulnerability
	if err := db.Select("id, cve_id, component, fixed_version, vuln_category, vuln_category_override").
		First(&vuln, hv.VulnID).Error; err != nil {
		return "", fmt.Errorf("vuln %d 不存在: %w", hv.VulnID, err)
	}
	if vuln.Component == "" {
		return "", fmt.Errorf("vuln.component 为空，无法 pre-check")
	}
	// 优先查 advisory_packages 拿 host OS-specific fixed_version，兜底退回 vulnerabilities.fixed_version
	fixedVer := ResolveFixedVersionForHost(db, vuln.CveID, vuln.Component, hv.HostID)
	if fixedVer == "" {
		fixedVer = vuln.FixedVersion
	}
	requestID = fmt.Sprintf("%s-%d-%d", requestIDPrefix, hv.ID, time.Now().Unix())
	payload := PreCheckDispatchPayload{
		RequestID:              requestID,
		HostVulnID:             hv.ID,
		Component:              vuln.Component,
		FixedVersion:           fixedVer,
		CheckAffectedProcesses: vuln.EffectiveCategory() == model.VulnCategorySharedLib,
	}
	body, _ := json.Marshal(payload)
	cmd := &grpcProto.Command{Tasks: []*grpcProto.Task{{
		DataType:   9101,
		ObjectName: "remediation",
		Data:       string(body),
		Token:      requestID,
	}}}
	if err := dispatcher.SendCommand(hv.HostID, cmd); err != nil {
		return "", fmt.Errorf("dispatch SendCommand 失败: %w", err)
	}
	return requestID, nil
}
