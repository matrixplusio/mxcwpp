// Package api — host vulnerability pre-check endpoints.
//
// 让 agent 在 host 本地查询「已装包列表 + 仓库可用版本」，避免靠 server vuln DB 字符串
// 直接拼 dnf 命令（多次踩坑：fixed_version="0" / Debian 包给 CentOS / repo 不存在）。
//
// Flow:
//
//	UI -> POST /host-vulnerabilities/:id/precheck            (单条)
//	   -> POST /hosts/:host_id/precheck-all                  (批量该 host unpatched)
//	   -> dispatcher.SendCommand(agent, DataType 9101)
//	   -> agent plugin handlePreCheck（已在 plugins/remediation/precheck.go）
//	   -> agent 上报 DataType 9201 (kind=precheck_result)
//	   -> agentcenter Service.HandlePreCheckResult
//	   -> biz.WritePreCheckResult -> host_vulnerabilities.precheck_*
//	   -> UI 周期 GET 看新状态
package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// PreCheck DataType（与 plugin 端 dataTypePreCheckPush 对齐）
const preCheckDataType int32 = 9101

// HostVulnPreCheckHandler 主机漏洞预检 API
type HostVulnPreCheckHandler struct {
	db         *gorm.DB
	logger     *zap.Logger
	dispatcher *sd.ACDispatcher
}

func NewHostVulnPreCheckHandler(db *gorm.DB, logger *zap.Logger, dispatcher *sd.ACDispatcher) *HostVulnPreCheckHandler {
	return &HostVulnPreCheckHandler{db: db, logger: logger, dispatcher: dispatcher}
}

// preCheckTaskPayload 下发给 agent 的 pre-check 任务
type preCheckTaskPayload struct {
	RequestID    string `json:"request_id"`
	HostVulnID   uint   `json:"host_vuln_id"`
	Component    string `json:"component"`
	FixedVersion string `json:"fixed_version"`
}

// CreateForHostVuln 单条 host_vulnerability pre-check
// POST /api/v1/host-vulnerabilities/:id/precheck
func (h *HostVulnPreCheckHandler) CreateForHostVuln(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "invalid id")
		return
	}
	var hv model.HostVulnerability
	if err := h.db.First(&hv, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "host vulnerability 不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}
	if err := h.dispatchPreCheck(&hv); err != nil {
		InternalError(c, err.Error())
		return
	}
	Success(c, gin.H{
		"hostVulnId": hv.ID,
		"hostId":     hv.HostID,
		"component":  "scheduled", // agent 异步执行，结果通过 9201 异步回报
	})
}

// CreateForHostAll 该 host 全部 unpatched 漏洞批量 pre-check
// POST /api/v1/hosts/:host_id/precheck-all
func (h *HostVulnPreCheckHandler) CreateForHostAll(c *gin.Context) {
	hostID := c.Param("host_id")
	if hostID == "" {
		BadRequest(c, "missing host_id")
		return
	}
	var host model.Host
	if err := h.db.Select("host_id, status").Where("host_id = ?", hostID).First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "host 不存在")
			return
		}
		InternalError(c, "查询 host 失败")
		return
	}
	if host.Status != model.HostStatusOnline {
		BadRequest(c, "host 不在线，无法 pre-check")
		return
	}

	var hvs []model.HostVulnerability
	// 默认只 pre-check unchecked / failed / >24h 过期的（避免重复打包管理器）
	cutoff := time.Now().Add(-24 * time.Hour)
	if err := h.db.Where(
		"host_id = ? AND status = ? AND (precheck_status = ? OR precheck_status = ? OR precheck_checked_at IS NULL OR precheck_checked_at < ?)",
		hostID, "unpatched",
		model.PreCheckStatusUnchecked, model.PreCheckStatusFailed,
		cutoff,
	).Find(&hvs).Error; err != nil {
		InternalError(c, "查询 host_vulnerabilities 失败")
		return
	}

	if len(hvs) == 0 {
		Success(c, gin.H{"scheduled": 0, "message": "无需要 pre-check 的漏洞"})
		return
	}

	scheduled := 0
	failed := 0
	for i := range hvs {
		if err := h.dispatchPreCheck(&hvs[i]); err != nil {
			h.logger.Warn("dispatch precheck failed",
				zap.Uint("id", hvs[i].ID), zap.Error(err))
			failed++
			continue
		}
		scheduled++
	}

	Success(c, gin.H{
		"hostId":    hostID,
		"scheduled": scheduled,
		"failed":    failed,
		"total":     len(hvs),
	})
}

// dispatchPreCheck 向 agent 推一条 pre-check 任务
func (h *HostVulnPreCheckHandler) dispatchPreCheck(hv *model.HostVulnerability) error {
	// 查 vuln.component / vuln.fixed_version
	var vuln model.Vulnerability
	if err := h.db.Select("id, component, fixed_version").First(&vuln, hv.VulnID).Error; err != nil {
		return fmt.Errorf("查询 vuln 失败: %w", err)
	}
	if vuln.Component == "" {
		// 标 not_in_repo，避免反复 dispatch
		h.db.Model(hv).Updates(map[string]any{
			"precheck_status":     model.PreCheckStatusFailed,
			"precheck_message":    "vuln.component 为空，无法 pre-check",
			"precheck_checked_at": model.Now(),
		})
		return fmt.Errorf("vuln.component 为空")
	}

	requestID := fmt.Sprintf("pc-%d-%d", hv.ID, time.Now().Unix())
	payload := preCheckTaskPayload{
		RequestID:    requestID,
		HostVulnID:   hv.ID,
		Component:    vuln.Component,
		FixedVersion: vuln.FixedVersion,
	}
	body, _ := json.Marshal(payload)

	grpcTask := &grpcProto.Task{
		DataType:   preCheckDataType,
		ObjectName: "remediation",
		Data:       string(body),
		Token:      requestID,
	}
	cmd := &grpcProto.Command{Tasks: []*grpcProto.Task{grpcTask}}
	if err := h.dispatcher.SendCommand(hv.HostID, cmd); err != nil {
		return fmt.Errorf("dispatch SendCommand 失败: %w", err)
	}
	// 标 running 状态（unchecked → 推送中，agent 回报后变 final 状态）
	// 不立即覆盖 precheck_status，避免 race；只更新 checked_at 反映"已 dispatch"
	return nil
}
