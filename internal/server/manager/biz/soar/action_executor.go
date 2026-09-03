// SOAR ActionExecutor 实际实现 (P3-3).
//
// 把 Playbook 的抽象 ActionKind 落地到具体的 Server 端 / Agent 端动作:
//
//	isolate_host       → AC 下发 host_isolation 命令
//	kill_pid           → AC 下发 process_kill 命令
//	block_ip           → AC 下发 firewall_block IP 命令
//	quarantine_file    → AC 下发 file_quarantine 命令
//	disable_user       → SSH disable + passwd -l
//	revoke_ssh_key     → 删 ~/.ssh/authorized_keys 中 key
//	scan_vuln          → 触发 vuln 扫描任务
//	trigger_av_scan    → 触发 av-scanner full scan
//	snapshot_forensic  → 触发 memory + disk 快照 (M2)

package soar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// DefaultActionExecutor 默认 ActionExecutor (依赖 ACDispatcher 下发命令到 Agent).
type DefaultActionExecutor struct {
	db           *gorm.DB
	acDispatcher *sd.ACDispatcher
	logger       *zap.Logger
}

// host_isolations.status 状态机取值（见 model.HostIsolation）。
const (
	isolationStatusActive = "active"
	isolationStatusFailed = "failed"
)

// NewDefaultActionExecutor 构造.
func NewDefaultActionExecutor(db *gorm.DB, acDispatcher *sd.ACDispatcher, logger *zap.Logger) *DefaultActionExecutor {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DefaultActionExecutor{db: db, acDispatcher: acDispatcher, logger: logger}
}

// Execute 按 ActionKind 派发.
func (a *DefaultActionExecutor) Execute(ctx context.Context, kind ActionKind, params map[string]interface{}, ec *ExecutionContext) (interface{}, error) {
	hostID, _ := params["host_id"].(string)
	if hostID == "" {
		// 从 ExecutionContext vars 取 (ctx-host step 的输出)
		if vars := ec.Vars; vars != nil {
			if ctxHost, ok := vars["ctx-host"].(map[string]interface{}); ok {
				hostID, _ = ctxHost["host_id"].(string)
			}
		}
	}

	switch kind {
	case ActionIsolateHost:
		return a.isolateHost(ctx, hostID, ec.Operator, params)
	case ActionKillPID:
		return a.killPID(ctx, hostID, params)
	case ActionBlockIP:
		return a.blockIP(ctx, hostID, params)
	case ActionQuarantineFile:
		return a.quarantineFile(ctx, hostID, params)
	case ActionDisableUser:
		return a.disableUser(ctx, hostID, params)
	case ActionRevokeSSHKey:
		return a.revokeSSHKey(ctx, hostID, params)
	case ActionScanVuln:
		return a.scanVuln(ctx, hostID)
	case ActionTriggerAVScan:
		return a.triggerAVScan(ctx, hostID, params)
	case ActionSnapshotForensic:
		return a.snapshotForensic(ctx, hostID)
	}
	return nil, fmt.Errorf("unknown action kind: %s", kind)
}

func (a *DefaultActionExecutor) isolateHost(ctx context.Context, hostID, operator string, params map[string]interface{}) (interface{}, error) {
	if hostID == "" {
		return nil, errors.New("host_id required")
	}
	reason, _ := params["reason"].(string)
	if reason == "" {
		reason = "SOAR Playbook 自动隔离"
	}
	// 同一主机同时只能有一条 active 隔离（见 model.HostIsolation 注释）。
	// 与 Manager API 流程一致，避免 SOAR 绕过该约束写出重复 active 记录。
	var existing model.HostIsolation
	if err := a.db.WithContext(ctx).
		Where("host_id = ? AND status = ?", hostID, isolationStatusActive).
		First(&existing).Error; err == nil {
		return nil, fmt.Errorf("主机已处于隔离状态 (isolation_id=%d)", existing.ID)
	}

	// 创建 host_isolation 记录 (Manager API 流程一致)。
	// 状态必须取自 model.HostIsolation 定义的状态机 pending/active/released/failed：
	// 原实现写的 "isolated" 不在状态机内，既让 status='active' 查询漏掉这条记录，
	// 也绕过了"同时只能一条 active 隔离"的约束。
	now := model.Now()
	iso := model.HostIsolation{
		HostID:     hostID,
		Status:     isolationStatusActive,
		Reason:     reason,
		Source:     "auto_response",
		CreatedBy:  operator,
		IsolatedAt: &now,
	}
	if err := a.db.WithContext(ctx).Create(&iso).Error; err != nil {
		return nil, fmt.Errorf("create isolation: %w", err)
	}
	// AC 下发隔离命令 (走 ACDispatcher)
	cmd := map[string]any{
		"action":       "isolate",
		"reason":       reason,
		"isolation_id": iso.ID,
	}
	if err := a.dispatchCommand(ctx, hostID, "host_isolation", cmd); err != nil {
		// 下发失败即隔离未生效。记录必须落 failed 并把错误返回，绝不能像原实现那样
		// 降级成 warning 还保留 "已隔离" 记录并返回 success——那会让值班以为主机已隔离
		// 而停止处置，攻击者仍在运行。
		a.db.WithContext(ctx).Model(&iso).Update("status", isolationStatusFailed)
		a.logger.Error("SOAR isolate_host 下发失败，隔离未生效",
			zap.String("host", hostID), zap.Uint("isolation_id", iso.ID), zap.Error(err))
		return nil, fmt.Errorf("下发隔离命令失败 (isolation_id=%d): %w", iso.ID, err)
	}
	a.logger.Warn("SOAR isolate_host applied",
		zap.String("host", hostID), zap.String("operator", operator))
	return map[string]any{"isolation_id": iso.ID, "host_id": hostID}, nil
}

func (a *DefaultActionExecutor) killPID(ctx context.Context, hostID string, params map[string]interface{}) (interface{}, error) {
	pid, _ := params["pid"].(float64)
	signal, _ := params["signal"].(string)
	if signal == "" {
		signal = "SIGKILL"
	}
	if pid == 0 {
		return nil, errors.New("pid required")
	}
	cmd := map[string]any{
		"action": "kill",
		"pid":    int32(pid),
		"signal": signal,
	}
	if err := a.dispatchCommand(ctx, hostID, "process_kill", cmd); err != nil {
		return nil, err
	}
	return map[string]any{"dispatched": true, "pid": int32(pid)}, nil
}

func (a *DefaultActionExecutor) blockIP(ctx context.Context, hostID string, params map[string]interface{}) (interface{}, error) {
	ip, _ := params["ip"].(string)
	if ip == "" {
		return nil, errors.New("ip required")
	}
	durationMin, _ := params["duration_min"].(float64)
	if durationMin == 0 {
		durationMin = 60
	}
	cmd := map[string]any{
		"action":       "block",
		"ip":           ip,
		"duration_min": int(durationMin),
	}
	if err := a.dispatchCommand(ctx, hostID, "firewall_block", cmd); err != nil {
		return nil, err
	}
	a.logger.Info("SOAR block_ip applied",
		zap.String("host", hostID), zap.String("ip", ip),
		zap.Int("duration_min", int(durationMin)))
	return map[string]any{"blocked_ip": ip, "duration_min": int(durationMin)}, nil
}

func (a *DefaultActionExecutor) quarantineFile(ctx context.Context, hostID string, params map[string]interface{}) (interface{}, error) {
	path, _ := params["path"].(string)
	triggerRule, _ := params["trigger_rule"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	cmd := map[string]any{
		"action":       "quarantine",
		"path":         path,
		"trigger_rule": triggerRule,
	}
	if err := a.dispatchCommand(ctx, hostID, "file_quarantine", cmd); err != nil {
		return nil, err
	}
	return map[string]any{"quarantined_path": path}, nil
}

func (a *DefaultActionExecutor) disableUser(ctx context.Context, hostID string, params map[string]interface{}) (interface{}, error) {
	username, _ := params["username"].(string)
	if username == "" {
		return nil, errors.New("username required")
	}
	cmd := map[string]any{
		"action":   "disable_user",
		"username": username,
	}
	if err := a.dispatchCommand(ctx, hostID, "user_disable", cmd); err != nil {
		return nil, err
	}
	return map[string]any{"disabled_user": username}, nil
}

func (a *DefaultActionExecutor) revokeSSHKey(ctx context.Context, hostID string, params map[string]interface{}) (interface{}, error) {
	username, _ := params["username"].(string)
	keyFingerprint, _ := params["key_fingerprint"].(string)
	if username == "" || keyFingerprint == "" {
		return nil, errors.New("username and key_fingerprint required")
	}
	cmd := map[string]any{
		"action":          "revoke_ssh_key",
		"username":        username,
		"key_fingerprint": keyFingerprint,
	}
	if err := a.dispatchCommand(ctx, hostID, "ssh_key_revoke", cmd); err != nil {
		return nil, err
	}
	return map[string]any{"revoked": keyFingerprint, "user": username}, nil
}

func (a *DefaultActionExecutor) scanVuln(ctx context.Context, hostID string) (interface{}, error) {
	if hostID == "" {
		return nil, errors.New("host_id required")
	}
	// 触发 VulnScanTask (复用现有 biz.NewVulnScanner)
	task := model.VulnScanTask{
		TenantID:      "t-default",
		TaskID:        fmt.Sprintf("soar-%d", time.Now().Unix()),
		Scope:         "hosts",
		TargetHostIDs: []byte(fmt.Sprintf(`["%s"]`, hostID)),
		Status:        "pending",
	}
	if err := a.db.WithContext(ctx).Create(&task).Error; err != nil {
		return nil, err
	}
	return map[string]any{"vuln_task_id": task.ID, "host_id": hostID}, nil
}

func (a *DefaultActionExecutor) triggerAVScan(ctx context.Context, hostID string, params map[string]interface{}) (interface{}, error) {
	scanType, _ := params["scan_type"].(string)
	if scanType == "" {
		scanType = "full"
	}
	task := model.AntivirusScanTask{
		TenantID: "t-default",
		Name:     fmt.Sprintf("SOAR av-scan host=%s", hostID),
		ScanType: scanType,
		HostIDs:  model.StringArray{hostID},
		Status:   "pending",
	}
	if err := a.db.WithContext(ctx).Create(&task).Error; err != nil {
		return nil, err
	}
	cmd := map[string]any{
		"action":    "av_scan",
		"scan_type": scanType,
		"task_id":   task.ID,
	}
	if err := a.dispatchCommand(ctx, hostID, "av_scan_request", cmd); err != nil {
		a.logger.Warn("dispatch av scan failed (record kept)",
			zap.String("host", hostID), zap.Error(err))
	}
	return map[string]any{"av_task_id": task.ID, "scan_type": scanType}, nil
}

// snapshotForensic 取证快照 (memory dump + disk snapshot) 尚未实现。
// 原实现返回 status="skeleton_only" 且 err=nil，Playbook 因此记为 success——
// 界面会显示已完成取证快照，而实际没有任何快照产生。
func (a *DefaultActionExecutor) snapshotForensic(_ context.Context, hostID string) (interface{}, error) {
	a.logger.Error("SOAR snapshot_forensic 未实现，未产生任何快照", zap.String("host", hostID))
	return nil, fmt.Errorf("取证快照未实现 (memory dump + disk snapshot): %w", ErrActionNotImplemented)
}

// ErrActionNotImplemented 表示该处置动作尚未接线，命令不会到达主机。
//
// 返回错误而非 nil 是刻意的：这些动作原本 return nil，于是 Playbook 记 success、
// 界面显示"已处置"，而实际什么都没发生。在安全产品里这是最坏的一种失败——
// 值班看到"已隔离/已阻断"就停止响应，攻击者却仍在运行。未接线就必须报未接线。
var ErrActionNotImplemented = errors.New("该处置动作尚未接线到 AC 下发链路，命令不会到达主机")

// dispatchCommand 通过 ACDispatcher 下发命令到 Agent (经 AC 实例分发).
//
// 尚未接线：ACDispatcher.Dispatch 为私有方法，接入留后续 PR。在接通之前一律返回
// ErrActionNotImplemented，绝不返回 nil 让调用方误以为命令已下发。
func (a *DefaultActionExecutor) dispatchCommand(_ context.Context, hostID, cmdType string, payload map[string]any) error {
	if a.acDispatcher == nil {
		return errors.New("ACDispatcher 未注入, 命令无法下发")
	}
	a.logger.Error("SOAR 动作未接线，命令未下发",
		zap.String("host", hostID),
		zap.String("type", cmdType),
		zap.Any("payload", payload))
	return ErrActionNotImplemented
}

// 编译期 sanity check.
var _ ActionExecutor = (*DefaultActionExecutor)(nil)
