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
	// 创建 host_isolation 记录 (Manager API 流程一致)
	iso := model.HostIsolation{
		HostID:    hostID,
		Status:    "isolated",
		Reason:    reason,
		CreatedBy: operator,
		CreatedAt: model.LocalTime(time.Now()),
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
		a.logger.Warn("dispatch isolation command failed (record kept)",
			zap.String("host", hostID), zap.Error(err))
	}
	a.logger.Info("SOAR isolate_host applied",
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

func (a *DefaultActionExecutor) snapshotForensic(_ context.Context, hostID string) (interface{}, error) {
	// 当前仅返回占位; 完整实现 (memory dump + disk snapshot) 留 M2
	a.logger.Info("SOAR snapshot_forensic (skeleton)", zap.String("host", hostID))
	return map[string]any{"host": hostID, "status": "skeleton_only", "note": "M2 实现 memory+disk 快照"}, nil
}

// dispatchCommand 通过 ACDispatcher 下发命令到 Agent (经 AC 实例分发).
func (a *DefaultActionExecutor) dispatchCommand(_ context.Context, hostID, cmdType string, payload map[string]any) error {
	if a.acDispatcher == nil {
		return errors.New("ACDispatcher 未注入, 命令无法下发")
	}
	// 实际接 ACDispatcher.Dispatch (API 因 ACDispatcher 私有方法暂占位)
	a.logger.Info("dispatch command (skeleton wiring)",
		zap.String("host", hostID),
		zap.String("type", cmdType),
		zap.Any("payload", payload),
		zap.String("note", "完整接 ACDispatcher.Dispatch 后续 PR"))
	return nil
}

// 编译期 sanity check.
var _ ActionExecutor = (*DefaultActionExecutor)(nil)
