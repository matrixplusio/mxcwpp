// Package remediation 提供漏洞修复任务派发与 Agent 结果/进度处理，跨服务共享。
package remediation

import (
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// RemediationDataType 漏洞修复任务的 DataType
	// 注意：不能使用 9000/9001，9000 是 Agent→Plugin 心跳 Ping，9001 是 Pong
	// 插件 SDK 的 ReceiveTask() 会拦截 DataType=9000 作为心跳自动回复，导致任务被吞
	RemediationDataType = 9100
	// RemediationPluginName Agent 端处理修复任务的插件名称
	RemediationPluginName = "remediation"
)

// RemediationExecutor 修复任务执行器
type RemediationExecutor struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewRemediationExecutor 创建修复任务执行器
func NewRemediationExecutor(db *gorm.DB, logger *zap.Logger) *RemediationExecutor {
	return &RemediationExecutor{db: db, logger: logger}
}

// RemediationTaskPayload 下发给 Agent 的修复任务数据
type RemediationTaskPayload struct {
	TaskID       uint   `json:"task_id"`
	CveID        string `json:"cve_id"`
	Component    string `json:"component"`
	FixedVersion string `json:"fixed_version"`
	Command      string `json:"command"`
	DryRun       bool   `json:"dry_run"`
}

const (
	// remediationPendingTimeout 待确认超时：创建后 24 小时无人确认则自动取消
	remediationPendingTimeout = 24 * time.Hour
	// remediationConfirmedTimeout 等待 Agent 超时：确认后 1 小时 Agent 未拉取则标记失败
	remediationConfirmedTimeout = 1 * time.Hour
	// remediationRunningTimeout 执行超时：running 状态超过 30 分钟视为失败
	remediationRunningTimeout = 30 * time.Minute
)

// DispatchConfirmedTasks 分发已确认的修复任务到 Agent
func (e *RemediationExecutor) DispatchConfirmedTasks(transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 超时处理
	e.SweepTimeouts()

	// 查询已确认待执行的任务
	var tasks []model.RemediationTask
	if err := e.db.Where("status = ?", "confirmed").Find(&tasks).Error; err != nil {
		return fmt.Errorf("查询已确认修复任务失败: %w", err)
	}

	if len(tasks) == 0 {
		return nil
	}

	e.logger.Info("发现待执行修复任务", zap.Int("count", len(tasks)))

	for i := range tasks {
		if err := e.dispatchTask(&tasks[i], transferService); err != nil {
			e.logger.Error("下发修复任务失败",
				zap.Uint("task_id", tasks[i].ID),
				zap.String("host_id", tasks[i].HostID),
				zap.Error(err),
			)
			continue
		}
	}

	return nil
}

// SweepTimeouts 推进所有修复任务的超时状态转移（pending 取消 / confirmed / running 置失败）。
// 由 DispatchConfirmedTasks 每轮调度前调用；亦作为可被独立触发的公开入口。
func (e *RemediationExecutor) SweepTimeouts() {
	e.timeoutPendingTasks()
	e.timeoutConfirmedTasks()
	e.timeoutRunningTasks()
}

// timeoutPendingTasks 将超时的 pending 任务自动取消
func (e *RemediationExecutor) timeoutPendingTasks() {
	cutoff := time.Now().Add(-remediationPendingTimeout)

	result := e.db.Model(&model.RemediationTask{}).
		Where("status = ? AND created_at < ?", "pending", cutoff).
		Updates(map[string]any{
			"status": "cancelled",
		})

	if result.RowsAffected > 0 {
		e.logger.Warn("待确认修复任务超时自动取消", zap.Int64("count", result.RowsAffected))
	}
}

// timeoutConfirmedTasks 将超时的 confirmed 任务标记为 failed
func (e *RemediationExecutor) timeoutConfirmedTasks() {
	cutoff := time.Now().Add(-remediationConfirmedTimeout)
	now := model.Now()

	result := e.db.Model(&model.RemediationTask{}).
		Where("status = ? AND confirmed_at < ?", "confirmed", cutoff).
		Updates(map[string]any{
			"status":      "failed",
			"exec_output": "任务超时：确认后 Agent 未在规定时间内拉取任务，请检查目标主机 Agent 是否在线",
			"finished_at": now,
		})

	if result.RowsAffected > 0 {
		e.logger.Warn("已确认修复任务等待 Agent 超时", zap.Int64("count", result.RowsAffected))
	}
}

// timeoutRunningTasks 将超时的 running 任务标记为 failed
func (e *RemediationExecutor) timeoutRunningTasks() {
	cutoff := time.Now().Add(-remediationRunningTimeout)
	now := model.Now()

	result := e.db.Model(&model.RemediationTask{}).
		Where("status = ? AND started_at < ?", "running", cutoff).
		Updates(map[string]any{
			"status":      "failed",
			"exec_output": "任务超时：Agent 未在规定时间内返回结果，可能主机已离线或命令执行超时",
			"finished_at": now,
		})

	if result.RowsAffected > 0 {
		e.logger.Warn("修复任务超时标记为失败", zap.Int64("count", result.RowsAffected))
	}
}

// dispatchTask 下发单个修复任务
func (e *RemediationExecutor) dispatchTask(task *model.RemediationTask, transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 检查主机是否在线
	var host model.Host
	if err := e.db.Where("host_id = ? AND status = ?", task.HostID, "online").First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			e.logger.Debug("目标主机不在线，等待下次调度",
				zap.Uint("task_id", task.ID),
				zap.String("host_id", task.HostID))
			return nil
		}
		return fmt.Errorf("查询主机状态失败: %w", err)
	}

	// 先更新状态为 running（防止重复下发）
	now := model.Now()
	result := e.db.Model(task).
		Where("status = ?", "confirmed"). // CAS: 只有 confirmed 状态才能转 running
		Updates(map[string]any{
			"status":     "running",
			"started_at": now,
		})
	if result.RowsAffected == 0 {
		// 状态已被其他调度实例改变，跳过
		return nil
	}

	// 构建任务数据
	payload := RemediationTaskPayload{
		TaskID:       task.ID,
		CveID:        task.CveID,
		Component:    task.Component,
		FixedVersion: task.FixedVersion,
		Command:      task.Command,
		DryRun:       false,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		// 回滚状态
		e.db.Model(task).Updates(map[string]any{"status": "confirmed", "started_at": nil})
		return fmt.Errorf("序列化任务数据失败: %w", err)
	}

	// 构建 gRPC Task
	grpcTask := &grpcProto.Task{
		DataType:   RemediationDataType,
		ObjectName: RemediationPluginName,
		Data:       string(payloadJSON),
		Token:      fmt.Sprintf("rem-%d", task.ID),
	}

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{grpcTask},
	}

	// 发送命令
	if err := transferService.SendCommand(host.HostID, cmd); err != nil {
		// 发送失败，回滚状态，下次调度重试
		e.db.Model(task).Updates(map[string]any{"status": "confirmed", "started_at": nil})
		return fmt.Errorf("发送修复命令失败: %w", err)
	}

	e.logger.Info("修复任务已下发",
		zap.Uint("task_id", task.ID),
		zap.String("host_id", task.HostID),
		zap.String("cve_id", task.CveID),
	)

	return nil
}

// HandleProgress 处理 Agent 上报的修复阶段进度事件（DataType 9201）。
//
// fields 来自 plugin sendProgress：
//
//	task_id / token / stage (detect_os|check_installed|...) / message / detail
//
// 写入 remediation_task_events，UI 通过 SSE 订阅实时显示。
// 同时同步 RemediationTask.Status 反映当前 stage（用于列表页快速渲染）。
func (e *RemediationExecutor) HandleProgress(agentID string, data map[string]string) error {
	taskIDStr, ok := data["task_id"]
	if !ok || taskIDStr == "" {
		return fmt.Errorf("missing task_id in remediation progress")
	}
	var taskID uint
	if _, err := fmt.Sscanf(taskIDStr, "%d", &taskID); err != nil {
		return fmt.Errorf("invalid task_id: %s", taskIDStr)
	}

	var task model.RemediationTask
	if err := e.db.First(&task, taskID).Error; err != nil {
		return fmt.Errorf("task not found: %d", taskID)
	}
	if task.HostID != agentID {
		return fmt.Errorf("agent %s 无权上报任务 %d 进度", agentID, taskID)
	}

	stage := data["stage"]
	message := data["message"]
	detail := data["detail"]

	// 写 events 表（sequence = 当前 task 已有 event 数 + 1）
	var seq int64
	e.db.Model(&model.RemediationTaskEvent{}).Where("task_id = ?", taskID).Count(&seq)
	event := &model.RemediationTaskEvent{
		TaskID:   taskID,
		Sequence: uint(seq + 1),
		Stage:    stage,
		Message:  message,
		Detail:   detail,
		Source:   "plugin",
	}
	if err := e.db.Create(event).Error; err != nil {
		e.logger.Warn("写 remediation_task_event 失败",
			zap.Uint("task_id", taskID), zap.String("stage", stage), zap.Error(err))
	}

	// 同步 task 状态（仅当 stage 在已知 lifecycle 列表内）
	if isValidLifecycleStage(stage) {
		if err := e.db.Model(&task).Update("status", stage).Error; err != nil {
			e.logger.Warn("同步 task status 失败",
				zap.Uint("task_id", taskID), zap.String("stage", stage), zap.Error(err))
		}
	}
	return nil
}

func isValidLifecycleStage(s string) bool {
	switch s {
	case model.RemTaskStatusPreCheck,
		model.RemTaskStatusDownload,
		model.RemTaskStatusInstall,
		model.RemTaskStatusVerifying,
		"detect_os", "check_installed", "check_available":
		return true
	}
	return false
}

// HandleResult 处理 Agent 上报的修复执行结果
// DataType = 9001
func (e *RemediationExecutor) HandleResult(agentID string, data map[string]string) error {
	taskIDStr, ok := data["task_id"]
	if !ok {
		return fmt.Errorf("missing task_id in remediation result")
	}

	var taskID uint
	if _, err := fmt.Sscanf(taskIDStr, "%d", &taskID); err != nil {
		return fmt.Errorf("invalid task_id: %s", taskIDStr)
	}

	var task model.RemediationTask
	if err := e.db.First(&task, taskID).Error; err != nil {
		return fmt.Errorf("task not found: %d", taskID)
	}

	// 安全校验：确认上报 Agent 就是任务目标主机
	if task.HostID != agentID {
		return fmt.Errorf("agent %s 无权上报任务 %d 的结果（目标主机为 %s）", agentID, taskID, task.HostID)
	}

	// 状态校验：只忽略「已终结」任务的重复结果。任务在 agent 执行期间，status 会被 9201
	// 进度事件推进为各 stage 名（detect_os / check_installed / check_available / downloading /
	// installing / verifying），此时收到最终 result(9200) 必须处理——若沿用旧的
	// `!= "running"` 判据，会因 status 已是 stage 名而丢弃结果，任务永远停在最后 stage，
	// 掩盖 agent 早已回报的真实成败（本次 vim/ kernel 修复"看似 hang"的真因）。
	switch task.Status {
	case model.RemTaskMainSuccess, model.RemTaskMainSuccessPendingVerify,
		model.RemTaskMainVerifying, model.RemTaskMainVerified,
		model.RemTaskMainVerifyFailed, model.RemTaskMainVerifyBlocked,
		model.RemTaskMainCancelled, model.RemTaskStatusFailed,
		model.RemTaskStatusCompleted, model.RemTaskStatusRolledBack:
		e.logger.Warn("收到已终结任务的修复结果，忽略",
			zap.Uint("task_id", taskID),
			zap.String("current_status", task.Status))
		return nil
	}

	exitCodeStr := data["exit_code"]
	var exitCode int
	_, _ = fmt.Sscanf(exitCodeStr, "%d", &exitCode)

	stdout := data["stdout"]
	stderr := data["stderr"]
	output := stdout
	if stderr != "" {
		if output != "" {
			output += "\n--- STDERR ---\n" + stderr
		} else {
			output = stderr
		}
	}
	if output == "" {
		if exitCode == 0 {
			output = "命令执行成功（无输出）"
		} else {
			output = fmt.Sprintf("命令执行失败，退出码 %d（无输出）", exitCode)
		}
	}

	now := model.Now()
	// P5.6: agent exit 0 不再直接 success，改 success_pending_verify 等 user 手动确认
	// 老的 success 路径保留作为兼容（如果调用方传入 success 状态外部）
	status := model.RemTaskMainSuccessPendingVerify
	if exitCode != 0 {
		status = "failed"
		// 对失败任务进行错误诊断，追加中文提示帮助用户定位问题
		if diagnosis := DiagnoseError(stdout, stderr); diagnosis != "" {
			output += "\n\n--- 诊断建议 ---\n" + diagnosis
		}
	}

	updates := map[string]any{
		"status":      status,
		"exec_output": output,
		"exit_code":   exitCode,
		"finished_at": now,
	}

	if err := e.db.Model(&task).Updates(updates).Error; err != nil {
		return fmt.Errorf("update task status failed: %w", err)
	}

	// P5.6: success_pending_verify 仅设状态等 user，不自动 verify / 不自动 patch vulnerability。
	// 真 patched 标识在 verify 完成后才落（biz/precheck_result.go 中处理）。

	// P4: 命令成功后清 precheck cache，user 点"确认已执行"会触发 pre-check 复测
	if status == model.RemTaskMainSuccessPendingVerify {
		if err := e.db.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND host_id = ?", task.VulnID, task.HostID).
			Updates(map[string]any{
				"precheck_status":     model.PreCheckStatusUnchecked,
				"precheck_message":    "修复任务执行后已重置，等待复扫验证",
				"precheck_packages":   "",
				"precheck_checked_at": nil,
			}).Error; err != nil {
			e.logger.Warn("清 precheck cache 失败",
				zap.Uint("task_id", taskID), zap.Error(err))
		}
	}

	e.logger.Info("修复任务结果已处理",
		zap.Uint("task_id", taskID),
		zap.String("agent_id", agentID),
		zap.String("status", status),
		zap.Int("exit_code", exitCode),
	)

	return nil
}
