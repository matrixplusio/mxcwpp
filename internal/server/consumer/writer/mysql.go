// Package writer 提供 Consumer 侧的存储写入器
package writer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/service"
	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// MySQLWriter 将 MQMessage 解码后幂等写入 MySQL
type MySQLWriter struct {
	db           *gorm.DB
	logger       *zap.Logger
	assetService *service.AssetService

	// P1-2: 异步通知 goroutine semaphore, 限并发避免无界 goroutine 风暴.
	// 默认 200, FIM/病毒 高 EPS 时通知发送被限流不阻塞 hot path.
	notifySem chan struct{}
}

// NewMySQLWriter 创建 MySQLWriter
func NewMySQLWriter(db *gorm.DB, logger *zap.Logger) *MySQLWriter {
	return &MySQLWriter{
		db:           db,
		logger:       logger,
		assetService: service.NewAssetService(db, logger),
		notifySem:    make(chan struct{}, 200),
	}
}

// runAsyncNotify P1-2: semaphore 限并发跑后台通知.
// 队列满 → drop 通知 (调用方失败仅 metrics, 不重试).
func (w *MySQLWriter) runAsyncNotify(name string, fn func()) {
	select {
	case w.notifySem <- struct{}{}:
		go func() {
			defer func() { <-w.notifySem }()
			defer func() {
				if r := recover(); r != nil {
					w.logger.Error("async notify panic recovered",
						zap.String("kind", name),
						zap.Any("panic", r))
				}
			}()
			fn()
		}()
	default:
		w.logger.Warn("async notify queue full, drop", zap.String("kind", name))
	}
}

// DB 返回内部 gorm.DB，供 consumer Router 等需要直接读写表的子模块使用。
func (w *MySQLWriter) DB() *gorm.DB {
	return w.db
}

// WriteBaseline 处理基线检查结果（DataType 8000），ON DUPLICATE KEY UPDATE 保证幂等
// 复合主键 (task_id, host_id, rule_id) 天然保证跨主机去重，无需人造 result_id
func (w *MySQLWriter) WriteBaseline(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析基线结果失败: %w", err)
	}

	// 丢弃已取消任务的结果
	if taskID := fields["task_id"]; taskID != "" {
		var status string
		if err := w.db.Model(&model.ScanTask{}).Select("status").
			Where("task_id = ?", taskID).Scan(&status).Error; err == nil && status == string(model.TaskStatusCancelled) {
			w.logger.Debug("丢弃已取消任务的结果", zap.String("task_id", taskID))
			return nil
		}
	}

	result := &model.ScanResult{
		TaskID:        fields["task_id"],
		HostID:        msg.AgentID,
		RuleID:        fields["rule_id"],
		Hostname:      msg.Hostname,
		PolicyID:      fields["policy_id"],
		PolicyName:    fields["policy_name"],
		Status:        model.ResultStatus(fields["status"]),
		Severity:      fields["severity"],
		Category:      fields["category"],
		Title:         fields["title"],
		Actual:        fields["actual"],
		Expected:      fields["expected"],
		FixSuggestion: fields["fix_suggestion"],
		CheckedAt:     model.LocalTime(time.Unix(msg.AgentTime, 0)),
	}

	return w.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "task_id"}, {Name: "host_id"}, {Name: "rule_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "actual", "checked_at"}),
	}).Create(result).Error
}

// WriteHeartbeat 处理 Agent 心跳（DataType 1000），upsert hosts 表
func (w *MySQLWriter) WriteHeartbeat(msg *kafka.MQMessage) error {
	now := model.LocalTime(time.Unix(msg.AgentTime, 0))

	var ipv4 model.StringArray
	if msg.IntranetIPv4 != "" {
		ipv4 = model.StringArray{msg.IntranetIPv4}
	}
	var publicIPv4 model.StringArray
	if msg.ExtranetIPv4 != "" {
		publicIPv4 = model.StringArray{msg.ExtranetIPv4}
	}

	host := &model.Host{
		HostID:        msg.AgentID,
		Hostname:      msg.Hostname,
		Status:        model.HostStatusOnline,
		LastHeartbeat: &now,
		AgentVersion:  msg.Version,
		IPv4:          ipv4,
		PublicIPv4:    publicIPv4,
	}

	return w.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "host_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"hostname", "status", "last_heartbeat", "agent_version",
			"ipv4", "public_ipv4",
		}),
	}).Create(host).Error
}

// WriteFIMEvent 处理 FIM 事件（DataType 6001），result_id 唯一约束保证幂等
func (w *MySQLWriter) WriteFIMEvent(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析 FIM 事件失败: %w", err)
	}

	eventID := fields["event_id"]
	if eventID == "" {
		return fmt.Errorf("FIM 事件缺少 event_id")
	}

	event := &model.FIMEvent{
		EventID:    eventID,
		HostID:     msg.AgentID,
		Hostname:   msg.Hostname,
		TaskID:     fields["task_id"],
		FilePath:   fields["file_path"],
		ChangeType: fields["change_type"],
		Severity:   fields["severity"],
		Category:   fields["category"],
		DetectedAt: model.LocalTime(time.Unix(msg.AgentTime, 0)),
	}

	// 解析 change_detail（可选字段）
	if cdStr := fields["change_detail"]; cdStr != "" {
		var cd model.ChangeDetail
		if err := json.Unmarshal([]byte(cdStr), &cd); err == nil {
			event.ChangeDetail = cd
		}
	}

	// 忽略重复插入（Consumer 重放时可能重复）
	result := w.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "event_id"}},
		DoNothing: true,
	}).Create(event)
	if result.Error != nil {
		return result.Error
	}

	// 仅新插入的记录才发送通知（RowsAffected == 0 表示被 OnConflict 跳过了）
	if result.RowsAffected > 0 {
		e := event
		w.runAsyncNotify("fim", func() {
			var host model.Host
			ip := ""
			if w.db.Select("ipv4").First(&host, "host_id = ?", e.HostID).Error == nil && len(host.IPv4) > 0 {
				ip = host.IPv4[0]
			}
			ns := biz.NewNotificationService(w.db, w.logger)
			if err := ns.SendFIMAlertNotification(&biz.FIMAlertData{
				HostID:     e.HostID,
				Hostname:   e.Hostname,
				IP:         ip,
				FilePath:   e.FilePath,
				ChangeType: e.ChangeType,
				Category:   e.Category,
				Severity:   e.Severity,
				DetectedAt: e.DetectedAt.Time(),
			}); err != nil {
				w.logger.Error("发送 FIM 告警通知失败", zap.Error(err))
			}
		})
	}

	return nil
}

// WriteTaskCompletion 处理基线扫描任务完成信号（DataType 8001）
// 更新 task_host_status + scan_tasks.completed_host_count
// 幂等保护：仅当 TaskHostStatus 实际发生状态转移时才递增计数
func (w *MySQLWriter) WriteTaskCompletion(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析任务完成信号失败: %w", err)
	}

	taskID := fields["task_id"]
	if taskID == "" {
		return fmt.Errorf("任务完成信号缺少 task_id")
	}

	// 丢弃已取消任务的完成信号
	var taskStatus string
	if err := w.db.Model(&model.ScanTask{}).Select("status").
		Where("task_id = ?", taskID).Scan(&taskStatus).Error; err == nil && taskStatus == string(model.TaskStatusCancelled) {
		w.logger.Debug("丢弃已取消任务的完成信号", zap.String("task_id", taskID))
		return nil
	}

	now := model.LocalTime(time.Now())

	return w.db.Transaction(func(tx *gorm.DB) error {
		// 1. 更新 TaskHostStatus（仅从 dispatched/timeout → completed，防止重复消费时多次递增）
		result := tx.Model(&model.TaskHostStatus{}).
			Where("task_id = ? AND host_id = ? AND status IN ?", taskID, msg.AgentID,
				[]string{model.TaskHostStatusDispatched, model.TaskHostStatusTimeout}).
			Updates(map[string]interface{}{
				"status":        model.TaskHostStatusCompleted,
				"completed_at":  &now,
				"error_message": "",
			})
		if result.Error != nil {
			return fmt.Errorf("更新 TaskHostStatus 失败: %w", result.Error)
		}

		// 没有实际更新（已经是 completed 或记录不存在），跳过后续操作
		if result.RowsAffected == 0 {
			return nil
		}

		// 2. 递增 ScanTask.completed_host_count
		if err := tx.Model(&model.ScanTask{}).
			Where("task_id = ?", taskID).
			Update("completed_host_count", gorm.Expr("completed_host_count + 1")).Error; err != nil {
			return fmt.Errorf("递增 completed_host_count 失败: %w", err)
		}

		// 3. 检查是否全部完成
		var task model.ScanTask
		if err := tx.Where("task_id = ?", taskID).First(&task).Error; err != nil {
			return fmt.Errorf("查询 ScanTask 失败: %w", err)
		}

		if task.DispatchedHostCount > 0 && task.CompletedHostCount >= task.DispatchedHostCount {
			completedAt := model.LocalTime(time.Now())
			if err := tx.Model(&model.ScanTask{}).
				Where("task_id = ?", taskID).
				Updates(map[string]interface{}{
					"status":        model.TaskStatusCompleted,
					"completed_at":  &completedAt,
					"failed_reason": "",
				}).Error; err != nil {
				return fmt.Errorf("更新 ScanTask 状态为 completed 失败: %w", err)
			}
		}

		return nil
	})
}

// WriteFixResult 处理基线修复结果（DataType 8003）
// 创建 fix_results，成功时更新对应 scan_results 状态
func (w *MySQLWriter) WriteFixResult(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析修复结果失败: %w", err)
	}

	fixResult := &model.FixResult{
		TaskID:   fields["fix_task_id"],
		HostID:   msg.AgentID,
		RuleID:   fields["rule_id"],
		Status:   model.FixResultStatus(fields["status"]),
		Command:  fields["command"],
		Output:   fields["output"],
		ErrorMsg: fields["error_msg"],
		Message:  fields["message"],
		FixedAt:  model.LocalTime(time.Unix(msg.AgentTime, 0)),
	}

	return w.db.Transaction(func(tx *gorm.DB) error {
		// 1. 创建 FixResult（幂等，复合主键去重）
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "task_id"}, {Name: "host_id"}, {Name: "rule_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"status", "output", "error_msg"}),
		}).Create(fixResult).Error; err != nil {
			return fmt.Errorf("创建 FixResult 失败: %w", err)
		}

		// 2. 修复成功时更新原 ScanResult 状态为 pass
		if fixResult.Status == model.FixResultStatusSuccess {
			tx.Model(&model.ScanResult{}).
				Where("host_id = ? AND rule_id = ? AND task_id IN (?)",
					msg.AgentID, fixResult.RuleID,
					tx.Model(&model.FixTask{}).Select("task_id").Where("task_id = ?", fixResult.TaskID),
				).
				Update("status", model.ResultStatusPass)
		}

		// 3. 更新 FixTask 计数
		if fixResult.Status == model.FixResultStatusSuccess {
			tx.Model(&model.FixTask{}).Where("task_id = ?", fixResult.TaskID).
				Update("success_count", gorm.Expr("success_count + 1"))
		} else if fixResult.Status == model.FixResultStatusFailed {
			tx.Model(&model.FixTask{}).Where("task_id = ?", fixResult.TaskID).
				Update("failed_count", gorm.Expr("failed_count + 1"))
		}

		return nil
	})
}

// WriteFixTaskComplete 处理修复任务完成信号（DataType 8004）
// 更新 fix_task_host_status + fix_tasks
func (w *MySQLWriter) WriteFixTaskComplete(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析修复任务完成信号失败: %w", err)
	}

	fixTaskID := fields["fix_task_id"]
	if fixTaskID == "" {
		return fmt.Errorf("修复任务完成信号缺少 fix_task_id")
	}

	now := model.LocalTime(time.Now())

	return w.db.Transaction(func(tx *gorm.DB) error {
		// 1. 更新 FixTaskHostStatus
		if err := tx.Model(&model.FixTaskHostStatus{}).
			Where("task_id = ? AND host_id = ?", fixTaskID, msg.AgentID).
			Updates(map[string]interface{}{
				"status":       model.FixTaskHostStatusCompleted,
				"completed_at": &now,
			}).Error; err != nil {
			return fmt.Errorf("更新 FixTaskHostStatus 失败: %w", err)
		}

		// 2. 统计已完成的不同主机数
		var completedCount int64
		if err := tx.Model(&model.FixTaskHostStatus{}).
			Where("task_id = ? AND status = ?", fixTaskID, model.FixTaskHostStatusCompleted).
			Distinct("host_id").
			Count(&completedCount).Error; err != nil {
			return fmt.Errorf("统计完成主机数失败: %w", err)
		}

		// 3. 查询 FixTask 判断是否全部完成
		var fixTask model.FixTask
		if err := tx.Where("task_id = ?", fixTaskID).First(&fixTask).Error; err != nil {
			return fmt.Errorf("查询 FixTask 失败: %w", err)
		}

		totalHosts := len(fixTask.HostIDs)
		if totalHosts > 0 && int(completedCount) >= totalHosts {
			completedAt := model.LocalTime(time.Now())
			if err := tx.Model(&model.FixTask{}).
				Where("task_id = ?", fixTaskID).
				Updates(map[string]interface{}{
					"status":       model.FixTaskStatusCompleted,
					"progress":     100,
					"completed_at": &completedAt,
				}).Error; err != nil {
				return fmt.Errorf("更新 FixTask 状态为 completed 失败: %w", err)
			}
		} else if totalHosts > 0 {
			progress := int(completedCount) * 100 / totalHosts
			tx.Model(&model.FixTask{}).
				Where("task_id = ?", fixTaskID).
				Update("progress", progress)
		}

		return nil
	})
}

// WriteFIMTaskComplete 处理 FIM 任务完成信号（DataType 6002）
// 更新 fim_task_host_status + fim_tasks
func (w *MySQLWriter) WriteFIMTaskComplete(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析 FIM 任务完成信号失败: %w", err)
	}

	taskID := fields["task_id"]
	if taskID == "" {
		return fmt.Errorf("FIM 任务完成信号缺少 task_id")
	}

	now := model.LocalTime(time.Now())
	totalEntries, _ := strconv.Atoi(fields["total_entries"])
	addedCount, _ := strconv.Atoi(fields["added_count"])
	removedCount, _ := strconv.Atoi(fields["removed_count"])
	changedCount, _ := strconv.Atoi(fields["changed_count"])
	runTimeSec, _ := strconv.Atoi(fields["run_time_sec"])

	return w.db.Transaction(func(tx *gorm.DB) error {
		// 1. 更新 FIMTaskHostStatus
		if err := tx.Model(&model.FIMTaskHostStatus{}).
			Where("task_id = ? AND host_id = ?", taskID, msg.AgentID).
			Updates(map[string]interface{}{
				"status":        fields["status"],
				"total_entries": totalEntries,
				"added_count":   addedCount,
				"removed_count": removedCount,
				"changed_count": changedCount,
				"run_time_sec":  runTimeSec,
				"error_message": fields["error_message"],
				"completed_at":  &now,
			}).Error; err != nil {
			return fmt.Errorf("更新 FIMTaskHostStatus 失败: %w", err)
		}

		// 2. 递增 FIMTask.completed_host_count
		if err := tx.Model(&model.FIMTask{}).
			Where("task_id = ?", taskID).
			Update("completed_host_count", gorm.Expr("completed_host_count + 1")).Error; err != nil {
			return fmt.Errorf("递增 FIMTask completed_host_count 失败: %w", err)
		}

		// 3. 检查是否全部完成
		var fimTask model.FIMTask
		if err := tx.Where("task_id = ?", taskID).First(&fimTask).Error; err != nil {
			return fmt.Errorf("查询 FIMTask 失败: %w", err)
		}

		if fimTask.CompletedHostCount >= fimTask.DispatchedHostCount && fimTask.DispatchedHostCount > 0 {
			completedAt := model.LocalTime(time.Now())
			if err := tx.Model(&model.FIMTask{}).
				Where("task_id = ?", taskID).
				Updates(map[string]interface{}{
					"status":       "completed",
					"completed_at": &completedAt,
				}).Error; err != nil {
				return fmt.Errorf("更新 FIMTask 状态为 completed 失败: %w", err)
			}
		}

		return nil
	})
}

// WriteAsset 处理资产数据（DataType 5050~5060），委托给 AssetService
func (w *MySQLWriter) WriteAsset(msg *kafka.MQMessage, dataType int32) error {
	return w.assetService.HandleAssetData(msg.AgentID, dataType, msg.Body)
}

// WriteCommandAck 处理命令执行回包（DataType 9999）
func (w *MySQLWriter) WriteCommandAck(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析命令回包失败: %w", err)
	}

	commandID := fields["command_id"]
	if commandID == "" {
		return fmt.Errorf("命令回包缺少 command_id")
	}

	errorCode, _ := strconv.ParseInt(fields["error_code"], 10, 32)

	record := &model.CommandAckRecord{
		CommandID:      commandID,
		CommandType:    fields["command_type"],
		HostID:         msg.AgentID,
		Hostname:       msg.Hostname,
		Status:         fields["status"],
		ErrorCode:      int32(errorCode),
		ErrorMessage:   fields["error_message"],
		Output:         fields["output"],
		AcknowledgedAt: model.LocalTime(time.Unix(msg.AgentTime, 0)),
	}

	return w.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "command_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "error_code", "error_message", "output"}),
	}).Create(record).Error
}

// WriteRemediationResult 处理漏洞修复结果（DataType 9200）
func (w *MySQLWriter) WriteRemediationResult(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析修复结果失败: %w", err)
	}

	executor := biz.NewRemediationExecutor(w.db, w.logger)
	return executor.HandleResult(msg.AgentID, fields)
}

// WriteRemediationProgress 处理 DataType 9201。
// 该 DataType 共用于两类 agent 上报，按 fields["kind"] 分发：
//   - "" / "progress"      : 修复阶段进度 → remediation_task_events（UI 实时显示）
//   - "precheck_result"    : 单条 pre-check 结果 → host_vulnerabilities.precheck_*
func (w *MySQLWriter) WriteRemediationProgress(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析修复进度失败: %w", err)
	}
	switch fields["kind"] {
	case "precheck_result":
		return biz.NewPreCheckResultHandler(w.db, w.logger).HandleResult(msg.AgentID, fields)
	default:
		return biz.NewRemediationExecutor(w.db, w.logger).HandleProgress(msg.AgentID, fields)
	}
}

// WriteScanResult 处理 Scanner 扫描结果（DataType 7001）
func (w *MySQLWriter) WriteScanResult(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析扫描结果失败: %w", err)
	}

	taskID, _ := strconv.ParseUint(fields["task_id"], 10, 64)
	fileSize, _ := strconv.ParseInt(fields["file_size"], 10, 64)

	result := &model.AntivirusScanResult{
		TaskID:     uint(taskID),
		HostID:     msg.AgentID,
		Hostname:   msg.Hostname,
		IP:         msg.IntranetIPv4,
		FilePath:   fields["file_path"],
		ThreatName: fields["threat_name"],
		ThreatType: fields["threat_type"],
		Severity:   fields["severity"],
		FileHash:   fields["file_hash"],
		FileSize:   fileSize,
		Action:     "detected",
		DetectedAt: model.LocalTime(time.Unix(msg.AgentTime, 0)),
	}

	if err := w.db.Create(result).Error; err != nil {
		return fmt.Errorf("写入扫描结果失败: %w", err)
	}

	// 递增任务的 threat_count
	if err := w.db.Model(&model.AntivirusScanTask{}).
		Where("id = ?", taskID).
		UpdateColumn("threat_count", gorm.Expr("threat_count + 1")).Error; err != nil {
		w.logger.Warn("递增 threat_count 失败", zap.Uint64("task_id", taskID), zap.Error(err))
	}

	// 异步发送病毒查杀告警通知 (P1-2 限并发)
	w.runAsyncNotify("virus", func() {
		r := result
		ns := biz.NewNotificationService(w.db, w.logger)
		if err := ns.SendVirusAlertNotification(&biz.VirusAlertData{
			HostID:     r.HostID,
			Hostname:   r.Hostname,
			IP:         r.IP,
			FilePath:   r.FilePath,
			ThreatName: r.ThreatName,
			ThreatType: r.ThreatType,
			Severity:   r.Severity,
			FileHash:   r.FileHash,
			Action:     r.Action,
			DetectedAt: r.DetectedAt.Time(),
		}); err != nil {
			w.logger.Error("发送病毒告警通知失败", zap.Error(err))
		}
	})

	return nil
}

// WriteScanTaskComplete 处理 Scanner 任务完成（DataType 7002）
func (w *MySQLWriter) WriteScanTaskComplete(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析任务完成信号失败: %w", err)
	}

	taskID, _ := strconv.ParseUint(fields["task_id"], 10, 64)
	now := model.LocalTime(time.Now())

	return w.db.Transaction(func(tx *gorm.DB) error {
		// 递增已扫描主机数
		if err := tx.Model(&model.AntivirusScanTask{}).
			Where("id = ?", taskID).
			UpdateColumn("scanned_hosts", gorm.Expr("scanned_hosts + 1")).Error; err != nil {
			return err
		}

		// 检查是否所有主机都已完成
		var task model.AntivirusScanTask
		if err := tx.First(&task, taskID).Error; err != nil {
			return err
		}

		if task.ScannedHosts >= task.TotalHosts && task.Status != "completed" {
			return tx.Model(&task).Updates(map[string]interface{}{
				"status":      "completed",
				"finished_at": &now,
			}).Error
		}

		return nil
	})
}

// WriteQuarantineResult 处理 Scanner 隔离/删除结果（DataType 7004）
func (w *MySQLWriter) WriteQuarantineResult(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析隔离结果失败: %w", err)
	}

	action := fields["action"]
	status := fields["status"]

	if action == "quarantine" && status == "success" {
		// 创建隔离文件记录
		file := &model.QuarantineFile{
			HostID:         msg.AgentID,
			Hostname:       msg.Hostname,
			IP:             msg.IntranetIPv4,
			OriginalPath:   fields["file_path"],
			QuarantinePath: fields["quarantine_path"],
			FilePermission: fields["file_permission"],
			FileOwner:      fields["file_owner"],
			Status:         "quarantined",
			QuarantinedAt:  model.LocalTime(time.Unix(msg.AgentTime, 0)),
		}

		return w.db.Create(file).Error
	}

	return nil
}

// WriteMemoryThreat persists a memory threat detection event (DataType 3004).
//
// Server-side dedup:同 host + exe + threat_type 24h 内已存在 open alert 则跳过。
// agent 端已有 (exe, threat_type) 24h dedup,server 端再加一层防止 agent 重启 / 多 agent
// 实例情况下的重复写入。
//
// memfd_exec 严重度从 critical 降到 high — prod 实测 dbus/runc 类 memfd_exec 极常见,
// critical 级别误导 SOC 关注。真 fileless malware 由 anonymous_exec(3+ rwx region) 标 critical。
func (w *MySQLWriter) WriteMemoryThreat(msg *kafka.MQMessage) error {
	fields, err := ParseRecordFields(msg.Body)
	if err != nil {
		return fmt.Errorf("解析内存威胁事件失败: %w", err)
	}

	severity := "high"
	switch fields["threat_type"] {
	case "anonymous_exec":
		severity = "critical" // 多个 rwx region,fileless shellcode 典型特征
	case "memfd_exec":
		severity = "medium" // prod 大量正常进程触发,降级
	case "deleted_exe":
		severity = "high"
	}

	hostID := msg.AgentID
	exe := fields["exe"]
	threatType := fields["threat_type"]

	// 24h dedup:同 host + exe + threat_type 24h 内任何 status 已有记录则跳过。
	// 注意 status 不限 open — SOC 标 fp / resolved 后,24h 内同 exe 再触发也应 dedup
	// (避免 fp 标记后又重新冒出 open 记录,SOC 处置无效)。
	// 真新威胁:24h 后窗口外新触发能正常写入。
	if hostID != "" && exe != "" && threatType != "" {
		var cnt int64
		cutoff := time.Now().Add(-24 * time.Hour)
		err := w.db.Model(&model.MemoryThreat{}).
			Where("host_id = ? AND exe = ? AND threat_type = ? AND created_at >= ?",
				hostID, exe, threatType, cutoff).
			Limit(1).
			Count(&cnt).Error
		if err != nil {
			w.logger.Warn("memory_threat dedup query failed,放行写入", zap.Error(err))
		} else if cnt > 0 {
			return nil // dedup 命中,丢弃此事件
		}
	}

	record := &model.MemoryThreat{
		HostID:     hostID,
		Hostname:   msg.Hostname,
		ThreatType: threatType,
		Severity:   severity,
		PID:        fields["pid"],
		PPID:       fields["ppid"],
		UID:        fields["uid"],
		Exe:        exe,
		Cmdline:    fields["cmdline"],
		Detail:     fields["detail"],
		StoryID:    fields["story_id"],
	}

	return w.db.Create(record).Error
}
