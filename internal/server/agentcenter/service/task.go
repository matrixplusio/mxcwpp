// Package service 提供任务管理服务
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// TaskService 是任务服务
type TaskService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewTaskService 创建任务服务实例
func NewTaskService(db *gorm.DB, logger *zap.Logger) *TaskService {
	return &TaskService{
		db:     db,
		logger: logger,
	}
}

// DispatchPendingTasks 分发待执行任务
// 查询 scan_tasks 表中状态为 pending 的任务，匹配主机并下发
func (s *TaskService) DispatchPendingTasks(transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 查询待执行任务
	var tasks []model.ScanTask
	if err := s.db.Where("status = ?", model.TaskStatusPending).Find(&tasks).Error; err != nil {
		return fmt.Errorf("查询待执行任务失败: %w", err)
	}

	if len(tasks) == 0 {
		return nil // 没有待执行任务
	}

	s.logger.Info("发现待执行任务", zap.Int("count", len(tasks)))

	// 处理每个任务
	for _, task := range tasks {
		if err := s.dispatchTask(&task, transferService); err != nil {
			s.logger.Error("分发任务失败",
				zap.String("task_id", task.TaskID),
				zap.Error(err),
			)
			// 继续处理下一个任务
			continue
		}
	}

	return nil
}

// dispatchTask 分发单个任务
func (s *TaskService) dispatchTask(task *model.ScanTask, transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 根据 target_type 匹配主机
	var hosts []model.Host

	// 构建基础查询（在线主机）
	baseQuery := s.db.Where("status = ?", model.HostStatusOnline)

	// 如果指定了运行时类型，添加筛选条件
	runtimeType := task.TargetConfig.RuntimeType
	if runtimeType != "" {
		if runtimeType == model.RuntimeTypeVM {
			// 虚拟机：runtime_type = 'vm' 或为空（兼容旧数据）
			baseQuery = baseQuery.Where("(runtime_type = ? OR runtime_type = '' OR runtime_type IS NULL)", model.RuntimeTypeVM)
		} else {
			// Docker 或 K8s：精确匹配
			baseQuery = baseQuery.Where("runtime_type = ?", runtimeType)
		}
		s.logger.Debug("按运行时类型筛选主机",
			zap.String("task_id", task.TaskID),
			zap.String("runtime_type", string(runtimeType)),
		)
	}

	switch task.TargetType {
	case model.TargetTypeAll:
		// 查询所有在线主机（已按 runtime_type 筛选）
		if err := baseQuery.Find(&hosts).Error; err != nil {
			return fmt.Errorf("查询主机失败: %w", err)
		}

	case model.TargetTypeHostIDs:
		// 查询指定主机 ID（已按 runtime_type 筛选）
		if len(task.TargetConfig.HostIDs) == 0 {
			return fmt.Errorf("target_config.host_ids 为空")
		}
		if err := baseQuery.Where("host_id IN ?", task.TargetConfig.HostIDs).Find(&hosts).Error; err != nil {
			return fmt.Errorf("查询主机失败: %w", err)
		}

	case model.TargetTypeOSFamily:
		// 查询指定 OS 系列的主机（已按 runtime_type 筛选）
		if len(task.TargetConfig.OSFamily) == 0 {
			return fmt.Errorf("target_config.os_family 为空")
		}
		if err := baseQuery.Where("os_family IN ?", task.TargetConfig.OSFamily).Find(&hosts).Error; err != nil {
			return fmt.Errorf("查询主机失败: %w", err)
		}

	default:
		return fmt.Errorf("未知的 target_type: %s", task.TargetType)
	}

	if len(hosts) == 0 {
		s.logger.Warn("没有匹配的在线主机，任务保持 pending 状态等待主机上线",
			zap.String("task_id", task.TaskID),
			zap.String("target_type", string(task.TargetType)),
		)
		// 保持 pending 状态，等待主机上线后重新调度
		// 不改变任务状态，让调度器下次继续尝试
		return nil
	}

	s.logger.Info("匹配到主机",
		zap.String("task_id", task.TaskID),
		zap.Int("host_count", len(hosts)),
	)

	// 获取所有策略ID（支持多策略）
	policyIDs := task.GetPolicyIDs()
	if len(policyIDs) == 0 {
		s.logger.Warn("任务没有关联策略，标记为失败",
			zap.String("task_id", task.TaskID),
		)
		s.db.Model(task).Update("status", model.TaskStatusFailed)
		return fmt.Errorf("任务没有关联策略")
	}

	// 查询第一个策略用于OS过滤（多策略场景下，所有策略应该兼容相同的OS）
	policyService := NewPolicyService(s.db, s.logger)
	firstPolicy, err := policyService.GetPolicy(policyIDs[0])
	if err != nil {
		return fmt.Errorf("查询策略失败: %w", err)
	}

	// 过滤不匹配策略 OS 要求的主机
	var matchedHosts []model.Host
	var skippedHosts []string
	for _, host := range hosts {
		if s.matchPolicyOS(firstPolicy, &host) {
			matchedHosts = append(matchedHosts, host)
		} else {
			skippedHosts = append(skippedHosts, host.HostID)
		}
	}

	// 记录被跳过的主机
	if len(skippedHosts) > 0 {
		s.logger.Info("部分主机不匹配策略 OS 要求，已跳过",
			zap.String("task_id", task.TaskID),
			zap.String("policy_os_family", fmt.Sprintf("%v", firstPolicy.OSFamily)),
			zap.String("policy_os_version", firstPolicy.OSVersion),
			zap.Int("skipped_count", len(skippedHosts)),
			zap.Strings("skipped_hosts", skippedHosts),
		)
	}

	// 检查是否还有匹配的主机
	if len(matchedHosts) == 0 {
		s.logger.Warn("没有匹配策略 OS 要求的在线主机，任务保持 pending 状态等待主机上线",
			zap.String("task_id", task.TaskID),
			zap.Strings("policy_ids", policyIDs),
			zap.String("policy_os_family", fmt.Sprintf("%v", firstPolicy.OSFamily)),
			zap.String("policy_os_version", firstPolicy.OSVersion),
		)
		// 保持 pending 状态，等待主机上线后重新调度
		return nil
	}

	s.logger.Info("OS 匹配后的主机数量",
		zap.String("task_id", task.TaskID),
		zap.Int("matched_count", len(matchedHosts)),
		zap.Int("original_count", len(hosts)),
	)

	// CAS：仅当任务仍为 pending 时才转为 running（防止与取消操作竞争）
	casResult := s.db.Model(&model.ScanTask{}).
		Where("task_id = ? AND status = ?", task.TaskID, model.TaskStatusPending).
		Update("status", model.TaskStatusRunning)
	if casResult.Error != nil {
		return fmt.Errorf("更新任务状态失败: %w", casResult.Error)
	}
	if casResult.RowsAffected == 0 {
		s.logger.Info("任务状态已变更（可能已被取消），跳过下发",
			zap.String("task_id", task.TaskID))
		return nil
	}

	// 查询所有策略和规则
	var allPolicies []*model.Policy
	var allRules []model.Rule
	var disabledRules []string

	for _, policyID := range policyIDs {
		policy, err := policyService.GetPolicy(policyID)
		if err != nil {
			s.logger.Error("查询策略失败",
				zap.String("task_id", task.TaskID),
				zap.String("policy_id", policyID),
				zap.Error(err),
			)
			continue
		}
		allPolicies = append(allPolicies, policy)

		// 收集启用的规则
		for _, rule := range policy.Rules {
			if rule.Enabled {
				allRules = append(allRules, rule)
			} else {
				disabledRules = append(disabledRules, rule.RuleID)
			}
		}
	}

	if len(allPolicies) == 0 {
		s.logger.Warn("没有有效的策略，标记为失败",
			zap.String("task_id", task.TaskID),
		)
		s.db.Model(task).Update("status", model.TaskStatusFailed)
		return fmt.Errorf("没有有效的策略")
	}

	// 记录被跳过的禁用规则
	if len(disabledRules) > 0 {
		s.logger.Info("部分规则已禁用，已跳过",
			zap.String("task_id", task.TaskID),
			zap.Int("disabled_count", len(disabledRules)),
		)
	}

	if len(allRules) == 0 {
		s.logger.Warn("没有启用的规则可执行，标记为失败",
			zap.String("task_id", task.TaskID),
			zap.Int("policy_count", len(allPolicies)),
			zap.Int("disabled_count", len(disabledRules)),
		)
		s.db.Model(task).Update("status", model.TaskStatusFailed)
		return fmt.Errorf("没有启用的规则可执行")
	}

	s.logger.Info("准备下发任务",
		zap.String("task_id", task.TaskID),
		zap.Int("policy_count", len(allPolicies)),
		zap.Int("rule_count", len(allRules)),
	)

	// 为每个匹配的主机下发任务（带重试，每批 20 台后暂停 100ms 避免瞬时流量尖峰）
	const dispatchBatchSize = 20
	const dispatchBatchDelay = 100 * time.Millisecond
	successCount := 0
	now := model.Now()
	for i, host := range matchedHosts {
		// 批间限速：每 dispatchBatchSize 台主机暂停一次
		if i > 0 && i%dispatchBatchSize == 0 {
			time.Sleep(dispatchBatchDelay)
		}
		// 使用重试机制下发任务
		err := Retry(context.Background(), func() error {
			return s.sendTaskToHostMultiPolicy(&host, task, allPolicies, transferService)
		}, DefaultRetryConfig, s.logger)

		if err != nil {
			s.logger.Error("下发任务到主机失败（已重试）",
				zap.String("task_id", task.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			// 记录失败状态
			hostStatus := &model.TaskHostStatus{
				TaskID:       task.TaskID,
				HostID:       host.HostID,
				Hostname:     host.Hostname,
				IPAddress:    getHostIPAddress(&host),
				BusinessLine: host.BusinessLine,
				OSFamily:     host.OSFamily,
				OSVersion:    host.OSVersion,
				RuntimeType:  string(host.RuntimeType),
				Status:       model.TaskHostStatusFailed,
				DispatchedAt: &now,
				ErrorMessage: err.Error(),
			}
			if dbErr := s.db.Create(hostStatus).Error; dbErr != nil {
				s.logger.Error("记录主机状态失败",
					zap.String("task_id", task.TaskID),
					zap.String("host_id", host.HostID),
					zap.Error(dbErr),
				)
			}
			continue
		}

		// 记录成功下发状态
		hostStatus := &model.TaskHostStatus{
			TaskID:       task.TaskID,
			HostID:       host.HostID,
			Hostname:     host.Hostname,
			IPAddress:    getHostIPAddress(&host),
			BusinessLine: host.BusinessLine,
			OSFamily:     host.OSFamily,
			OSVersion:    host.OSVersion,
			RuntimeType:  string(host.RuntimeType),
			Status:       model.TaskHostStatusDispatched,
			DispatchedAt: &now,
		}
		if dbErr := s.db.Create(hostStatus).Error; dbErr != nil {
			s.logger.Error("记录主机状态失败",
				zap.String("task_id", task.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(dbErr),
			)
		}

		successCount++
	}

	// 更新已下发主机数
	s.db.Model(task).Update("dispatched_host_count", successCount)

	// 如果没有成功下发到任何主机，回滚为 pending 让调度器下一轮重试
	// （可能是 Agent 正在更新重启，稍后会重新上线）
	// 超时由 task_timeout_scheduler 统一处理
	if successCount == 0 {
		s.logger.Warn("任务本轮下发失败，回滚为 pending 等待下一轮重试",
			zap.String("task_id", task.TaskID),
			zap.Int("matched_hosts", len(matchedHosts)),
		)
		// 回滚状态为 pending（仅当仍为 running 时，防止覆盖取消操作）
		s.db.Model(&model.ScanTask{}).
			Where("task_id = ? AND status = ?", task.TaskID, model.TaskStatusRunning).
			Update("status", model.TaskStatusPending)
		// 清理本轮产生的失败记录，避免下一轮重复创建
		s.db.Where("task_id = ? AND status = ?", task.TaskID, model.TaskHostStatusFailed).
			Delete(&model.TaskHostStatus{})
		return fmt.Errorf("没有成功下发到任何主机，等待重试")
	}

	s.logger.Info("任务分发完成",
		zap.String("task_id", task.TaskID),
		zap.Int("matched_hosts", len(matchedHosts)),
		zap.Int("skipped_hosts", len(skippedHosts)),
		zap.Int("success_count", successCount),
	)

	return nil
}

// sendTaskToHostMultiPolicy 向指定主机发送多策略任务
func (s *TaskService) sendTaskToHostMultiPolicy(
	host *model.Host,
	task *model.ScanTask,
	policies []*model.Policy,
	transferService interface {
		SendCommand(agentID string, cmd *grpcProto.Command) error
	},
) error {
	// 构建多策略数据
	policiesData := s.buildMultiPoliciesData(policies, host, true) // 检查任务裁剪 fix.command

	// 构建任务数据（JSON）
	taskData := map[string]interface{}{
		"task_id":    task.TaskID,
		"host_id":    host.HostID,
		"policy_ids": task.GetPolicyIDs(),
		"policies":   policiesData,
		"os_family":  host.OSFamily,
		"os_version": host.OSVersion,
	}

	taskDataJSON, err := json.Marshal(taskData)
	if err != nil {
		return fmt.Errorf("序列化任务数据失败: %w", err)
	}

	// 构建 Task
	grpcTask := &grpcProto.Task{
		DataType:   8000,       // 基线检查任务
		ObjectName: "baseline", // 插件名称
		Data:       string(taskDataJSON),
		Token:      task.TaskID, // 使用 task_id 作为 token
	}

	// 构建 Command
	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{grpcTask},
	}

	// 发送命令
	if err := transferService.SendCommand(host.HostID, cmd); err != nil {
		return fmt.Errorf("发送命令失败: %w", err)
	}

	s.logger.Debug("多策略任务已下发",
		zap.String("task_id", task.TaskID),
		zap.String("host_id", host.HostID),
		zap.Int("policy_count", len(policies)),
	)

	return nil
}

// buildMultiPoliciesData 构建多策略数据
// 返回 json.RawMessage 避免双重 JSON 编码（之前返回 string，嵌入 map 后 Marshal 会再次转义）
// stripFixCommand: 检查任务不需要 fix.command / fix.restart_services，裁剪以减少传输量
func (s *TaskService) buildMultiPoliciesData(policies []*model.Policy, host *model.Host, stripFixCommand bool) json.RawMessage {
	policiesArray := make([]map[string]interface{}, 0, len(policies))

	for _, policy := range policies {
		// 检查策略是否匹配主机OS
		if !s.matchPolicyOS(policy, host) {
			continue
		}

		// 检查策略是否匹配主机运行时类型
		if !policy.MatchesRuntimeType(host.RuntimeType) {
			s.logger.Debug("策略不适用于主机运行时类型",
				zap.String("policy_id", policy.ID),
				zap.String("host_id", host.HostID),
				zap.String("host_runtime_type", string(host.RuntimeType)),
				zap.Strings("policy_runtime_types", policy.RuntimeTypes))
			continue
		}

		// 收集启用的规则（并按运行时类型过滤）
		rulesList := make([]map[string]interface{}, 0)
		var skippedRules []string
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}
			// 检查规则是否匹配主机运行时类型
			if !rule.MatchesRuntimeType(host.RuntimeType) {
				skippedRules = append(skippedRules, rule.RuleID)
				continue
			}
			ruleData := map[string]interface{}{
				"rule_id":     rule.RuleID,
				"category":    rule.Category,
				"title":       rule.Title,
				"description": rule.Description,
				"severity":    rule.Severity,
				"check":       rule.CheckConfig,
			}
			if stripFixCommand {
				// 检查任务只需修复建议，不需要 command 和 restart_services
				ruleData["fix"] = map[string]string{"suggestion": rule.FixConfig.Suggestion}
			} else {
				ruleData["fix"] = rule.FixConfig
			}
			rulesList = append(rulesList, ruleData)
		}

		// 记录被运行时类型过滤的规则
		if len(skippedRules) > 0 {
			s.logger.Debug("部分规则不适用于主机运行时类型，已跳过",
				zap.String("policy_id", policy.ID),
				zap.String("host_id", host.HostID),
				zap.String("host_runtime_type", string(host.RuntimeType)),
				zap.Int("skipped_count", len(skippedRules)))
		}

		if len(rulesList) == 0 {
			continue
		}

		policyData := map[string]interface{}{
			"id":          policy.ID,
			"name":        policy.Name,
			"version":     policy.Version,
			"description": policy.Description,
			"os_family":   policy.OSFamily,
			"os_version":  policy.OSVersion,
			"enabled":     policy.Enabled,
			"rules":       rulesList,
		}
		policiesArray = append(policiesArray, policyData)
	}

	policiesJSON, err := json.Marshal(policiesArray)
	if err != nil {
		s.logger.Error("序列化策略数据失败", zap.Error(err))
		return json.RawMessage("[]")
	}

	return json.RawMessage(policiesJSON)
}

// matchPolicyOS 检查主机是否匹配策略的 OS 要求
func (s *TaskService) matchPolicyOS(policy *model.Policy, host *model.Host) bool {
	// 如果策略没有指定 OS Family，则匹配所有主机
	if len(policy.OSFamily) == 0 {
		return true
	}

	// 检查主机的 OS Family 是否在策略的 OS Family 列表中
	familyMatched := false
	for _, family := range policy.OSFamily {
		if strings.EqualFold(family, host.OSFamily) {
			familyMatched = true
			break
		}
	}

	if !familyMatched {
		return false
	}

	// 如果策略指定了 OS Version 约束，检查版本是否匹配
	if policy.OSVersion != "" {
		return matchVersionConstraint(host.OSVersion, policy.OSVersion)
	}

	return true
}

// matchVersionConstraint 检查版本是否满足约束条件
// 支持格式：>=7.0, >7.0, <=9.0, <9.0, 7.0（精确匹配）
func matchVersionConstraint(actual, constraint string) bool {
	if constraint == "" {
		return true
	}

	constraint = strings.TrimSpace(constraint)
	actual = strings.TrimSpace(actual)

	// 支持 >= 前缀
	if strings.HasPrefix(constraint, ">=") {
		version := strings.TrimSpace(constraint[2:])
		return compareVersionNumbers(actual, version) >= 0
	}

	// 支持 > 前缀
	if strings.HasPrefix(constraint, ">") {
		version := strings.TrimSpace(constraint[1:])
		return compareVersionNumbers(actual, version) > 0
	}

	// 支持 <= 前缀
	if strings.HasPrefix(constraint, "<=") {
		version := strings.TrimSpace(constraint[2:])
		return compareVersionNumbers(actual, version) <= 0
	}

	// 支持 < 前缀
	if strings.HasPrefix(constraint, "<") {
		version := strings.TrimSpace(constraint[1:])
		return compareVersionNumbers(actual, version) < 0
	}

	// 精确匹配
	return actual == constraint
}

// compareVersionNumbers 比较两个版本号
// 返回值：-1 表示 v1 < v2, 0 表示 v1 == v2, 1 表示 v1 > v2
func compareVersionNumbers(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var v1Num, v2Num int
		if i < len(v1Parts) {
			v1Num, _ = strconv.Atoi(strings.TrimSpace(v1Parts[i]))
		}
		if i < len(v2Parts) {
			v2Num, _ = strconv.Atoi(strings.TrimSpace(v2Parts[i]))
		}

		if v1Num < v2Num {
			return -1
		}
		if v1Num > v2Num {
			return 1
		}
	}

	return 0
}

// DispatchFixTask 下发修复任务到 Agent
func (s *TaskService) DispatchFixTask(fixTask *model.FixTask, transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 1. 查询目标主机（只查询在线主机）
	var hosts []model.Host
	// 将 StringArray 转换为 []string 以便 GORM 查询
	hostIDs := []string(fixTask.HostIDs)
	if err := s.db.Where("host_id IN ? AND status = ?", hostIDs, model.HostStatusOnline).Find(&hosts).Error; err != nil {
		return fmt.Errorf("查询主机失败: %w", err)
	}

	if len(hosts) == 0 {
		s.logger.Warn("没有在线主机，修复任务失败",
			zap.String("task_id", fixTask.TaskID),
			zap.Int("requested_hosts", len(fixTask.HostIDs)),
		)
		s.db.Model(fixTask).Updates(map[string]interface{}{
			"status":       model.FixTaskStatusFailed,
			"completed_at": model.Now(),
		})
		return fmt.Errorf("没有在线主机")
	}

	// 2. 查询规则信息
	var rules []model.Rule
	// 将 StringArray 转换为 []string 以便 GORM 查询
	ruleIDs := []string(fixTask.RuleIDs)
	if err := s.db.Where("rule_id IN ?", ruleIDs).Find(&rules).Error; err != nil {
		return fmt.Errorf("查询规则失败: %w", err)
	}

	if len(rules) == 0 {
		s.logger.Warn("没有找到规则，修复任务失败",
			zap.String("task_id", fixTask.TaskID),
		)
		s.db.Model(fixTask).Updates(map[string]interface{}{
			"status":       model.FixTaskStatusFailed,
			"completed_at": model.Now(),
		})
		return fmt.Errorf("没有找到规则")
	}

	// 3. 按策略组织规则
	policyRulesMap := make(map[string][]*model.Rule)
	for i := range rules {
		rule := &rules[i]
		policyRulesMap[rule.PolicyID] = append(policyRulesMap[rule.PolicyID], rule)
	}

	// 4. 查询所有相关策略
	policyIDs := make([]string, 0, len(policyRulesMap))
	for policyID := range policyRulesMap {
		policyIDs = append(policyIDs, policyID)
	}

	policyService := NewPolicyService(s.db, s.logger)
	var policies []*model.Policy
	for _, policyID := range policyIDs {
		policy, err := policyService.GetPolicy(policyID)
		if err != nil {
			s.logger.Error("查询策略失败",
				zap.String("task_id", fixTask.TaskID),
				zap.String("policy_id", policyID),
				zap.Error(err),
			)
			continue
		}
		// 只保留需要修复且启用的规则
		var filteredRules []model.Rule
		for _, rule := range policyRulesMap[policyID] {
			if rule.Enabled {
				filteredRules = append(filteredRules, *rule)
			}
		}
		policy.Rules = filteredRules
		policies = append(policies, policy)
	}

	if len(policies) == 0 {
		s.logger.Warn("没有有效的策略，修复任务失败",
			zap.String("task_id", fixTask.TaskID),
		)
		s.db.Model(fixTask).Updates(map[string]interface{}{
			"status":       model.FixTaskStatusFailed,
			"completed_at": model.Now(),
		})
		return fmt.Errorf("没有有效的策略")
	}

	// 5. 更新任务状态为 running
	if err := s.db.Model(fixTask).Update("status", model.FixTaskStatusRunning).Error; err != nil {
		return fmt.Errorf("更新任务状态失败: %w", err)
	}

	s.logger.Info("准备下发修复任务",
		zap.String("task_id", fixTask.TaskID),
		zap.Int("host_count", len(hosts)),
		zap.Int("rule_count", len(rules)),
		zap.Int("policy_count", len(policies)),
	)

	// 6. 为每个主机下发修复任务
	successCount := 0
	for _, host := range hosts {
		// 过滤匹配主机 OS 的策略
		var matchedPolicies []*model.Policy
		for _, policy := range policies {
			if s.matchPolicyOS(policy, &host) {
				matchedPolicies = append(matchedPolicies, policy)
			}
		}

		if len(matchedPolicies) == 0 {
			s.logger.Debug("主机不匹配任何策略 OS 要求，跳过",
				zap.String("task_id", fixTask.TaskID),
				zap.String("host_id", host.HostID),
			)
			continue
		}

		// 构建策略数据（修复任务保留完整 fix 配置）
		policiesData := s.buildMultiPoliciesData(matchedPolicies, &host, false)

		// 构建任务数据（JSON）
		taskData := map[string]interface{}{
			"task_id":     fmt.Sprintf("%s-%s", fixTask.TaskID, host.HostID), // 子任务ID
			"fix_task_id": fixTask.TaskID,                                    // 修复任务ID
			"policies":    policiesData,
			"rule_ids":    fixTask.RuleIDs,
			"os_family":   host.OSFamily,
			"os_version":  host.OSVersion,
		}

		taskDataJSON, err := json.Marshal(taskData)
		if err != nil {
			s.logger.Error("序列化任务数据失败",
				zap.String("task_id", fixTask.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			continue
		}

		// 构建 Task
		grpcTask := &grpcProto.Task{
			DataType:   8002,       // 基线修复任务
			ObjectName: "baseline", // 插件名称
			Data:       string(taskDataJSON),
			Token:      fmt.Sprintf("%s-%s", fixTask.TaskID, host.HostID), // 与 taskData["task_id"] 保持一致
		}

		// 构建 Command
		cmd := &grpcProto.Command{
			Tasks: []*grpcProto.Task{grpcTask},
		}

		// 发送命令
		if err := transferService.SendCommand(host.HostID, cmd); err != nil {
			s.logger.Error("下发修复任务到主机失败",
				zap.String("task_id", fixTask.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			continue
		}

		// 创建主机状态记录
		now := model.Now()
		hostStatus := &model.FixTaskHostStatus{
			TaskID:       fixTask.TaskID,
			HostID:       host.HostID,
			Hostname:     host.Hostname,
			IPAddress:    getHostIPAddress(&host),
			BusinessLine: host.BusinessLine,
			OSFamily:     host.OSFamily,
			OSVersion:    host.OSVersion,
			RuntimeType:  string(host.RuntimeType),
			Status:       model.FixTaskHostStatusDispatched,
			DispatchedAt: &now,
		}

		if err := s.db.Create(hostStatus).Error; err != nil {
			s.logger.Error("创建主机状态记录失败",
				zap.String("task_id", fixTask.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			// 不影响任务下发，继续
		}

		successCount++
		s.logger.Debug("修复任务已下发",
			zap.String("task_id", fixTask.TaskID),
			zap.String("host_id", host.HostID),
		)
	}

	// 7. 检查是否成功下发到任何主机
	if successCount == 0 {
		s.logger.Warn("修复任务下发失败，没有成功下发到任何主机",
			zap.String("task_id", fixTask.TaskID),
			zap.Int("matched_hosts", len(hosts)),
		)
		s.db.Model(fixTask).Updates(map[string]interface{}{
			"status":       model.FixTaskStatusFailed,
			"completed_at": model.Now(),
		})
		return fmt.Errorf("没有成功下发到任何主机")
	}

	s.logger.Info("修复任务分发完成",
		zap.String("task_id", fixTask.TaskID),
		zap.Int("total_hosts", len(hosts)),
		zap.Int("success_count", successCount),
	)

	return nil
}

// DispatchPendingFixTasks 分发待执行的修复任务
// 查询 fix_tasks 表中状态为 pending 的任务并下发
func (s *TaskService) DispatchPendingFixTasks(transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 查询待执行的修复任务
	var tasks []model.FixTask
	if err := s.db.Where("status = ?", model.FixTaskStatusPending).Find(&tasks).Error; err != nil {
		return fmt.Errorf("查询待执行修复任务失败: %w", err)
	}

	if len(tasks) == 0 {
		return nil // 没有待执行任务
	}

	s.logger.Info("发现待执行修复任务", zap.Int("count", len(tasks)))

	// 处理每个任务
	for _, task := range tasks {
		if err := s.DispatchFixTask(&task, transferService); err != nil {
			s.logger.Error("分发修复任务失败",
				zap.String("task_id", task.TaskID),
				zap.Error(err),
			)
			// 继续处理下一个任务
			continue
		}
	}

	return nil
}

// getHostIPAddress 获取主机的 IP 地址（优先返回第一个 IPv4 地址）
func getHostIPAddress(host *model.Host) string {
	if len(host.IPv4) > 0 {
		return host.IPv4[0]
	}
	return ""
}

// DispatchPendingFIMTasks 分发待执行的 FIM 任务
func (s *TaskService) DispatchPendingFIMTasks(transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	var tasks []model.FIMTask
	if err := s.db.Where("status = ?", "pending").Find(&tasks).Error; err != nil {
		return fmt.Errorf("查询待执行 FIM 任务失败: %w", err)
	}

	if len(tasks) == 0 {
		return nil
	}

	s.logger.Debug("发现待执行 FIM 任务", zap.Int("count", len(tasks)))

	for _, task := range tasks {
		if err := s.dispatchFIMTask(&task, transferService); err != nil {
			s.logger.Error("分发 FIM 任务失败",
				zap.String("task_id", task.TaskID),
				zap.Error(err),
			)
			continue
		}
	}

	return nil
}

// dispatchFIMTask 分发单个 FIM 任务
func (s *TaskService) dispatchFIMTask(task *model.FIMTask, transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 查询关联的 FIM 策略
	var policy model.FIMPolicy
	if err := s.db.Where("policy_id = ?", task.PolicyID).First(&policy).Error; err != nil {
		s.db.Model(task).Update("status", "failed")
		return fmt.Errorf("查询 FIM 策略失败: %w", err)
	}

	if !policy.Enabled {
		s.logger.Warn("FIM 策略已禁用，跳过",
			zap.String("task_id", task.TaskID),
			zap.String("policy_id", task.PolicyID),
		)
		return nil
	}

	// 根据 target_type 匹配在线主机
	hosts, err := s.matchFIMTargetHosts(task)
	if err != nil {
		return err
	}

	if len(hosts) == 0 {
		// 无在线主机匹配 → 保持 pending；超时由 task_timeout_scheduler 统一处理（24h）
		s.logger.Debug("没有匹配的在线主机，FIM 任务保持 pending",
			zap.String("task_id", task.TaskID),
		)
		return nil
	}

	// 构建策略数据
	policyData := map[string]interface{}{
		"task_id":       task.TaskID,
		"policy_id":     policy.PolicyID,
		"watch_paths":   policy.WatchPaths,
		"exclude_paths": policy.ExcludePaths,
	}
	policyJSON, err := json.Marshal(policyData)
	if err != nil {
		return fmt.Errorf("序列化策略数据失败: %w", err)
	}

	// 更新任务状态为 running
	now := model.Now()
	s.db.Model(task).Updates(map[string]interface{}{
		"status":      "running",
		"executed_at": &now,
	})

	// 为每个主机下发任务并记录状态
	successCount := s.sendFIMToHosts(task, hosts, policyJSON, transferService)

	// 更新已下发主机数
	s.db.Model(task).Update("dispatched_host_count", successCount)

	if successCount == 0 {
		s.db.Model(task).Update("status", "pending")
		return fmt.Errorf("FIM 任务没有成功下发到任何主机")
	}

	s.logger.Info("FIM 任务分发完成",
		zap.String("task_id", task.TaskID),
		zap.Int("host_count", len(hosts)),
		zap.Int("success_count", successCount),
	)
	return nil
}

// matchFIMTargetHosts 根据 target_type 匹配在线主机
func (s *TaskService) matchFIMTargetHosts(task *model.FIMTask) ([]model.Host, error) {
	var hosts []model.Host
	// FIM 仅适用于 VM（物理机/虚拟机），容器环境不支持 AIDE
	baseQuery := s.db.Where("status = ? AND runtime_type = ?", model.HostStatusOnline, model.RuntimeTypeVM)

	switch task.TargetType {
	case "all":
		if err := baseQuery.Find(&hosts).Error; err != nil {
			return nil, fmt.Errorf("查询主机失败: %w", err)
		}
	case "host_ids":
		if len(task.TargetConfig.HostIDs) == 0 {
			return nil, fmt.Errorf("target_config.host_ids 为空")
		}
		if err := baseQuery.Where("host_id IN ?", task.TargetConfig.HostIDs).Find(&hosts).Error; err != nil {
			return nil, fmt.Errorf("查询主机失败: %w", err)
		}
	case "os_family":
		if len(task.TargetConfig.OSFamily) == 0 {
			return nil, fmt.Errorf("target_config.os_family 为空")
		}
		if err := baseQuery.Where("os_family IN ?", task.TargetConfig.OSFamily).Find(&hosts).Error; err != nil {
			return nil, fmt.Errorf("查询主机失败: %w", err)
		}
	default:
		return nil, fmt.Errorf("未知的 target_type: %s", task.TargetType)
	}

	return hosts, nil
}

// sendFIMToHosts 向主机列表下发 FIM 任务
func (s *TaskService) sendFIMToHosts(task *model.FIMTask, hosts []model.Host, policyJSON []byte, transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) int {
	now := model.Now()
	successCount := 0

	for _, host := range hosts {
		grpcTask := &grpcProto.Task{
			DataType:   6000,
			ObjectName: "fim",
			Data:       string(policyJSON),
			Token:      task.TaskID,
		}
		cmd := &grpcProto.Command{
			Tasks: []*grpcProto.Task{grpcTask},
		}

		if err := transferService.SendCommand(host.HostID, cmd); err != nil {
			s.logger.Error("下发 FIM 任务到主机失败",
				zap.String("task_id", task.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			continue
		}

		hostStatus := &model.FIMTaskHostStatus{
			TaskID:       task.TaskID,
			HostID:       host.HostID,
			Hostname:     host.Hostname,
			Status:       "dispatched",
			DispatchedAt: &now,
		}
		if dbErr := s.db.Create(hostStatus).Error; dbErr != nil {
			s.logger.Error("记录 FIM 主机状态失败",
				zap.String("task_id", task.TaskID),
				zap.String("host_id", host.HostID),
				zap.Error(dbErr),
			)
		}
		successCount++
	}

	return successCount
}

// DispatchPendingAntivirusTasks 分发待执行的病毒扫描任务
func (s *TaskService) DispatchPendingAntivirusTasks(transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	var tasks []model.AntivirusScanTask
	if err := s.db.Where("status = ?", "pending").Find(&tasks).Error; err != nil {
		return fmt.Errorf("查询待执行病毒扫描任务失败: %w", err)
	}

	if len(tasks) == 0 {
		return nil
	}

	s.logger.Info("发现待执行病毒扫描任务", zap.Int("count", len(tasks)))

	for i := range tasks {
		if err := s.dispatchAntivirusTask(&tasks[i], transferService); err != nil {
			s.logger.Error("分发病毒扫描任务失败",
				zap.Uint("task_id", tasks[i].ID),
				zap.Error(err),
			)
			continue
		}
	}

	return nil
}

// dispatchAntivirusTask 分发单个病毒扫描任务
func (s *TaskService) dispatchAntivirusTask(task *model.AntivirusScanTask, transferService interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}) error {
	// 查询目标主机（仅在线主机）
	var hosts []model.Host
	if len(task.HostIDs) > 0 {
		if err := s.db.Where("host_id IN ? AND status = ?", []string(task.HostIDs), model.HostStatusOnline).
			Find(&hosts).Error; err != nil {
			return fmt.Errorf("查询目标主机失败: %w", err)
		}
	} else {
		// 未指定主机时，扫描所有在线 VM 主机
		if err := s.db.Where("status = ? AND (runtime_type = ? OR runtime_type = '' OR runtime_type IS NULL)",
			model.HostStatusOnline, model.RuntimeTypeVM).
			Find(&hosts).Error; err != nil {
			return fmt.Errorf("查询在线主机失败: %w", err)
		}
	}

	if len(hosts) == 0 {
		s.logger.Warn("没有匹配的在线主机，任务保持 pending",
			zap.Uint("task_id", task.ID))
		return nil
	}

	// 构建扫描任务数据
	taskData := map[string]interface{}{
		"task_id":   fmt.Sprintf("%d", task.ID),
		"scan_type": task.ScanType,
		"paths":     []string(task.ScanPaths),
	}
	taskJSON, _ := json.Marshal(taskData)

	now := model.LocalTime(time.Now())
	successCount := 0

	for _, host := range hosts {
		grpcTask := &grpcProto.Task{
			DataType:   7000, // Scanner 扫描任务
			ObjectName: "scanner",
			Data:       string(taskJSON),
			Token:      fmt.Sprintf("%d", task.ID),
		}
		cmd := &grpcProto.Command{
			Tasks: []*grpcProto.Task{grpcTask},
		}

		if err := transferService.SendCommand(host.HostID, cmd); err != nil {
			s.logger.Error("下发病毒扫描任务失败",
				zap.Uint("task_id", task.ID),
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			continue
		}
		successCount++
	}

	if successCount > 0 {
		s.db.Model(task).Updates(map[string]interface{}{
			"status":      "running",
			"started_at":  &now,
			"total_hosts": successCount,
		})
	}

	s.logger.Info("病毒扫描任务已下发",
		zap.Uint("task_id", task.ID),
		zap.Int("dispatched", successCount),
		zap.Int("total_hosts", len(hosts)),
	)

	return nil
}
