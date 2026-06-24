package biz

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PolicyExecutor 修复策略执行器
type PolicyExecutor struct {
	db       *gorm.DB
	logger   *zap.Logger
	executor *RemediationExecutor
}

// NewPolicyExecutor 创建策略执行器
func NewPolicyExecutor(db *gorm.DB, logger *zap.Logger, executor *RemediationExecutor) *PolicyExecutor {
	return &PolicyExecutor{
		db:       db,
		logger:   logger,
		executor: executor,
	}
}

// Execute 执行修复策略
func (p *PolicyExecutor) Execute(policyID uint, createdBy string) error {
	var policy model.RemediationPolicy
	if err := p.db.First(&policy, policyID).Error; err != nil {
		return fmt.Errorf("策略不存在: %w", err)
	}

	if !policy.Enabled {
		return fmt.Errorf("策略已禁用")
	}

	p.logger.Info("开始执行修复策略",
		zap.Uint("policy_id", policyID),
		zap.String("name", policy.Name),
		zap.String("rollout_type", policy.RolloutType))

	// 创建执行记录
	now := model.Now()
	exec := model.RemediationPolicyExecution{
		PolicyID:  policyID,
		Status:    "running",
		CreatedBy: createdBy,
		StartedAt: now,
	}
	p.db.Create(&exec)

	// 执行完成时统一更新记录
	finishExec := func(status string, errMsg string, hostCount, vulnCount, taskCount int) {
		finishedAt := model.Now()
		duration := int(time.Since(time.Time(now)).Seconds())
		p.db.Model(&exec).Updates(map[string]any{
			"status":      status,
			"error_msg":   errMsg,
			"host_count":  hostCount,
			"vuln_count":  vulnCount,
			"task_count":  taskCount,
			"duration":    duration,
			"finished_at": finishedAt,
		})
	}

	// 1. 匹配目标主机
	hostIDs, err := p.matchHosts(&policy)
	if err != nil {
		finishExec("failed", "匹配目标主机失败: "+err.Error(), 0, 0, 0)
		return fmt.Errorf("匹配目标主机失败: %w", err)
	}
	if len(hostIDs) == 0 {
		p.logger.Info("没有匹配的目标主机")
		finishExec("success", "没有匹配的目标主机", 0, 0, 0)
		return nil
	}

	// 2. 匹配漏洞
	vulns, err := p.matchVulns(&policy, hostIDs)
	if err != nil {
		finishExec("failed", "匹配漏洞失败: "+err.Error(), len(hostIDs), 0, 0)
		return fmt.Errorf("匹配漏洞失败: %w", err)
	}
	if len(vulns) == 0 {
		p.logger.Info("没有匹配的漏洞")
		finishExec("success", "没有匹配的漏洞", len(hostIDs), 0, 0)
		return nil
	}

	p.logger.Info("策略匹配结果",
		zap.Int("hosts", len(hostIDs)),
		zap.Int("vulns", len(vulns)))

	// 3. 创建修复任务
	tasks, err := p.createTasks(&policy, vulns, hostIDs, createdBy)
	if err != nil {
		finishExec("failed", "创建修复任务失败: "+err.Error(), len(hostIDs), len(vulns), 0)
		return fmt.Errorf("创建修复任务失败: %w", err)
	}

	// 4. 按策略类型执行
	switch policy.RolloutType {
	case "immediate":
		err = p.executeImmediate(tasks, &policy)
	case "canary":
		err = p.executeCanary(tasks, &policy)
	case "rolling":
		err = p.executeRolling(tasks, &policy)
	default:
		err = p.executeImmediate(tasks, &policy)
	}

	if err != nil {
		finishExec("failed", err.Error(), len(hostIDs), len(vulns), len(tasks))
	} else {
		finishExec("success", "", len(hostIDs), len(vulns), len(tasks))
	}

	// 更新策略最后执行时间
	p.db.Model(&policy).Update("last_run_at", model.Now())

	return err
}

// Preview 预览策略影响范围（不实际执行）
func (p *PolicyExecutor) Preview(policyID uint) (*PolicyPreview, error) {
	var policy model.RemediationPolicy
	if err := p.db.First(&policy, policyID).Error; err != nil {
		return nil, fmt.Errorf("策略不存在: %w", err)
	}

	hostIDs, err := p.matchHosts(&policy)
	if err != nil {
		return nil, err
	}

	vulns, err := p.matchVulns(&policy, hostIDs)
	if err != nil {
		return nil, err
	}

	// 统计每个漏洞影响的主机数
	totalTasks := 0
	for _, vuln := range vulns {
		var count int64
		p.db.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND host_id IN ? AND status = ?", vuln.ID, hostIDs, "unpatched").
			Count(&count)
		totalTasks += int(count)
	}

	return &PolicyPreview{
		HostCount: len(hostIDs),
		VulnCount: len(vulns),
		TaskCount: totalTasks,
	}, nil
}

// PolicyPreview 策略预览结果
type PolicyPreview struct {
	HostCount int `json:"hostCount"`
	VulnCount int `json:"vulnCount"`
	TaskCount int `json:"taskCount"`
}

// matchHosts 根据策略条件匹配目标主机
func (p *PolicyExecutor) matchHosts(policy *model.RemediationPolicy) ([]string, error) {
	var hostIDs []string

	switch policy.TargetType {
	case "all":
		p.db.Table("hosts").Where("status = ?", "online").Pluck("host_id", &hostIDs)
	case "business_line":
		var blID string
		if err := json.Unmarshal([]byte(policy.TargetValue), &blID); err != nil {
			return nil, fmt.Errorf("解析业务线 ID 失败: %w", err)
		}
		p.db.Table("hosts").Where("status = ? AND business_line_id = ?", "online", blID).Pluck("host_id", &hostIDs)
	case "tag":
		var tags []string
		if err := json.Unmarshal([]byte(policy.TargetValue), &tags); err != nil {
			return nil, fmt.Errorf("解析标签失败: %w", err)
		}
		// 使用 JSON 包含查询
		query := p.db.Table("hosts").Where("status = ?", "online")
		for _, tag := range tags {
			query = query.Where("tags LIKE ?", "%"+tag+"%")
		}
		query.Pluck("host_id", &hostIDs)
	case "host_ids":
		if err := json.Unmarshal([]byte(policy.TargetValue), &hostIDs); err != nil {
			return nil, fmt.Errorf("解析主机 ID 列表失败: %w", err)
		}
	default:
		return nil, fmt.Errorf("未知目标类型: %s", policy.TargetType)
	}

	return hostIDs, nil
}

// matchVulns 根据条件筛选漏洞
func (p *PolicyExecutor) matchVulns(policy *model.RemediationPolicy, hostIDs []string) ([]model.Vulnerability, error) {
	query := p.db.Model(&model.Vulnerability{}).Where("status = ?", "unpatched")

	// 严重级别筛选
	if policy.SeverityMin != "" {
		severities := severitiesAbove(policy.SeverityMin)
		if len(severities) > 0 {
			query = query.Where("severity IN ?", severities)
		}
	}

	// 优先级筛选
	if policy.PriorityMin > 0 {
		query = query.Where("priority_score >= ?", policy.PriorityMin)
	}

	// 只返回在目标主机上有未修复实例的漏洞
	query = query.Where("id IN (?)",
		p.db.Table("host_vulnerabilities").
			Select("DISTINCT vuln_id").
			Where("host_id IN ? AND status = ?", hostIDs, "unpatched"))

	var vulns []model.Vulnerability
	if err := query.Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

// createTasks 为匹配的漏洞×主机创建修复任务
func (p *PolicyExecutor) createTasks(policy *model.RemediationPolicy, vulns []model.Vulnerability, hostIDs []string, createdBy string) ([]model.RemediationTask, error) {
	remService := NewRemediationService(p.db, p.logger)
	var tasks []model.RemediationTask

	for _, vuln := range vulns {
		// 获取该漏洞在目标主机上的未修复实例
		var hostVulns []model.HostVulnerability
		p.db.Where("vuln_id = ? AND host_id IN ? AND status = ?", vuln.ID, hostIDs, "unpatched").
			Find(&hostVulns)

		// 生成修复命令
		commands := remService.generateCommands(&vuln)
		if len(commands) == 0 {
			continue
		}
		command := commands[0].Command

		for _, hv := range hostVulns {
			// 检查是否已有进行中的任务
			var existing int64
			p.db.Model(&model.RemediationTask{}).
				Where("vuln_id = ? AND host_id = ? AND status IN ?", vuln.ID, hv.HostID, []string{"pending", "confirmed", "running"}).
				Count(&existing)
			if existing > 0 {
				continue
			}

			task := model.RemediationTask{
				VulnID:       vuln.ID,
				CveID:        vuln.CveID,
				HostID:       hv.HostID,
				Hostname:     hv.Hostname,
				IP:           hv.IP,
				Component:    vuln.Component,
				FixedVersion: vuln.FixedVersion,
				Command:      command,
				CreatedBy:    createdBy,
			}

			// 自动审批
			if policy.AutoConfirm {
				task.Status = "confirmed"
				now := model.Now()
				task.ConfirmedAt = &now
				task.ConfirmedBy = "policy:" + policy.Name
			}

			if err := p.db.Create(&task).Error; err != nil {
				p.logger.Warn("创建修复任务失败", zap.Error(err))
				continue
			}
			tasks = append(tasks, task)
		}
	}

	p.logger.Info("修复任务创建完成", zap.Int("count", len(tasks)))
	return tasks, nil
}

// executeImmediate 立即执行所有任务
func (p *PolicyExecutor) executeImmediate(tasks []model.RemediationTask, _ *model.RemediationPolicy) error {
	p.logger.Info("立即执行修复策略", zap.Int("tasks", len(tasks)))
	// 任务已创建，等待 executor 轮询调度
	return nil
}

// executeCanary 金丝雀执行
func (p *PolicyExecutor) executeCanary(tasks []model.RemediationTask, policy *model.RemediationPolicy) error {
	canaryCount := len(tasks) * policy.CanaryRatio / 100
	if canaryCount == 0 {
		canaryCount = 1
	}

	p.logger.Info("金丝雀执行", zap.Int("canary_count", canaryCount), zap.Int("total", len(tasks)))

	// 随机选择金丝雀任务
	perm := rand.Perm(len(tasks))
	for i := 0; i < len(tasks); i++ {
		task := tasks[perm[i]]
		if i >= canaryCount {
			// 非金丝雀任务设为 pending，等待确认
			p.db.Model(&task).Update("status", "pending")
		}
	}

	return nil
}

// executeRolling 滚动执行
func (p *PolicyExecutor) executeRolling(tasks []model.RemediationTask, policy *model.RemediationPolicy) error {
	maxParallel := policy.MaxParallel
	if maxParallel <= 0 {
		maxParallel = 10
	}

	p.logger.Info("滚动执行", zap.Int("max_parallel", maxParallel), zap.Int("total", len(tasks)))

	// 第一批设为 confirmed，其余 pending
	for i, task := range tasks {
		if i >= maxParallel {
			p.db.Model(&task).Update("status", "pending")
		}
	}

	// 启动后台监控，自动推进后续批次
	go p.monitorRollingBatches(tasks, maxParallel)

	return nil
}

// monitorRollingBatches 监控滚动执行批次，自动推进
func (p *PolicyExecutor) monitorRollingBatches(tasks []model.RemediationTask, maxParallel int) {
	if len(tasks) <= maxParallel {
		return
	}

	taskIDs := make([]uint, len(tasks))
	for i, t := range tasks {
		taskIDs[i] = t.ID
	}

	batchStart := 0
	for batchStart < len(tasks) {
		batchEnd := batchStart + maxParallel
		if batchEnd > len(tasks) {
			batchEnd = len(tasks)
		}
		batchIDs := taskIDs[batchStart:batchEnd]

		// 轮询等待当前批次完成
		for {
			time.Sleep(10 * time.Second)

			var running int64
			p.db.Model(&model.RemediationTask{}).
				Where("id IN ? AND status IN ?", batchIDs, []string{"confirmed", "running"}).
				Count(&running)
			if running == 0 {
				break
			}
		}

		// 检查成功率
		var succeeded, total int64
		p.db.Model(&model.RemediationTask{}).Where("id IN ?", batchIDs).Count(&total)
		p.db.Model(&model.RemediationTask{}).Where("id IN ? AND status = ?", batchIDs, "success").Count(&succeeded)

		if total > 0 && float64(succeeded)/float64(total) < 0.8 {
			p.logger.Warn("滚动执行批次成功率低于 80%，暂停后续批次",
				zap.Int("batch_start", batchStart),
				zap.Int64("succeeded", succeeded),
				zap.Int64("total", total))
			return
		}

		// 推进下一批
		batchStart = batchEnd
		if batchStart >= len(tasks) {
			break
		}
		nextEnd := batchStart + maxParallel
		if nextEnd > len(tasks) {
			nextEnd = len(tasks)
		}
		nextBatchIDs := taskIDs[batchStart:nextEnd]
		p.db.Model(&model.RemediationTask{}).
			Where("id IN ? AND status = ?", nextBatchIDs, "pending").
			Update("status", "confirmed")

		p.logger.Info("滚动执行推进下一批",
			zap.Int("batch_start", batchStart),
			zap.Int("batch_size", nextEnd-batchStart))
	}
}

// severitiesAbove 返回指定级别及以上的所有严重级别
func severitiesAbove(minSeverity string) []string {
	levels := []string{"low", "medium", "high", "critical"}
	var result []string
	found := false
	for _, l := range levels {
		if l == minSeverity {
			found = true
		}
		if found {
			result = append(result, l)
		}
	}
	return result
}
