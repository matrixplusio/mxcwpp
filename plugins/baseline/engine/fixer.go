// Package engine 提供基线修复执行器
package engine

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// FixResult 是修复结果
type FixResult struct {
	RuleID            string
	PolicyID          string
	Status            FixStatus
	Command           string
	Output            string
	ErrorMsg          string
	Message           string
	FixedAt           time.Time
	RestartedServices []string // 已重启的服务列表
}

// FixStatus 是修复状态
type FixStatus string

const (
	FixStatusSuccess FixStatus = "success" // 成功（命令执行 + 修后复检通过）
	FixStatusFailed  FixStatus = "failed"  // 失败
	FixStatusSkipped FixStatus = "skipped" // 跳过（无修复命令）
	// FixStatusStagedReboot：修复内容已写入配置文件，但因 auditd 处于 immutable 模式
	// (auditctl -s enabled=2) 无法 live 加载，需重启主机后生效。区别于 failed。
	FixStatusStagedReboot FixStatus = "staged_reboot_required"
)

// serviceValidators 服务重启前的配置校验命令。重启前先校验，避免把损坏的配置
// （尤其 sshd）重启进生效态导致服务起不来 / 锁死。校验失败则跳过重启。
var serviceValidators = map[string]string{
	"sshd":    "sshd -t",
	"ssh":     "sshd -t",
	"nginx":   "nginx -t",
	"rsyslog": "rsyslogd -N1",
}

// Fixer 是修复执行器
type Fixer struct {
	logger *zap.Logger
	// verifier 用于修后复检：fix+restart 后重跑规则 check 确认真合规。
	// 为 nil 时跳过复检（向后兼容旧调用方）。
	verifier *Engine
}

// NewFixer 创建新的修复执行器
func NewFixer(logger *zap.Logger) *Fixer {
	return &Fixer{
		logger: logger,
	}
}

// SetVerifier 注入用于修后复检的检查引擎（通常与扫描用同一 Engine）。
func (f *Fixer) SetVerifier(e *Engine) {
	f.verifier = e
}

// verifyRule 修后复检：重跑规则 check，返回是否真合规及实际值。
// verifier 未注入时返回 (true, "")，保持旧行为不阻断。
func (f *Fixer) verifyRule(ctx context.Context, policy *Policy, rule *Rule) (bool, string) {
	if f.verifier == nil {
		return true, ""
	}
	res := f.verifier.executeRule(ctx, policy, rule)
	return res.Status == StatusPass, res.Actual
}

// auditdImmutable 探测 auditd 是否处于 immutable 模式（enabled 2），
// 此模式下规则集锁定到下次重启，新规则只能写文件无法 live 加载。
func (f *Fixer) auditdImmutable(ctx context.Context) bool {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := f.execCommand(cmdCtx, "auditctl -s 2>/dev/null | awk '/^enabled/{print $2}'")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "2"
}

// finalizeStatus 依据修后复检结果裁定最终状态：复检通过=success；
// 未通过则区分 auditd immutable 的 staged_reboot_required 与普通 failed。
func (f *Fixer) finalizeStatus(ctx context.Context, policy *Policy, rule *Rule, result *FixResult) {
	pass, actual := f.verifyRule(ctx, policy, rule)
	if pass {
		result.Status = FixStatusSuccess
		result.Message = "修复成功"
		return
	}
	// 复检未通过：判定是否 auditd immutable 导致的"已写文件待重启"。
	if rule.Fix != nil && slices.Contains(rule.Fix.RestartServices, "auditd") && f.auditdImmutable(ctx) {
		result.Status = FixStatusStagedReboot
		result.Message = "规则已写入配置文件，但 auditd 处于 immutable 模式，需重启主机后生效"
		return
	}
	result.Status = FixStatusFailed
	result.Message = fmt.Sprintf("修复命令已执行但复检未通过，实际值: %s", actual)
	if result.ErrorMsg == "" {
		result.ErrorMsg = "post-fix verification failed"
	}
}

// execCommand 执行外部命令，使用进程组确保超时时能杀掉整棵进程树
// 解决 exec.CommandContext 只杀直接子进程导致 CombinedOutput 永远阻塞的问题
func (f *Fixer) execCommand(ctx context.Context, command string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// 超时时发送 SIGKILL 到整个进程组（负 PID = 进程组）
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second // Cancel 后最多等 5 秒管道关闭
	return cmd.CombinedOutput()
}

// Fix 执行单条规则的修复（包含服务重启）
func (f *Fixer) Fix(ctx context.Context, policy *Policy, rule *Rule) *FixResult {
	return f.fixInternal(ctx, policy, rule, true)
}

// fixInternal 执行修复的内部方法
// restartService: 是否在修复后重启服务，批量修复时设为 false 以便最后统一重启
func (f *Fixer) fixInternal(ctx context.Context, policy *Policy, rule *Rule, restartService bool) *FixResult {
	result := &FixResult{
		RuleID:   rule.RuleID,
		PolicyID: policy.ID,
		FixedAt:  time.Now(),
	}

	// 检查是否有修复命令
	if rule.Fix == nil || rule.Fix.Command == "" {
		result.Status = FixStatusSkipped
		result.Message = "无自动修复方案"
		f.logger.Debug("no fix command available",
			zap.String("rule_id", rule.RuleID))
		return result
	}

	result.Command = rule.Fix.Command

	// 执行修复命令
	f.logger.Info("executing fix command",
		zap.String("rule_id", rule.RuleID),
		zap.String("command", rule.Fix.Command))

	// 创建带超时的上下文（10 分钟，aide --init 等命令可能需要较长时间）
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// 执行命令（使用进程组，确保超时时能杀掉所有子进程）
	output, err := f.execCommand(cmdCtx, rule.Fix.Command)

	result.Output = string(output)

	if err != nil {
		result.Status = FixStatusFailed
		result.ErrorMsg = err.Error()
		result.Message = fmt.Sprintf("修复失败: %v", err)

		f.logger.Error("fix command failed",
			zap.String("rule_id", rule.RuleID),
			zap.String("command", rule.Fix.Command),
			zap.Error(err),
			zap.String("output", string(output)))

		return result
	}

	f.logger.Info("fix command succeeded",
		zap.String("rule_id", rule.RuleID),
		zap.String("output", strings.TrimSpace(string(output))))

	// 重启指定服务（仅当 restartService 为 true 时，即单条修复路径）。
	// 批量路径 restartService=false：此处只写文件，重启与复检由 FixBatch 末尾统一处理。
	if restartService && len(rule.Fix.RestartServices) > 0 {
		restartErrors := f.restartServices(ctx, rule.Fix.RestartServices)
		result.RestartedServices = rule.Fix.RestartServices

		if len(restartErrors) > 0 {
			result.Status = FixStatusFailed
			result.ErrorMsg = strings.Join(restartErrors, "; ")
			result.Message = fmt.Sprintf("修复命令执行成功，但服务重启失败: %s", result.ErrorMsg)
			return result
		}
	}

	if restartService {
		// 单条路径：命令 + 重启均完成，修后复检裁定真实状态。
		f.finalizeStatus(ctx, policy, rule, result)
	} else {
		// 批量路径：暂记命令已执行，最终状态在 FixBatch 重启后复检裁定。
		result.Status = FixStatusSuccess
		result.Message = "修复命令已执行（待批量重启后复检）"
	}

	return result
}

// restartServices 重启指定服务
func (f *Fixer) restartServices(ctx context.Context, services []string) []string {
	var errors []string

	for _, service := range services {
		f.logger.Info("restarting service", zap.String("service", service))

		// 重启前配置校验（P2）：sshd/nginx/rsyslog 等先校验配置合法性，
		// 不合法则跳过重启，避免把损坏配置重启进生效态（sshd 尤其会锁死）。
		if validator, ok := serviceValidators[service]; ok {
			valCtx, valCancel := context.WithTimeout(ctx, 15*time.Second)
			valOut, valErr := f.execCommand(valCtx, validator)
			valCancel()
			if valErr != nil {
				errMsg := fmt.Sprintf("服务 %s 配置校验失败(%s)，已跳过重启以防故障: %s",
					service, validator, strings.TrimSpace(string(valOut)))
				errors = append(errors, errMsg)
				f.logger.Error("service config validation failed, skipping restart",
					zap.String("service", service),
					zap.String("validator", validator),
					zap.Error(valErr),
					zap.String("output", strings.TrimSpace(string(valOut))))
				continue
			}
		}

		// auditd 重启前需要先加载规则文件到内核
		// 批量修复时各规则只写文件不加载，统一在此处加载一次，避免 -e 2（不可变标志）导致后续加载失败
		if service == "auditd" {
			f.logger.Info("loading audit rules before restarting auditd")
			loadCtx, loadCancel := context.WithTimeout(ctx, 30*time.Second)
			loadOutput, loadErr := f.execCommand(loadCtx, "augenrules --load")
			loadCancel()
			if loadErr != nil {
				f.logger.Warn("augenrules --load failed, will try service restart anyway",
					zap.Error(loadErr),
					zap.String("output", strings.TrimSpace(string(loadOutput))))
			} else {
				f.logger.Info("audit rules loaded successfully")
			}
		}

		// 创建带超时的上下文（服务重启最多等待 30 秒）
		cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		// 优先使用 systemctl，降级到 service 命令
		output, err := f.execCommand(cmdCtx,
			fmt.Sprintf("systemctl restart %s 2>/dev/null || service %s restart", service, service))
		cancel()

		if err != nil {
			errMsg := fmt.Sprintf("重启服务 %s 失败: %v, 输出: %s", service, err, strings.TrimSpace(string(output)))
			errors = append(errors, errMsg)
			f.logger.Error("service restart failed",
				zap.String("service", service),
				zap.Error(err),
				zap.String("output", string(output)))
		} else {
			f.logger.Info("service restarted successfully", zap.String("service", service))
		}
	}

	return errors
}

// FixBatch 批量执行修复（合并服务重启，提高效率）
// onResult 回调在每条规则修复完成后立即调用，用于实时上报结果
func (f *Fixer) FixBatch(ctx context.Context, policies []*Policy, ruleIDs []string, osFamily, osVersion string, onResult func(*FixResult)) []*FixResult {
	var results []*FixResult

	// 待修后复检项：记录已执行命令的规则，批量重启后统一复检裁定最终状态。
	type pendingVerify struct {
		policy *Policy
		rule   *Rule
		result *FixResult
	}
	var toVerify []pendingVerify

	// 收集所有需要重启的服务（去重）
	pendingServices := make(map[string]bool)

	// 构建规则ID映射，用于快速查找
	ruleIDMap := make(map[string]bool)
	for _, id := range ruleIDs {
		ruleIDMap[id] = true
	}

	for _, policy := range policies {
		// OS 匹配
		if !policy.MatchOS(osFamily, osVersion) {
			f.logger.Debug("policy OS mismatch",
				zap.String("policy_id", policy.ID),
				zap.String("os_family", osFamily),
				zap.String("os_version", osVersion))
			continue
		}

		// 执行规则修复
		for _, rule := range policy.Rules {
			// 检查是否在待修复列表中
			if len(ruleIDMap) > 0 && !ruleIDMap[rule.RuleID] {
				continue
			}

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				f.logger.Warn("fix batch cancelled",
					zap.String("policy_id", policy.ID),
					zap.String("rule_id", rule.RuleID))
				return results
			default:
			}

			// 执行修复（不重启服务）
			result := f.fixInternal(ctx, policy, rule, false)
			if result != nil {
				results = append(results, result)

				// 实时回调上报结果（命令已执行的暂态；复检后若状态变化会再次上报修正）
				if onResult != nil {
					onResult(result)
				}

				// 收集成功修复项需要重启的服务 + 登记待复检
				if result.Status == FixStatusSuccess && rule.Fix != nil {
					for _, svc := range rule.Fix.RestartServices {
						pendingServices[svc] = true
					}
					toVerify = append(toVerify, pendingVerify{policy: policy, rule: rule, result: result})
				}
			}
		}
	}

	// 批量修复完成后，统一重启所有需要重启的服务
	if len(pendingServices) > 0 {
		var services []string
		for svc := range pendingServices {
			services = append(services, svc)
		}

		f.logger.Info("restarting services after batch fix",
			zap.Strings("services", services))

		restartErrors := f.restartServices(ctx, services)

		// 如果服务重启失败，更新最后一个成功结果的状态
		if len(restartErrors) > 0 {
			errMsg := strings.Join(restartErrors, "; ")
			f.logger.Error("some services failed to restart after batch fix",
				zap.String("errors", errMsg))

			// 添加一个汇总结果记录服务重启情况
			restartResult := &FixResult{
				RuleID:            "_SERVICE_RESTART",
				PolicyID:          "_BATCH",
				Status:            FixStatusFailed,
				ErrorMsg:          errMsg,
				Message:           fmt.Sprintf("部分服务重启失败: %s", errMsg),
				FixedAt:           time.Now(),
				RestartedServices: services,
			}
			results = append(results, restartResult)
			if onResult != nil {
				onResult(restartResult)
			}
		} else {
			// 记录服务重启成功
			restartResult := &FixResult{
				RuleID:            "_SERVICE_RESTART",
				PolicyID:          "_BATCH",
				Status:            FixStatusSuccess,
				Message:           fmt.Sprintf("服务重启成功: %s", strings.Join(services, ", ")),
				FixedAt:           time.Now(),
				RestartedServices: services,
			}
			results = append(results, restartResult)
			if onResult != nil {
				onResult(restartResult)
			}
		}
	}

	// 修后复检（P1）：重启完成后重跑每条已修规则的 check，裁定真实状态。
	// 捕获"命令执行成功但未真正合规"的假成功（如 auditd immutable 下规则只写文件未 live 加载）。
	// 仅当 verifier 注入时执行；状态相对暂态发生变化的，二次回调上报修正（依赖 fix_results
	// 按 (task,host,rule) upsert）。
	if f.verifier != nil {
		for _, pv := range toVerify {
			f.finalizeStatus(ctx, pv.policy, pv.rule, pv.result)
			// 复检后总是二次上报最终态：覆盖此前"待复检"暂态记录
			// （fix_results 按 task/host/rule upsert，幂等）。
			if onResult != nil {
				onResult(pv.result)
			}
		}
	}

	return results
}
