// Package main 是 Remediation Plugin 的主程序入口
// Remediation Plugin 作为 Agent 的子进程运行，接收修复命令并执行
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	plugins "github.com/imkerbos/mxsec-platform/plugins/lib/go"
)

var (
	buildVersion = "dev"
	buildTime    = ""
)

// commandTimeout 单条修复命令的最大执行时间
const commandTimeout = 10 * time.Minute

// dataTypeRemediationResult 漏洞修复结果的 DataType
// 注意：不能使用 9001，因为 9001 是心跳 Pong（被 Agent receiveData 拦截），会导致结果丢失
const dataTypeRemediationResult int32 = 9200

// taskPayload 从 Server 下发的修复任务数据
type taskPayload struct {
	TaskID       uint   `json:"task_id"`
	CveID        string `json:"cve_id"`
	Component    string `json:"component"`
	FixedVersion string `json:"fixed_version"`
	Command      string `json:"command"`
	DryRun       bool   `json:"dry_run"`
}

func main() {
	client, err := plugins.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create plugin client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	logger, err := plugins.NewPluginLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("remediation plugin started",
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// 任务接收循环
	taskCh := make(chan *bridge.Task, 10)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	for {
		select {
		case <-ctx.Done():
			logger.Info("remediation plugin stopped")
			return
		case task, ok := <-taskCh:
			if !ok {
				return
			}
			if err := handleTask(ctx, task, client, logger); err != nil {
				logger.Error("handle task failed", zap.Error(err))
			}
		}
	}
}

func handleTask(ctx context.Context, task *bridge.Task, client *plugins.Client, logger *zap.Logger) error {
	logger.Info("received remediation task",
		zap.Int32("data_type", task.DataType),
		zap.String("token", task.Token))

	// 解析任务数据
	var payload taskPayload
	if err := json.Unmarshal([]byte(task.Data), &payload); err != nil {
		return fmt.Errorf("解析任务数据失败: %w", err)
	}

	logger.Info("executing remediation command",
		zap.Uint("task_id", payload.TaskID),
		zap.String("cve_id", payload.CveID),
		zap.String("component", payload.Component),
		zap.String("command", payload.Command),
		zap.Bool("dry_run", payload.DryRun))

	// 命令安全校验
	if payload.Command == "" {
		return sendResult(client, payload.TaskID, 1, "", "修复命令为空", logger)
	}

	if err := validateCommand(payload.Command); err != nil {
		logger.Warn("command rejected by safety check",
			zap.Uint("task_id", payload.TaskID),
			zap.String("command", payload.Command),
			zap.Error(err))
		return sendResult(client, payload.TaskID, 1, "", fmt.Sprintf("命令安全校验失败: %v", err), logger)
	}

	// 审计日志（独立于常规日志，便于安全审计）
	logger.Info("[AUDIT] remediation command accepted",
		zap.Uint("task_id", payload.TaskID),
		zap.String("cve_id", payload.CveID),
		zap.String("component", payload.Component),
		zap.String("command", payload.Command),
		zap.Bool("dry_run", payload.DryRun))

	// DryRun 模式：不实际执行
	if payload.DryRun {
		logger.Info("dry run mode, skipping execution")
		return sendResult(client, payload.TaskID, 0, "[DRY RUN] 命令未实际执行: "+payload.Command, "", logger)
	}

	// 执行修复命令
	execCtx, execCancel := context.WithTimeout(ctx, commandTimeout)
	defer execCancel()

	cmd := exec.CommandContext(execCtx, "/bin/sh", "-c", payload.Command)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	output, err := cmd.CombinedOutput()
	exitCode := 0
	stdout := string(output)
	stderr := ""

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			exitCode = 124 // timeout
			stderr = "命令执行超时（超过 10 分钟）"
		} else {
			exitCode = 1
			stderr = err.Error()
		}
	}

	logger.Info("remediation command completed",
		zap.Uint("task_id", payload.TaskID),
		zap.Int("exit_code", exitCode),
		zap.Int("output_len", len(stdout)))

	return sendResult(client, payload.TaskID, exitCode, stdout, stderr, logger)
}

func sendResult(client *plugins.Client, taskID uint, exitCode int, stdout, stderr string, logger *zap.Logger) error {
	record := &bridge.Record{
		DataType:  dataTypeRemediationResult, // 漏洞修复结果
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id":   fmt.Sprintf("%d", taskID),
				"exit_code": fmt.Sprintf("%d", exitCode),
				"stdout":    stdout,
				"stderr":    stderr,
			},
		},
	}

	if err := client.SendRecord(record); err != nil {
		logger.Error("send result failed",
			zap.Uint("task_id", taskID),
			zap.Error(err))
		return fmt.Errorf("发送修复结果失败: %w", err)
	}

	logger.Info("result sent",
		zap.Uint("task_id", taskID),
		zap.Int("exit_code", exitCode))
	return nil
}

// dangerousPatterns 危险命令模式黑名单
// 这些命令可能导致系统不可恢复，即使 Server 下发也必须拒绝
var dangerousPatterns = []string{
	"rm -rf /",
	"rm -rf /*",
	"mkfs.",
	"dd if=",
	":(){:|:&};:", // fork bomb
	"> /dev/sda",
	"chmod -R 777 /",
	"wget|sh",
	"curl|sh",
	"wget|bash",
	"curl|bash",
	"/dev/tcp/",
	"bash -i",
	"nc -e",
	"ncat -e",
	"python -c",
	"python3 -c",
	"perl -e",
	"ruby -e",
	"base64 -d",
	"eval ",
	"exec ",
	"`",  // 反引号命令替换
	"$(", // $() 命令替换
}

// allowedPrefixes 命令白名单前缀
// 仅允许包管理器和必要的服务管理操作，不允许通用文件操作命令
var allowedPrefixes = []string{
	"yum update ",
	"yum install ",
	"yum upgrade ",
	"yum downgrade ",
	"dnf update ",
	"dnf install ",
	"dnf upgrade ",
	"dnf downgrade ",
	"apt-get install ",
	"apt-get update",
	"apt-get upgrade",
	"apt-get dist-upgrade",
	"dpkg -i ",
	"rpm -U ",
	"rpm -i ",
	"pip install ",
	"pip3 install ",
	"systemctl restart ",
	"systemctl reload ",
}

// validateCommand 校验修复命令是否安全
func validateCommand(command string) error {
	cmd := strings.TrimSpace(command)
	cmdLower := strings.ToLower(cmd)

	// 1. 长度限制
	if len(cmd) > 4096 {
		return fmt.Errorf("命令长度超过 4096 字符限制")
	}

	// 2. 拒绝命令替换和子 shell（防止引号内绕过）
	if strings.Contains(cmd, "$(") || strings.Contains(cmd, "`") {
		return fmt.Errorf("命令包含命令替换（$() 或反引号），不允许")
	}

	// 3. 拒绝重定向写入（防止通过白名单命令写任意文件）
	if strings.ContainsAny(cmd, "><") {
		return fmt.Errorf("命令包含重定向操作符，不允许")
	}

	// 4. 危险命令黑名单
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, strings.ToLower(pattern)) {
			return fmt.Errorf("命令匹配危险模式: %s", pattern)
		}
	}

	// 5. 拒绝组合命令（不允许管道、分号、&&、|| 连接多条命令）
	// 漏洞修复场景只需要单条包管理器命令，不需要组合命令
	if containsShellOperator(cmd) {
		return fmt.Errorf("不允许组合命令（管道、分号、&& 等），请使用单条命令")
	}

	// 6. 白名单前缀检查
	if !matchesAllowedPrefix(cmd) {
		return fmt.Errorf("命令不在白名单中: %s", truncate(cmd, 80))
	}

	return nil
}

// containsShellOperator 检查命令是否包含 shell 组合操作符
// 感知引号内的操作符（忽略引号内的内容）
func containsShellOperator(cmd string) bool {
	inSingle := false
	inDouble := false
	runes := []rune(cmd)

	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		// 处理转义
		if ch == '\\' && i+1 < len(runes) {
			i++ // 跳过下一个字符
			continue
		}

		// 切换引号状态
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}

		// 仅在引号外检测操作符
		if inSingle || inDouble {
			continue
		}

		switch ch {
		case ';':
			return true
		case '|':
			return true
		case '&':
			return true
		}
	}
	return false
}

// matchesAllowedPrefix 检查命令是否匹配白名单前缀
func matchesAllowedPrefix(cmd string) bool {
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cmdLower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// truncate 截断字符串
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
