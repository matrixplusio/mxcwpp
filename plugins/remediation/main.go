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

// precheckTimeout 预检命令的超时时间（短超时，避免网络慢阻塞主流程）
const precheckTimeout = 60 * time.Second

// dataTypeRemediationResult 漏洞修复结果的 DataType
// 注意：不能使用 9001，因为 9001 是心跳 Pong（被 Agent receiveData 拦截），会导致结果丢失
const dataTypeRemediationResult int32 = 9200

// taskPayload 从 Server 下发的修复任务数据。
//
// 商业级修复任务必须经过 3 阶段精确预检：
//  1. detect_os    — 确认 OS 类型，选对 pkg manager
//  2. check_installed — 包必须已装，否则 dnf upgrade 会报 "no installed package"
//  3. check_available — 包仓库实际可用版本（取代 vuln DB 的 fixed_version，
//     因 NVD 字段经常与 OS erratum 不匹配，如 openssl 4.1.0.2 假数据）
type taskPayload struct {
	TaskID       uint   `json:"task_id"`
	CveID        string `json:"cve_id"`
	Component    string `json:"component"`
	FixedVersion string `json:"fixed_version"` // 仅作 verify 期望，不直接拼命令
	Command      string `json:"command"`       // dnf upgrade {comp} -y（不带 version，让 pkg manager 自选 latest）
	DryRun       bool   `json:"dry_run"`
}

// dataTypeRemediationProgress 修复任务阶段进度事件。
// Agent 收到后转发 manager 更新 remediation_task_events，UI 实时显示 11 state 转换。
const dataTypeRemediationProgress int32 = 9201

// stageDetectOS 等是 lifecycle stage 标识，对应 manager 端 11 state 中的 6 个 plugin-side state。
const (
	stageDetectOS       = "detect_os"
	stageCheckInstalled = "check_installed"
	stageCheckAvailable = "check_available"
	stageDownloading    = "downloading"
	stageInstalling     = "installing"
	stageVerifying      = "verifying"
)

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
	defer func() { _ = logger.Sync() }()

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
	// taskCh 缓冲调到 256：吸收 precheck-all 一次性下发的成百漏洞，配合 lib 端
	// deferred 投递让 ReceiveTask 保持调用频率（ping/pong 不被业务阻塞）。
	taskCh := make(chan *bridge.Task, 256)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	// precheckSem 限制并发 precheck（dnf 进程数），避免 CPU/repo 锁压力过大
	const maxConcurrentPrecheck = 4
	precheckSem := make(chan struct{}, maxConcurrentPrecheck)

	for {
		select {
		case <-ctx.Done():
			logger.Info("remediation plugin stopped")
			return
		case task, ok := <-taskCh:
			if !ok {
				return
			}
			// 按 DataType 分发：9100 = 修复执行；9101 = 单独 pre-check（只查不动）
			switch task.DataType {
			case dataTypePreCheckPush:
				// pre-check 走 goroutine + 信号量并发，避免阻塞主 loop
				// 主 loop 不阻塞 = ReceiveTaskLoop 可持续投递 = ping/pong 不停 = agent 不强杀
				precheckSem <- struct{}{}
				go func(t *bridge.Task) {
					defer plugins.RecoverAndLog(logger, "handlePreCheck")()
					defer func() { <-precheckSem }()
					if err := handlePreCheck(ctx, t, client, logger); err != nil {
						logger.Error("handle precheck failed", zap.Error(err))
					}
				}(task)
			default:
				// 漏洞修复 (9100) 仍走串行：单 host 同一时刻只跑一次 dnf install，
				// 避免锁竞争和包管理器并发限制。
				if err := handleTask(ctx, task, client, logger); err != nil {
					logger.Error("handle task failed", zap.Error(err))
				}
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

	// Component 会被拼入仓库查询命令(checkPkgInstalled/checkPkgAvailable 的 sh -c)，
	// 严格白名单防命令注入（与 precheck 一致），杜绝 "pkg; rm -rf /" 之类。
	if payload.Component != "" && !validPkgName.MatchString(payload.Component) {
		logger.Warn("component rejected by safety check",
			zap.Uint("task_id", payload.TaskID),
			zap.String("component", payload.Component))
		return sendResult(client, payload.TaskID, 1, "", fmt.Sprintf("组件名非法（含危险字符）: %s", payload.Component), logger)
	}

	// 审计日志（独立于常规日志，便于安全审计）
	logger.Info("[AUDIT] remediation command accepted",
		zap.Uint("task_id", payload.TaskID),
		zap.String("cve_id", payload.CveID),
		zap.String("component", payload.Component),
		zap.String("command", payload.Command),
		zap.Bool("dry_run", payload.DryRun))

	// 3 阶段精确预检
	// stage 1: detect_os —— 选 pkg manager
	sendProgress(client, payload.TaskID, task.Token, stageDetectOS, "检测包管理器", "", logger)
	pkgMgr, ok := detectPkgManager(payload.Component)
	if !ok {
		return sendResult(client, payload.TaskID, 2, "",
			"无法检测到 yum/dnf/apt 包管理器", logger)
	}
	logger.Info("stage detect_os passed",
		zap.Uint("task_id", payload.TaskID), zap.String("pkg_mgr", pkgMgr))

	// stage 2: check_installed —— 包必须已装
	sendProgress(client, payload.TaskID, task.Token, stageCheckInstalled,
		"检查包是否已安装", payload.Component, logger)
	installedVer, err := checkPkgInstalled(ctx, pkgMgr, payload.Component)
	if err != nil {
		return sendResult(client, payload.TaskID, 2, "",
			fmt.Sprintf("预检失败：包 %s 未安装 (%v)", payload.Component, err), logger)
	}
	logger.Info("stage check_installed passed",
		zap.String("installed_version", installedVer))

	// stage 3: check_available —— 取仓库实际可用版本
	sendProgress(client, payload.TaskID, task.Token, stageCheckAvailable,
		"查询仓库可用版本", payload.Component, logger)
	availVer, err := checkPkgAvailable(ctx, pkgMgr, payload.Component)
	if err != nil {
		return sendResult(client, payload.TaskID, 2, "",
			fmt.Sprintf("预检失败：仓库无可升级版本 (%v)", err), logger)
	}
	logger.Info("stage check_available passed",
		zap.String("installed_version", installedVer),
		zap.String("available_version", availVer))

	// 已是最新（installed == available）→ 视为成功，无需执行
	if installedVer == availVer {
		msg := fmt.Sprintf("包 %s 已是最新版本 %s，无需修复", payload.Component, installedVer)
		logger.Info(msg, zap.Uint("task_id", payload.TaskID))
		return sendResult(client, payload.TaskID, 0, msg, "", logger)
	}

	// DryRun 模式：不实际执行，输出 3 阶段预检结果给 UI 审阅
	if payload.DryRun {
		report := fmt.Sprintf("[DRY RUN] 3 阶段预检通过\nOS pkg_mgr: %s\n包: %s\n已装版本: %s → 可用版本: %s\n待执行: %s",
			pkgMgr, payload.Component, installedVer, availVer, payload.Command)
		logger.Info("dry run mode, skipping execution")
		return sendResult(client, payload.TaskID, 0, report, "", logger)
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

	// stage verifying：执行后核验包升级到预期版本
	sendProgress(client, payload.TaskID, task.Token, stageVerifying,
		"验证升级后版本", payload.Component, logger)
	if exitCode == 0 {
		newVer, vErr := checkPkgInstalled(ctx, pkgMgr, payload.Component)
		if vErr == nil && newVer != installedVer {
			stdout += fmt.Sprintf("\n[verify] %s: %s → %s", payload.Component, installedVer, newVer)
		}
	}

	return sendResult(client, payload.TaskID, exitCode, stdout, stderr, logger)
}

// sendProgress 上报修复任务阶段进度事件（DataType 9201）。
// agent 收到后转发 manager 写 remediation_task_events 表，UI 实时显示 stage 转换。
func sendProgress(client *plugins.Client, taskID uint, token, stage, message, detail string, logger *zap.Logger) {
	record := &bridge.Record{
		DataType:  dataTypeRemediationProgress,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id": fmt.Sprintf("%d", taskID),
				"token":   token,
				"stage":   stage,
				"message": message,
				"detail":  detail,
			},
		},
	}
	if err := client.SendRecord(record); err != nil {
		logger.Warn("send progress failed",
			zap.Uint("task_id", taskID),
			zap.String("stage", stage),
			zap.Error(err))
	}
}

// detectPkgManager 探测可用包管理器。
// 返回首个找到的：dnf > yum > apt-get。
func detectPkgManager(_ string) (string, bool) {
	for _, mgr := range []string{"dnf", "yum", "apt-get"} {
		if _, err := exec.LookPath(mgr); err == nil {
			return mgr, true
		}
	}
	return "", false
}

// checkPkgInstalled 查询包当前已装版本。
// dnf/yum: rpm -q --qf "%{EVR}" <pkg>
// apt-get: dpkg-query -W -f='${Version}' <pkg>
func checkPkgInstalled(ctx context.Context, pkgMgr, pkg string) (string, error) {
	var args []string
	var bin string
	switch pkgMgr {
	case "dnf", "yum":
		bin = "rpm"
		args = []string{"-q", "--qf", "%{EVR}", pkg}
	case "apt-get":
		bin = "dpkg-query"
		args = []string{"-W", "-f=${Version}", pkg}
	default:
		return "", fmt.Errorf("unsupported pkg manager: %s", pkgMgr)
	}
	cctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" || strings.Contains(v, "not installed") {
		return "", fmt.Errorf("package %s not installed", pkg)
	}
	return v, nil
}

// checkPkgAvailable 查询包仓库可升级到的最新版本。
// dnf: dnf repoquery <pkg> --latest-limit=1 --qf "%{EVR}"
// yum: repoquery --pkgnarrow=available <pkg> --qf "%{evr}"
// apt-get: apt-cache madison <pkg> | head -1 | awk '{print $3}'
func checkPkgAvailable(ctx context.Context, pkgMgr, pkg string) (string, error) {
	var cmd string
	switch pkgMgr {
	case "dnf":
		cmd = fmt.Sprintf("dnf repoquery %s --latest-limit=1 --qf '%%{EVR}' 2>/dev/null | tail -1", pkg)
	case "yum":
		cmd = fmt.Sprintf("repoquery --pkgnarrow=available %s --qf '%%{evr}' 2>/dev/null | head -1", pkg)
	case "apt-get":
		cmd = fmt.Sprintf("apt-cache madison %s 2>/dev/null | head -1 | awk '{print $3}'", pkg)
	default:
		return "", fmt.Errorf("unsupported pkg manager: %s", pkgMgr)
	}
	cctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/bin/sh", "-c", cmd).Output()
	if err != nil {
		return "", fmt.Errorf("repoquery %s: %w", pkg, err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("repoquery 返回空，包 %s 仓库无可用版本", pkg)
	}
	return v, nil
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

// 历史 buildPrecheck/extractPackageArg 已被 3 阶段精确预检（detectPkgManager +
// checkPkgInstalled + checkPkgAvailable）取代，提供数据驱动的真实版本反查，
// 不再依赖命令字符串解析。
