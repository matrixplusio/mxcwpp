package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// LogsOptions --logs 子命令选项
type LogsOptions struct {
	LogFile string // 默认 DefaultLogFile
	Lines   int    // tail 末尾行数，默认 100
	Follow  bool   // 实时跟踪
}

// RunLogs 执行 --logs 子命令
//
// 默认行为：tail -n <Lines> <LogFile>
// Follow=true 时阻塞，转发 tail -f 输出，收到 SIGINT/SIGTERM 时优雅退出。
func RunLogs(opts LogsOptions, stdout, stderr io.Writer) error {
	logFile := opts.LogFile
	if logFile == "" {
		logFile = DefaultLogFile
	}
	lines := opts.Lines
	if lines <= 0 {
		lines = 100
	}

	if _, err := os.Stat(logFile); err != nil {
		return fmt.Errorf("日志文件不存在或无权访问 %s: %w", logFile, err)
	}

	args := []string{"-n", fmt.Sprintf("%d", lines)}
	if opts.Follow {
		args = append(args, "-F") // -F 跟随轮转
	}
	args = append(args, logFile)

	cmd := exec.Command("tail", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if !opts.Follow {
		return cmd.Run()
	}

	// Follow 模式：转发信号让 tail 优雅退出
	if err := cmd.Start(); err != nil {
		return err
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}()
	err := cmd.Wait()
	signal.Stop(sigCh)
	// tail 被 SIGTERM 中断不算错误
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				return nil
			}
		}
	}
	return err
}
