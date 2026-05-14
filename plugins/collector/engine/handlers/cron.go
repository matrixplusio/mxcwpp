// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// CronHandler 是定时任务采集器
type CronHandler struct {
	Logger *zap.Logger
}

// Collect 采集定时任务信息
func (h *CronHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var cronJobs []interface{}

	// 采集用户 crontab
	userCronJobs, err := h.collectUserCrontabs(ctx)
	if err != nil {
		h.Logger.Warn("failed to collect user crontabs", zap.Error(err))
	} else {
		cronJobs = append(cronJobs, userCronJobs...)
	}

	// 采集系统 crontab
	systemCronJobs, err := h.collectSystemCrontab(ctx)
	if err != nil {
		h.Logger.Warn("failed to collect system crontab", zap.Error(err))
	} else {
		cronJobs = append(cronJobs, systemCronJobs...)
	}

	// 采集 systemd timers
	systemdTimers, err := h.collectSystemdTimers(ctx)
	if err != nil {
		h.Logger.Warn("failed to collect systemd timers", zap.Error(err))
	} else {
		cronJobs = append(cronJobs, systemdTimers...)
	}

	return cronJobs, nil
}

// collectUserCrontabs 采集用户 crontab
func (h *CronHandler) collectUserCrontabs(ctx context.Context) ([]interface{}, error) {
	var cronJobs []interface{}

	// 读取 /etc/passwd 获取所有用户
	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	lines := strings.Split(string(passwdData), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return cronJobs, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		homeDir := parts[5]

		// 尝试读取用户的 crontab
		userCronJobs, err := h.readUserCrontab(ctx, username, homeDir)
		if err != nil {
			continue
		}

		cronJobs = append(cronJobs, userCronJobs...)
	}

	return cronJobs, nil
}

// readUserCrontab 读取用户 crontab
func (h *CronHandler) readUserCrontab(ctx context.Context, username, homeDir string) ([]interface{}, error) {
	var cronJobs []interface{}

	// 方法1：使用 crontab -l 命令
	cmd := exec.CommandContext(ctx, "crontab", "-l", "-u", username)
	output, err := cmd.Output()
	if err != nil {
		// 如果命令失败，尝试读取文件
		return h.readCrontabFile(username, homeDir)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析 crontab 行：schedule command
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		schedule := strings.Join(parts[0:5], " ")
		command := strings.Join(parts[5:], " ")

		cronJob := &engine.CronAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			User:     username,
			Schedule: schedule,
			Command:  command,
			CronType: "crontab",
			Enabled:  true,
		}

		cronJobs = append(cronJobs, cronJob)
	}

	return cronJobs, nil
}

// readCrontabFile 读取 crontab 文件
func (h *CronHandler) readCrontabFile(username, homeDir string) ([]interface{}, error) {
	var cronJobs []interface{}

	// 尝试读取常见的 crontab 文件位置
	crontabPaths := []string{
		filepath.Join("/var/spool/cron", username),
		filepath.Join("/var/spool/cron/crontabs", username),
		filepath.Join(homeDir, ".crontab"),
	}

	for _, path := range crontabPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) < 6 {
				continue
			}

			schedule := strings.Join(parts[0:5], " ")
			command := strings.Join(parts[5:], " ")

			cronJob := &engine.CronAsset{
				Asset: engine.Asset{
					CollectedAt: time.Now(),
				},
				User:     username,
				Schedule: schedule,
				Command:  command,
				CronType: "crontab",
				Enabled:  true,
			}

			cronJobs = append(cronJobs, cronJob)
		}

		break
	}

	return cronJobs, nil
}

// collectSystemCrontab 采集系统 crontab
func (h *CronHandler) collectSystemCrontab(ctx context.Context) ([]interface{}, error) {
	var cronJobs []interface{}

	// 读取 /etc/crontab
	crontabPath := "/etc/crontab"
	data, err := os.ReadFile(crontabPath)
	if err != nil {
		return cronJobs, nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return cronJobs, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 7 {
			continue
		}

		schedule := strings.Join(parts[0:5], " ")
		user := parts[5]
		command := strings.Join(parts[6:], " ")

		cronJob := &engine.CronAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			User:     user,
			Schedule: schedule,
			Command:  command,
			CronType: "crontab",
			Enabled:  true,
		}

		cronJobs = append(cronJobs, cronJob)
	}

	// 读取 /etc/cron.d 目录
	cronDDir := "/etc/cron.d"
	entries, err := os.ReadDir(cronDDir)
	if err == nil {
		for _, entry := range entries {
			select {
			case <-ctx.Done():
				return cronJobs, ctx.Err()
			default:
			}

			if entry.IsDir() {
				continue
			}

			filePath := filepath.Join(cronDDir, entry.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			fileLines := strings.Split(string(data), "\n")
			for _, line := range fileLines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				parts := strings.Fields(line)
				if len(parts) < 6 {
					continue
				}

				schedule := strings.Join(parts[0:5], " ")
				user := parts[5]
				command := strings.Join(parts[6:], " ")

				cronJob := &engine.CronAsset{
					Asset: engine.Asset{
						CollectedAt: time.Now(),
					},
					User:     user,
					Schedule: schedule,
					Command:  command,
					CronType: "crontab",
					Enabled:  true,
				}

				cronJobs = append(cronJobs, cronJob)
			}
		}
	}

	return cronJobs, nil
}

// collectSystemdTimers 采集 systemd timers
func (h *CronHandler) collectSystemdTimers(ctx context.Context) ([]interface{}, error) {
	var cronJobs []interface{}

	// 检查是否有 systemctl 命令
	if _, err := exec.LookPath("systemctl"); err != nil {
		return cronJobs, nil
	}

	// 执行 systemctl list-timers --all --no-pager
	cmd := exec.CommandContext(ctx, "systemctl", "list-timers", "--all", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute systemctl list-timers: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return cronJobs, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析 systemctl list-timers 输出
		// 格式：timer unit next left last passed
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		timerName := fields[0]

		// 获取 timer 的详细信息（包括 OnCalendar）
		schedule := h.getSystemdTimerSchedule(ctx, timerName)
		enabled := h.isSystemdTimerEnabled(ctx, timerName)

		// 获取 timer 对应的 service
		serviceName := h.getSystemdTimerService(ctx, timerName)
		command := fmt.Sprintf("systemd timer: %s -> %s", timerName, serviceName)

		cronJob := &engine.CronAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			User:     "system",
			Schedule: schedule,
			Command:  command,
			CronType: "systemd-timer",
			Enabled:  enabled,
		}

		cronJobs = append(cronJobs, cronJob)
	}

	return cronJobs, nil
}

// getSystemdTimerSchedule 获取 systemd timer 的调度表达式
func (h *CronHandler) getSystemdTimerSchedule(ctx context.Context, timerName string) string {
	cmd := exec.CommandContext(ctx, "systemctl", "show", timerName, "--property=OnCalendar")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	line := strings.TrimSpace(string(output))
	if strings.HasPrefix(line, "OnCalendar=") {
		return strings.TrimPrefix(line, "OnCalendar=")
	}

	return ""
}

// isSystemdTimerEnabled 检查 systemd timer 是否启用
func (h *CronHandler) isSystemdTimerEnabled(ctx context.Context, timerName string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-enabled", timerName)
	err := cmd.Run()
	return err == nil
}

// getSystemdTimerService 获取 systemd timer 对应的 service
func (h *CronHandler) getSystemdTimerService(ctx context.Context, timerName string) string {
	// systemd timer 名称通常是 service 名称加上 .timer 后缀
	if strings.HasSuffix(timerName, ".timer") {
		return strings.TrimSuffix(timerName, ".timer")
	}
	return timerName
}
