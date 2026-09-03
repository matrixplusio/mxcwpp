// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/plugins/collector/engine"
)

// ServiceHandler 是系统服务采集器
type ServiceHandler struct {
	Logger *zap.Logger
}

// Collect 采集系统服务信息
func (h *ServiceHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var services []interface{}

	// 检测服务管理器类型
	serviceManager := h.detectServiceManager()
	if serviceManager == "" {
		h.Logger.Warn("no supported service manager found")
		return services, nil
	}

	h.Logger.Debug("detected service manager", zap.String("type", serviceManager))

	// 根据服务管理器类型采集
	switch serviceManager {
	case "systemd":
		systemdServices, err := h.collectSystemdServices(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to collect systemd services: %w", err)
		}
		services = append(services, systemdServices...)
	case "sysv":
		sysvServices, err := h.collectSysVServices(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to collect SysV services: %w", err)
		}
		services = append(services, sysvServices...)
	}

	return services, nil
}

// detectServiceManager 检测服务管理器类型
func (h *ServiceHandler) detectServiceManager() string {
	// 检测 systemd
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}

	// 检测 SysV（通过 service 命令）
	if _, err := exec.LookPath("service"); err == nil {
		return "sysv"
	}

	return ""
}

// collectSystemdServices 采集 systemd 服务信息
func (h *ServiceHandler) collectSystemdServices(ctx context.Context) ([]interface{}, error) {
	var services []interface{}

	// 执行 systemctl list-units --type=service --all --no-pager
	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute systemctl: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return services, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析 systemctl 输出格式：unit load active sub description
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		serviceName := fields[0]
		activeState := fields[2]

		// 获取服务描述
		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}

		// 检查是否启用（开机自启）
		enabled := h.isSystemdServiceEnabled(ctx, serviceName)

		service := &engine.ServiceAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			ServiceName: serviceName,
			ServiceType: "systemd",
			Status:      activeState,
			Enabled:     enabled,
			Description: description,
		}

		services = append(services, service)
	}

	return services, nil
}

// collectSysVServices 采集 SysV 服务信息
func (h *ServiceHandler) collectSysVServices(ctx context.Context) ([]interface{}, error) {
	var services []interface{}

	// 读取 /etc/init.d 目录
	initDir := "/etc/init.d"
	dirEntries, err := os.ReadDir(initDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list init.d directory: %w", err)
	}

	for _, entry := range dirEntries {
		select {
		case <-ctx.Done():
			return services, ctx.Err()
		default:
		}

		if entry.IsDir() {
			continue
		}

		serviceName := entry.Name()

		// 检查服务状态
		status := h.getSysVServiceStatus(ctx, serviceName)

		// 检查是否启用（通过 chkconfig 或 update-rc.d）
		enabled := h.isSysVServiceEnabled(ctx, serviceName)

		service := &engine.ServiceAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			ServiceName: serviceName,
			ServiceType: "sysv",
			Status:      status,
			Enabled:     enabled,
		}

		services = append(services, service)
	}

	return services, nil
}

// isSystemdServiceEnabled 检查 systemd 服务是否启用
func (h *ServiceHandler) isSystemdServiceEnabled(ctx context.Context, serviceName string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-enabled", serviceName)
	err := cmd.Run()
	return err == nil
}

// getSysVServiceStatus 获取 SysV 服务状态
func (h *ServiceHandler) getSysVServiceStatus(ctx context.Context, serviceName string) string {
	cmd := exec.CommandContext(ctx, "service", serviceName, "status")
	err := cmd.Run()
	if err == nil {
		return "active"
	}
	return "inactive"
}

// isSysVServiceEnabled 检查 SysV 服务是否启用
func (h *ServiceHandler) isSysVServiceEnabled(ctx context.Context, serviceName string) bool {
	// 尝试使用 chkconfig（RHEL/CentOS）
	output, err := exec.CommandContext(ctx, "chkconfig", "--list", serviceName).Output()
	if err == nil {
		return strings.Contains(string(output), "on")
	}

	// 尝试使用 update-rc.d（Debian/Ubuntu）
	err = exec.CommandContext(ctx, "update-rc.d", serviceName, "status").Run()
	return err == nil
}
