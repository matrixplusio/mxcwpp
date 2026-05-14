// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// ContainerHandler 是容器采集器
type ContainerHandler struct {
	Logger *zap.Logger
}

// Collect 采集容器信息
func (h *ContainerHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var containers []interface{}

	// 检测容器运行时
	runtimes := h.detectContainerRuntimes()
	if len(runtimes) == 0 {
		h.Logger.Debug("no container runtime detected")
		return containers, nil
	}

	// 采集 Docker 容器
	if contains(runtimes, "docker") {
		dockerContainers, err := h.collectDockerContainers(ctx)
		if err != nil {
			h.Logger.Warn("failed to collect Docker containers", zap.Error(err))
		} else {
			containers = append(containers, dockerContainers...)
		}
	}

	// 采集 containerd 容器
	if contains(runtimes, "containerd") {
		containerdContainers, err := h.collectContainerdContainers(ctx)
		if err != nil {
			h.Logger.Warn("failed to collect containerd containers", zap.Error(err))
		} else {
			containers = append(containers, containerdContainers...)
		}
	}

	return containers, nil
}

// detectContainerRuntimes 检测容器运行时
func (h *ContainerHandler) detectContainerRuntimes() []string {
	var runtimes []string

	// 检测 Docker
	if _, err := exec.LookPath("docker"); err == nil {
		runtimes = append(runtimes, "docker")
	}

	// 检测 containerd
	if _, err := exec.LookPath("ctr"); err == nil {
		runtimes = append(runtimes, "containerd")
	}

	// 检测 containerd socket
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		if !contains(runtimes, "containerd") {
			runtimes = append(runtimes, "containerd")
		}
	}

	return runtimes
}

// collectDockerContainers 采集 Docker 容器信息
func (h *ContainerHandler) collectDockerContainers(ctx context.Context) ([]interface{}, error) {
	var containers []interface{}

	// 执行 docker ps -a --format json
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute docker ps: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return containers, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var dockerInfo map[string]interface{}
		if err := json.Unmarshal([]byte(line), &dockerInfo); err != nil {
			h.Logger.Debug("failed to parse docker output", zap.String("line", line), zap.Error(err))
			continue
		}

		containerID := h.getString(dockerInfo, "ID")
		containerName := h.getString(dockerInfo, "Names")
		image := h.getString(dockerInfo, "Image")
		status := h.getString(dockerInfo, "Status")
		createdAt := h.getString(dockerInfo, "CreatedAt")

		// 获取镜像 ID
		imageID := h.getDockerImageID(ctx, containerID)

		container := &engine.ContainerAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			ContainerID:   containerID,
			ContainerName: containerName,
			Image:         image,
			ImageID:       imageID,
			Runtime:       "docker",
			Status:        status,
			CreatedAt:     createdAt,
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// collectContainerdContainers 采集 containerd 容器信息
func (h *ContainerHandler) collectContainerdContainers(ctx context.Context) ([]interface{}, error) {
	// 尝试使用 ctr 命令
	if _, err := exec.LookPath("ctr"); err == nil {
		return h.collectContainerdWithCtr(ctx)
	}

	// 尝试读取 containerd 元数据目录
	return h.collectContainerdFromMetadata(ctx)
}

// collectContainerdWithCtr 使用 ctr 命令采集
func (h *ContainerHandler) collectContainerdWithCtr(ctx context.Context) ([]interface{}, error) {
	var containers []interface{}

	// 执行 ctr -n k8s.io containers list
	cmd := exec.CommandContext(ctx, "ctr", "-n", "k8s.io", "containers", "list", "-q")
	output, err := cmd.Output()
	if err != nil {
		// 如果 k8s.io namespace 失败，尝试 default
		cmd = exec.CommandContext(ctx, "ctr", "-n", "default", "containers", "list", "-q")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to execute ctr: %w", err)
		}
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return containers, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析容器信息（格式：image/container_id）
		parts := strings.Split(line, "/")
		containerID := ""
		image := ""
		if len(parts) >= 2 {
			image = parts[0]
			containerID = parts[len(parts)-1]
		} else {
			containerID = line
		}

		container := &engine.ContainerAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			ContainerID:   containerID,
			ContainerName: containerID,
			Image:         image,
			ImageID:       "",
			Runtime:       "containerd",
			Status:        "unknown",
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// collectContainerdFromMetadata 从元数据目录采集
func (h *ContainerHandler) collectContainerdFromMetadata(ctx context.Context) ([]interface{}, error) {
	var containers []interface{}

	// containerd 元数据目录通常在 /var/lib/containerd/io.containerd.runtime.v2.task/
	metadataDirs := []string{
		"/var/lib/containerd/io.containerd.runtime.v2.task/",
		"/run/containerd/io.containerd.runtime.v2.task/",
	}

	for _, metadataDir := range metadataDirs {
		if _, err := os.Stat(metadataDir); err != nil {
			continue
		}

		// 遍历命名空间目录
		namespaces, err := os.ReadDir(metadataDir)
		if err != nil {
			continue
		}

		for _, ns := range namespaces {
			if !ns.IsDir() {
				continue
			}

			nsPath := filepath.Join(metadataDir, ns.Name())
			containersInNs, err := os.ReadDir(nsPath)
			if err != nil {
				continue
			}

			for _, container := range containersInNs {
				select {
				case <-ctx.Done():
					return containers, ctx.Err()
				default:
				}

				if !container.IsDir() {
					continue
				}

				containerID := container.Name()
				containerAsset := &engine.ContainerAsset{
					Asset: engine.Asset{
						CollectedAt: time.Now(),
					},
					ContainerID:   containerID,
					ContainerName: containerID,
					Image:         "",
					ImageID:       "",
					Runtime:       "containerd",
					Status:        "unknown",
				}

				containers = append(containers, containerAsset)
			}
		}
	}

	return containers, nil
}

// getDockerImageID 获取 Docker 镜像 ID
func (h *ContainerHandler) getDockerImageID(ctx context.Context, containerID string) string {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Image}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getString 从 map 中获取字符串值
func (h *ContainerHandler) getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// contains 检查字符串切片是否包含指定字符串
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
