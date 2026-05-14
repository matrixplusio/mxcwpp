// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// ProcessHandler 是进程采集器
type ProcessHandler struct {
	Logger *zap.Logger
}

// Collect 采集进程信息
func (h *ProcessHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var processes []interface{}

	// 遍历 /proc 目录
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		// 只处理数字目录（PID）
		pid := entry.Name()
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return processes, ctx.Err()
		default:
		}

		// 采集进程信息
		proc, err := h.collectProcess(pid)
		if err != nil {
			h.Logger.Debug("failed to collect process",
				zap.String("pid", pid),
				zap.Error(err))
			continue
		}

		if proc != nil {
			processes = append(processes, proc)
		}
	}

	return processes, nil
}

// collectProcess 采集单个进程信息
func (h *ProcessHandler) collectProcess(pid string) (*engine.ProcessAsset, error) {
	procPath := filepath.Join("/proc", pid)

	// 读取命令行
	cmdline, _ := h.readFile(filepath.Join(procPath, "cmdline"))
	cmdline = strings.ReplaceAll(cmdline, "\x00", " ")

	// 读取可执行文件路径
	exe, _ := os.Readlink(filepath.Join(procPath, "exe"))

	// 读取 stat 文件获取基本信息
	stat, _ := h.readFile(filepath.Join(procPath, "stat"))
	ppid := h.parseStatField(stat, 3) // PPID 在第 4 个字段

	// 读取 status 文件获取 UID/GID
	status, _ := h.readFile(filepath.Join(procPath, "status"))
	uid := h.parseStatusField(status, "Uid:")
	gid := h.parseStatusField(status, "Gid:")

	// 解析用户名和组名
	username, groupname := h.resolveUserGroup(uid, gid)

	// 计算可执行文件 MD5（如果文件存在）
	var exeHash string
	if exe != "" {
		if hash, err := h.calculateMD5(exe); err == nil {
			exeHash = hash
		}
	}

	// 检测容器关联（通过 cgroup）
	containerID := h.detectContainer(pid)

	// 构建进程资产数据
	// 注意：HostID 由 Server 端填充
	proc := &engine.ProcessAsset{
		Asset: engine.Asset{
			CollectedAt: time.Now(),
		},
		PID:         pid,
		PPID:        ppid,
		Cmdline:     cmdline,
		Exe:         exe,
		ExeHash:     exeHash,
		ContainerID: containerID,
		UID:         uid,
		GID:         gid,
		Username:    username,
		Groupname:   groupname,
	}

	return proc, nil
}

// readFile 读取文件内容（简化实现，忽略错误）
func (h *ProcessHandler) readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// parseStatField 解析 /proc/{pid}/stat 文件的字段
func (h *ProcessHandler) parseStatField(stat string, index int) string {
	fields := strings.Fields(stat)
	if len(fields) > index {
		return fields[index]
	}
	return ""
}

// parseStatusField 解析 /proc/{pid}/status 文件的字段
func (h *ProcessHandler) parseStatusField(status, key string) string {
	lines := strings.Split(status, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, key) {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[1] // 返回第一个值（实际 UID/GID）
			}
		}
	}
	return ""
}

// resolveUserGroup 解析用户名和组名
func (h *ProcessHandler) resolveUserGroup(uidStr, gidStr string) (string, string) {
	var username, groupname string

	if uidStr != "" {
		if u, err := user.LookupId(uidStr); err == nil {
			username = u.Username
		}
	}

	if gidStr != "" {
		if g, err := user.LookupGroupId(gidStr); err == nil {
			groupname = g.Name
		}
	}

	return username, groupname
}

// calculateMD5 计算文件 MD5
func (h *ProcessHandler) calculateMD5(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// detectContainer 检测容器关联
func (h *ProcessHandler) detectContainer(pid string) string {
	// 读取 cgroup 文件
	cgroupPath := filepath.Join("/proc", pid, "cgroup")
	cgroup, err := h.readFile(cgroupPath)
	if err != nil {
		return ""
	}

	// 解析 cgroup 内容，查找容器 ID
	// Docker: /docker/{container_id}
	// containerd: /containerd/{container_id}
	lines := strings.Split(cgroup, "\n")
	for _, line := range lines {
		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) > 1 {
				containerID := strings.Split(parts[1], "/")[0]
				return containerID
			}
		}
		if strings.Contains(line, "/containerd/") {
			parts := strings.Split(line, "/containerd/")
			if len(parts) > 1 {
				containerID := strings.Split(parts[1], "/")[0]
				return containerID
			}
		}
	}

	return ""
}
