// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/plugins/collector/engine"
)

// PortHandler 是端口采集器
type PortHandler struct {
	Logger *zap.Logger
}

// Collect 采集端口信息
func (h *PortHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var ports []interface{}

	// 采集 TCP 端口
	tcpPorts, err := h.collectTCPPorts(ctx)
	if err != nil {
		h.Logger.Warn("failed to collect TCP ports", zap.Error(err))
	} else {
		ports = append(ports, tcpPorts...)
	}

	// 采集 UDP 端口
	udpPorts, err := h.collectUDPPorts(ctx)
	if err != nil {
		h.Logger.Warn("failed to collect UDP ports", zap.Error(err))
	} else {
		ports = append(ports, udpPorts...)
	}

	return ports, nil
}

// collectTCPPorts 采集 TCP 端口
func (h *PortHandler) collectTCPPorts(ctx context.Context) ([]interface{}, error) {
	return h.collectPortsFromFile("/proc/net/tcp", "tcp", ctx)
}

// collectUDPPorts 采集 UDP 端口
func (h *PortHandler) collectUDPPorts(ctx context.Context) ([]interface{}, error) {
	return h.collectPortsFromFile("/proc/net/udp", "udp", ctx)
}

// collectPortsFromFile 从 /proc/net/{tcp,udp} 文件采集端口信息
func (h *PortHandler) collectPortsFromFile(filepath, protocol string, ctx context.Context) ([]interface{}, error) {
	var ports []interface{}

	// 读取文件
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filepath, err)
	}

	lines := strings.Split(string(data), "\n")
	// 跳过第一行（表头）
	for i := 1; i < len(lines); i++ {
		select {
		case <-ctx.Done():
			return ports, ctx.Err()
		default:
		}

		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		port, err := h.parsePortLine(line, protocol)
		if err != nil {
			h.Logger.Debug("failed to parse port line",
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		if port != nil {
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// parsePortLine 解析端口行
// 格式：sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
func (h *PortHandler) parsePortLine(line, protocol string) (*engine.PortAsset, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil, fmt.Errorf("invalid port line format")
	}

	// 解析本地地址（格式：IP:PORT，十六进制）
	localAddr := fields[1]
	addrParts := strings.Split(localAddr, ":")
	if len(addrParts) < 2 {
		return nil, fmt.Errorf("invalid local address format: %s", localAddr)
	}
	portHex := addrParts[1]
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port: %w", err)
	}

	// 解析状态（TCP 才有状态）
	state := ""
	if protocol == "tcp" {
		stateHex := fields[3]
		stateCode, _ := strconv.ParseInt(stateHex, 16, 32)
		state = h.tcpStateToString(int(stateCode))
	}

	// 解析 inode（用于关联进程）
	inode := fields[9]

	// 通过 inode 查找进程
	pid, processName := h.findProcessByInode(inode)

	// 检测容器关联
	containerID := ""
	if pid != "" {
		containerID = h.detectContainer(pid)
	}

	// 构建端口资产数据
	portAsset := &engine.PortAsset{
		Asset: engine.Asset{
			CollectedAt: time.Now(),
		},
		Protocol:    protocol,
		Port:        int(port),
		State:       state,
		PID:         pid,
		ProcessName: processName,
		ContainerID: containerID,
	}

	return portAsset, nil
}

// tcpStateToString 将 TCP 状态码转换为字符串
func (h *PortHandler) tcpStateToString(code int) string {
	states := map[int]string{
		0x01: "ESTABLISHED",
		0x02: "SYN_SENT",
		0x03: "SYN_RECV",
		0x04: "FIN_WAIT1",
		0x05: "FIN_WAIT2",
		0x06: "TIME_WAIT",
		0x07: "CLOSE",
		0x08: "CLOSE_WAIT",
		0x09: "LAST_ACK",
		0x0A: "LISTEN",
		0x0B: "CLOSING",
	}
	if state, ok := states[code]; ok {
		return state
	}
	return fmt.Sprintf("UNKNOWN(%d)", code)
}

// findProcessByInode 通过 inode 查找进程
func (h *PortHandler) findProcessByInode(inode string) (string, string) {
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return "", ""
	}

	for _, entry := range entries {
		pid := entry.Name()
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// 遍历进程的文件描述符目录
		fdDir := filepath.Join(procDir, pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}

			// 检查是否是 socket，格式：socket:[inode]
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				fdInode := strings.TrimPrefix(strings.TrimSuffix(link, "]"), "socket:[")
				if fdInode == inode {
					// 找到进程，读取进程名
					cmdline, _ := h.readFile(filepath.Join(procDir, pid, "cmdline"))
					processName := h.extractProcessName(cmdline)
					return pid, processName
				}
			}
		}
	}

	return "", ""
}

// extractProcessName 从命令行提取进程名
func (h *PortHandler) extractProcessName(cmdline string) string {
	cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
	parts := strings.Fields(cmdline)
	if len(parts) > 0 {
		return filepath.Base(parts[0])
	}
	return ""
}

// readFile 读取文件内容
func (h *PortHandler) readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// detectContainer 检测容器关联
func (h *PortHandler) detectContainer(pid string) string {
	cgroupPath := filepath.Join("/proc", pid, "cgroup")
	cgroup, err := h.readFile(cgroupPath)
	if err != nil {
		return ""
	}

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
