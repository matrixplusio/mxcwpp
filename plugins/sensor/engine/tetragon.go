package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// 默认 Tetragon socket 路径
const DefaultTetragonSock = "unix:///var/run/tetragon/tetragon.sock"

// maxConnectFailures 连续连接失败次数上限，超过后放弃重试并退出
// Agent 会自动重启插件，形成退避效果
const maxConnectFailures = 12 // 12 × 5s = 约 1 分钟后放弃

// TetragonClient 通过 JSON 事件流采集 Tetragon eBPF 事件
type TetragonClient struct {
	sockPath string
	logger   *zap.Logger
}

// NewTetragonClient 创建 Tetragon 客户端
func NewTetragonClient(sockPath string, logger *zap.Logger) *TetragonClient {
	if sockPath == "" {
		sockPath = DefaultTetragonSock
	}
	return &TetragonClient{
		sockPath: sockPath,
		logger:   logger,
	}
}

// Available 快速检测 Tetragon 是否可用（tetra CLI 或 socket 存在）
func (c *TetragonClient) Available() bool {
	// LookPath 依赖 PATH，systemd 环境下可能不包含 /usr/local/bin
	if _, err := exec.LookPath("tetra"); err == nil {
		return true
	}
	// 直接检查常见安装路径
	if _, err := os.Stat("/usr/local/bin/tetra"); err == nil {
		return true
	}
	sockAddr := strings.TrimPrefix(c.sockPath, "unix://")
	if _, err := os.Stat(sockAddr); err == nil {
		return true
	}
	return false
}

// EventStream 启动事件流，返回事件 channel
// 优先尝试 tetra CLI 方式；若不可用则回退到直接连接 Unix Socket
func (c *TetragonClient) EventStream(ctx context.Context) (<-chan *TetragonEvent, error) {
	ch := make(chan *TetragonEvent, 256)

	// 尝试 tetra CLI
	if tetraPath, err := exec.LookPath("tetra"); err == nil {
		c.logger.Info("使用 tetra CLI 获取事件流", zap.String("path", tetraPath))
		go c.streamFromCLI(ctx, tetraPath, ch)
		return ch, nil
	}

	// 回退到 Unix Socket 直连
	sockAddr := strings.TrimPrefix(c.sockPath, "unix://")
	c.logger.Info("使用 Unix Socket 直连获取事件流", zap.String("socket", sockAddr))
	go c.streamFromSocket(ctx, sockAddr, ch)
	return ch, nil
}

// streamFromCLI 通过 tetra getevents 命令获取 JSON 事件流
func (c *TetragonClient) streamFromCLI(ctx context.Context, tetraPath string, ch chan<- *TetragonEvent) {
	defer close(ch)

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmd := exec.CommandContext(ctx, tetraPath, "getevents", "-o", "json")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			consecutiveFailures++
			c.logger.Error("创建 tetra stdout pipe 失败", zap.Error(err), zap.Int("failures", consecutiveFailures))
			if consecutiveFailures >= maxConnectFailures {
				c.logger.Error("tetra CLI 连续失败次数超限，放弃重试", zap.Int("max", maxConnectFailures))
				return
			}
			c.sleepOrDone(ctx, 5*time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			consecutiveFailures++
			c.logger.Error("启动 tetra 命令失败", zap.Error(err), zap.Int("failures", consecutiveFailures))
			if consecutiveFailures >= maxConnectFailures {
				c.logger.Error("tetra CLI 连续失败次数超限，放弃重试", zap.Int("max", maxConnectFailures))
				return
			}
			c.sleepOrDone(ctx, 5*time.Second)
			continue
		}

		// 连接成功，重置计数器
		consecutiveFailures = 0
		c.logger.Info("tetra 进程已启动", zap.Int("pid", cmd.Process.Pid))

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024) // 最大 1MB 行缓冲

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return
			default:
			}

			event := c.parseJSON(scanner.Bytes())
			if event != nil {
				select {
				case ch <- event:
				case <-ctx.Done():
					_ = cmd.Process.Kill()
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			c.logger.Warn("tetra 输出读取错误", zap.Error(err))
		}

		_ = cmd.Wait()
		c.logger.Warn("tetra 进程已退出，将重新启动")
		c.sleepOrDone(ctx, 3*time.Second)
	}
}

// streamFromSocket 通过 Unix Socket 直连读取 JSON 事件流
func (c *TetragonClient) streamFromSocket(ctx context.Context, sockAddr string, ch chan<- *TetragonEvent) {
	defer close(ch)

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := net.DialTimeout("unix", sockAddr, 10*time.Second)
		if err != nil {
			consecutiveFailures++
			c.logger.Error("连接 Tetragon socket 失败",
				zap.String("socket", sockAddr),
				zap.Int("failures", consecutiveFailures),
				zap.Error(err))
			if consecutiveFailures >= maxConnectFailures {
				c.logger.Error("Tetragon socket 连续失败次数超限，放弃重试（Tetragon 可能未安装）",
					zap.Int("max", maxConnectFailures))
				return
			}
			c.sleepOrDone(ctx, 5*time.Second)
			continue
		}

		// 连接成功，重置计数器
		consecutiveFailures = 0
		c.logger.Info("已连接 Tetragon socket", zap.String("socket", sockAddr))

		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			default:
			}

			event := c.parseJSON(scanner.Bytes())
			if event != nil {
				select {
				case ch <- event:
				case <-ctx.Done():
					_ = conn.Close()
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			c.logger.Warn("socket 读取错误", zap.Error(err))
		}
		_ = conn.Close()

		c.logger.Warn("Tetragon socket 连接断开，将重连")
		c.sleepOrDone(ctx, 3*time.Second)
	}
}

// parseJSON 解析 Tetragon JSON 事件
func (c *TetragonClient) parseJSON(data []byte) *TetragonEvent {
	if len(data) == 0 {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		c.logger.Debug("JSON 解析失败", zap.Error(err))
		return nil
	}

	// 判断事件类型
	if _, ok := raw["process_exec"]; ok {
		return c.parseProcessExec(raw["process_exec"])
	}
	if _, ok := raw["process_exit"]; ok {
		return c.parseProcessExit(raw["process_exit"])
	}
	if _, ok := raw["process_kprobe"]; ok {
		return c.parseKprobe(raw["process_kprobe"])
	}

	return nil
}

// parseProcessExec 解析 process_exec 事件
func (c *TetragonClient) parseProcessExec(data json.RawMessage) *TetragonEvent {
	var exec struct {
		Process tetragonProcess `json:"process"`
		Parent  tetragonProcess `json:"parent"`
		Time    string          `json:"time"`
	}

	if err := json.Unmarshal(data, &exec); err != nil {
		c.logger.Debug("解析 process_exec 失败", zap.Error(err))
		return nil
	}

	return &TetragonEvent{
		EventType: "process_exec",
		Timestamp: parseTime(exec.Time),
		Process: &ProcessInfo{
			PID:       exec.Process.PID,
			PPID:      exec.Parent.PID,
			Exe:       exec.Process.Binary,
			Cmdline:   exec.Process.Arguments,
			ParentExe: exec.Parent.Binary,
			UID:       exec.Process.UID,
			GID:       exec.Process.GID,
		},
	}
}

// parseProcessExit 解析 process_exit 事件
func (c *TetragonClient) parseProcessExit(data json.RawMessage) *TetragonEvent {
	var exit struct {
		Process tetragonProcess `json:"process"`
		Parent  tetragonProcess `json:"parent"`
		Time    string          `json:"time"`
	}

	if err := json.Unmarshal(data, &exit); err != nil {
		c.logger.Debug("解析 process_exit 失败", zap.Error(err))
		return nil
	}

	return &TetragonEvent{
		EventType: "process_exit",
		Timestamp: parseTime(exit.Time),
		Process: &ProcessInfo{
			PID:       exit.Process.PID,
			PPID:      exit.Parent.PID,
			Exe:       exit.Process.Binary,
			Cmdline:   exit.Process.Arguments,
			ParentExe: exit.Parent.Binary,
			UID:       exit.Process.UID,
			GID:       exit.Process.GID,
		},
	}
}

// parseKprobe 解析 process_kprobe 事件（文件和网络事件通过 kprobe 上报）
func (c *TetragonClient) parseKprobe(data json.RawMessage) *TetragonEvent {
	var kprobe struct {
		Process      tetragonProcess `json:"process"`
		Parent       tetragonProcess `json:"parent"`
		FunctionName string          `json:"function_name"`
		Args         []tetragonArg   `json:"args"`
		Time         string          `json:"time"`
	}

	if err := json.Unmarshal(data, &kprobe); err != nil {
		c.logger.Debug("解析 process_kprobe 失败", zap.Error(err))
		return nil
	}

	process := &ProcessInfo{
		PID:       kprobe.Process.PID,
		PPID:      kprobe.Parent.PID,
		Exe:       kprobe.Process.Binary,
		Cmdline:   kprobe.Process.Arguments,
		ParentExe: kprobe.Parent.Binary,
		UID:       kprobe.Process.UID,
		GID:       kprobe.Process.GID,
	}

	ts := parseTime(kprobe.Time)

	// 根据 function_name 判断事件类型
	switch {
	case isFileFunction(kprobe.FunctionName):
		return &TetragonEvent{
			EventType: inferFileEventType(kprobe.FunctionName),
			Timestamp: ts,
			Process:   process,
			File:      extractFileInfo(kprobe.Args),
		}
	case isNetworkFunction(kprobe.FunctionName):
		netInfo := extractNetworkInfo(kprobe.Args)
		eventType := inferNetworkEventType(kprobe.FunctionName)
		// sockaddr_arg 没有协议信息，根据事件类型推断
		if netInfo.Protocol == "" {
			if strings.Contains(eventType, "udp") {
				netInfo.Protocol = "udp"
			} else {
				netInfo.Protocol = "tcp"
			}
		}
		return &TetragonEvent{
			EventType: eventType,
			Timestamp: ts,
			Process:   process,
			Network:   netInfo,
		}
	default:
		return nil
	}
}

// --- 内部 JSON 模型 ---

type tetragonProcess struct {
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
}

type tetragonArg struct {
	StringArg string `json:"string_arg,omitempty"`
	IntArg    int64  `json:"int_arg,omitempty"`
	SockArg   *struct {
		Family string `json:"family"`
		Type   string `json:"type"`
		Saddr  string `json:"saddr"`
		Daddr  string `json:"daddr"`
		Sport  uint32 `json:"sport"`
		Dport  uint32 `json:"dport"`
	} `json:"sock_arg,omitempty"`
	// SockaddrArg 用于 syscall kprobe（sys_connect/sys_accept4/sys_sendto）
	// 结构与 sock_arg 不同：只有一组 addr/port，代表对端地址
	SockaddrArg *struct {
		Family string `json:"family"`
		Addr   string `json:"addr"`
		Port   uint32 `json:"port"`
	} `json:"sockaddr_arg,omitempty"`
	SkbArg *struct {
		Saddr  string `json:"saddr"`
		Daddr  string `json:"daddr"`
		Sport  uint32 `json:"sport"`
		Dport  uint32 `json:"dport"`
		Proto  uint32 `json:"proto"`
		Family string `json:"family"`
	} `json:"skb_arg,omitempty"`
	FileArg *struct {
		Path  string `json:"path"`
		Flags string `json:"flags"`
	} `json:"file_arg,omitempty"`
}

// --- 辅助函数 ---

func parseTime(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	// Tetragon 使用 RFC3339Nano 格式
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Now()
	}
	return t
}

// isFileFunction 判断是否为文件相关的内核函数
func isFileFunction(name string) bool {
	fileKernelFuncs := []string{
		"fd_install",
		"security_file_open",
		"__x64_sys_openat",
		"__x64_sys_openat2",
		"__x64_sys_open",
		"security_file_permission",
		"vfs_open",
		"vfs_read",
		"vfs_write",
	}
	for _, fn := range fileKernelFuncs {
		if name == fn {
			return true
		}
	}
	return false
}

// isNetworkFunction 判断是否为网络相关的内核函数
func isNetworkFunction(name string) bool {
	netKernelFuncs := []string{
		"tcp_connect",
		"tcp_close",
		"tcp_sendmsg",
		"security_socket_connect",
		"__x64_sys_connect",
		"__x64_sys_accept4",
		"__x64_sys_sendto",
		"tcp_v4_connect",
		"tcp_v6_connect",
		"inet_csk_accept",
		"icmp_rcv",
	}
	for _, fn := range netKernelFuncs {
		if name == fn {
			return true
		}
	}
	return false
}

// inferFileEventType 从内核函数名推断文件事件类型
func inferFileEventType(funcName string) string {
	switch {
	case strings.Contains(funcName, "write"):
		return "file_write"
	case strings.Contains(funcName, "read"):
		return "file_read"
	default:
		return "file_open"
	}
}

// inferNetworkEventType 从内核函数名推断网络事件类型
func inferNetworkEventType(funcName string) string {
	switch {
	case strings.Contains(funcName, "close"):
		return "tcp_close"
	case strings.Contains(funcName, "sendto"):
		return "udp_send"
	case strings.Contains(funcName, "sendmsg"):
		return "tcp_send"
	case strings.Contains(funcName, "accept"):
		return "tcp_accept"
	case strings.Contains(funcName, "icmp"):
		return "icmp_recv"
	default:
		return "tcp_connect"
	}
}

// extractFileInfo 从 kprobe 参数中提取文件信息
func extractFileInfo(args []tetragonArg) *FileInfo {
	info := &FileInfo{}
	for _, arg := range args {
		if arg.FileArg != nil {
			info.Path = arg.FileArg.Path
			info.Flags = arg.FileArg.Flags
			return info
		}
		// 有些 kprobe 事件中文件路径以 string_arg 形式出现
		if arg.StringArg != "" && info.Path == "" {
			info.Path = arg.StringArg
		}
	}
	return info
}

// extractNetworkInfo 从 kprobe 参数中提取网络信息
func extractNetworkInfo(args []tetragonArg) *NetworkInfo {
	info := &NetworkInfo{}
	for _, arg := range args {
		// sock_arg: 内核态 kprobe（tcp_connect/inet_csk_accept 等），有 saddr/daddr
		if arg.SockArg != nil {
			info.RemoteAddr = arg.SockArg.Daddr
			info.RemotePort = arg.SockArg.Dport
			info.LocalAddr = arg.SockArg.Saddr
			info.LocalPort = arg.SockArg.Sport
			info.Protocol = inferProtocol(arg.SockArg.Type)
			return info
		}
		// sockaddr_arg: syscall kprobe（sys_connect/sys_accept4/sys_sendto），
		// 只有一组 addr/port，代表对端（远程）地址
		if arg.SockaddrArg != nil {
			info.RemoteAddr = arg.SockaddrArg.Addr
			info.RemotePort = arg.SockaddrArg.Port
			if arg.SockaddrArg.Family == "AF_INET6" {
				info.Protocol = "tcp6"
			}
			return info
		}
		// skb_arg: ICMP 等非 socket 事件
		if arg.SkbArg != nil {
			info.RemoteAddr = arg.SkbArg.Saddr
			info.LocalAddr = arg.SkbArg.Daddr
			info.RemotePort = arg.SkbArg.Sport
			info.LocalPort = arg.SkbArg.Dport
			info.Protocol = inferSkbProtocol(arg.SkbArg.Proto)
			return info
		}
	}
	return info
}

// inferProtocol 从 socket 类型推断协议
func inferProtocol(sockType string) string {
	switch strings.ToLower(sockType) {
	case "sock_stream":
		return "tcp"
	case "sock_dgram":
		return "udp"
	default:
		return "tcp"
	}
}

// inferSkbProtocol 从 IP 协议号推断协议名称
func inferSkbProtocol(proto uint32) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", proto)
	}
}

// sleepOrDone 休眠指定时间，或者上下文取消时立即返回
func (c *TetragonClient) sleepOrDone(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// FormatUint32 将 uint32 格式化为字符串
func FormatUint32(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

// FormatPort 将端口号格式化为字符串
func FormatPort(v uint32) string {
	return fmt.Sprintf("%d", v)
}
