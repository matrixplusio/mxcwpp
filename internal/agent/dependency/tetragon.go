package dependency

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

const defaultTetragonVersion = "1.6.1"

// tetragonPolicyDir TracingPolicy 部署目录
const tetragonPolicyDir = "/etc/tetragon/tetragon.tp.d"

// tetragonConfig 默认配置内容
const tetragonConfig = `# MxSec Tetragon 配置
export-filename: ""
export-file-max-size-mb: 100
export-file-rotation-interval: 24h
export-file-max-backups: 3
export-file-compress: true
enable-process-cred: true
enable-process-ns: true
process-cache-size: 65536
data-cache-size: 1024
metrics-server: ""
health-server: ""
gops-address: ""
`

// TracingPolicy 内嵌策略定义
// 这些策略控制 Tetragon eBPF 钩子采集哪些内核事件
var tracingPolicies = map[string]string{
	"mxsec-process-monitor.yaml": `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: mxsec-process-monitor
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
        - index: 1
          type: "string"
      selectors:
        - matchActions:
            - action: Post
      return: false
      returnArg:
        index: 0
        type: "int"
    - call: "sys_execveat"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "string"
        - index: 2
          type: "string"
      selectors:
        - matchActions:
            - action: Post
    - call: "sys_setuid"
      syscall: true
      args:
        - index: 0
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "0"
          matchActions:
            - action: Post
    - call: "sys_ptrace"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "int"
      selectors:
        - matchActions:
            - action: Post
`,
	"mxsec-file-monitor.yaml": `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: mxsec-file-monitor
spec:
  kprobes:
    - call: "sys_openat"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "string"
        - index: 2
          type: "int"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/passwd"
                - "/etc/shadow"
                - "/etc/sudoers"
                - "/etc/crontab"
                - "/etc/cron.d"
                - "/etc/ssh/sshd_config"
                - "/etc/ld.so.preload"
                - "/etc/pam.d"
                - "/root/.ssh"
                - "/root/.bash_history"
                - "/var/spool/cron"
                - "/var/www"
                - "/usr/share/nginx/html"
                - "/opt/lampp/htdocs"
                - "/etc/init.d"
                - "/etc/systemd/system"
                - "/usr/lib/systemd/system"
                - "/lib/modules"
                - "/etc/modprobe.d"
                - "/etc/ld.so.conf"
                - "/etc/ld.so.conf.d"
          matchActions:
            - action: Post
    - call: "sys_openat2"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "string"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/passwd"
                - "/etc/shadow"
                - "/etc/sudoers"
                - "/etc/crontab"
                - "/etc/cron.d"
                - "/etc/ssh/sshd_config"
                - "/etc/ld.so.preload"
                - "/etc/pam.d"
                - "/root/.ssh"
                - "/root/.bash_history"
                - "/var/spool/cron"
                - "/var/www"
                - "/usr/share/nginx/html"
                - "/opt/lampp/htdocs"
                - "/etc/init.d"
                - "/etc/systemd/system"
                - "/usr/lib/systemd/system"
                - "/lib/modules"
                - "/etc/modprobe.d"
                - "/etc/ld.so.conf"
                - "/etc/ld.so.conf.d"
          matchActions:
            - action: Post
`,
	"mxsec-network-monitor.yaml": `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: mxsec-network-monitor
spec:
  kprobes:
    - call: "sys_connect"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "sockaddr"
        - index: 2
          type: "int"
      selectors:
        - matchArgs:
            - index: 1
              operator: "NotSAddr"
              values:
                - "127.0.0.0/8"
                - "::1"
          matchActions:
            - action: Post
    - call: "sys_accept4"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "sockaddr"
        - index: 3
          type: "int"
      selectors:
        - matchActions:
            - action: Post
    - call: "sys_sendto"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 4
          type: "sockaddr"
      selectors:
        - matchArgs:
            - index: 4
              operator: "SPort"
              values:
                - "53"
                - "853"
                - "4444"
                - "5555"
                - "6666"
                - "8888"
                - "9999"
                - "31337"
          matchActions:
            - action: Post
    - call: "icmp_rcv"
      syscall: false
      args:
        - index: 0
          type: "skb"
      selectors:
        - matchActions:
            - action: Post
`,
}

// executeTetragon 执行 Tetragon 相关操作
func (m *Manager) executeTetragon(action, version string) Result {
	switch action {
	case "install":
		return m.installTetragon(version)
	case "uninstall":
		return m.uninstallTetragon()
	case "status":
		return m.statusTetragon()
	case "update-policy":
		return m.updateTetragonPolicy()
	default:
		return Result{Success: false, Message: fmt.Sprintf("unknown action: %s", action)}
	}
}

// installTetragon 安装 Tetragon
func (m *Manager) installTetragon(version string) Result {
	// 1. 检查是否已安装
	if ver := tetragonVersion(); ver != "" {
		m.logger.Info("tetragon already installed, ensuring policies are deployed", zap.String("version", ver))
		// 已安装：确保 TracingPolicy 是最新的
		deployed := deployTracingPolicies()
		if deployed > 0 {
			// 重启使策略生效
			_ = startTetragon()
			m.logger.Info("tracing policies refreshed", zap.Int("deployed", deployed))
		}
		return Result{Success: true, Message: fmt.Sprintf("already installed, %d policies deployed", deployed), Version: ver}
	}

	// 2. 内核版本检查 (>= 4.19)
	if err := checkKernelVersion(); err != nil {
		return Result{Success: false, Message: err.Error()}
	}

	// 3. systemd 检查
	if _, err := runCommand("systemctl", "--version"); err != nil {
		return Result{Success: false, Message: "systemd not available"}
	}

	// 4. 确定版本和架构
	if version == "" {
		version = defaultTetragonVersion
	}
	arch := detectArch()
	if arch == "" {
		return Result{Success: false, Message: "unsupported architecture"}
	}

	// 5. 安装
	pkgMgr := detectPackageManager()
	m.logger.Info("installing tetragon",
		zap.String("version", version),
		zap.String("arch", arch),
		zap.String("pkg_manager", pkgMgr))

	if err := downloadAndInstallTetragon(version, arch, m.BackendURL); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("install failed: %v", err)}
	}

	// 6. 配置
	if err := configureTetragon(); err != nil {
		m.logger.Warn("failed to configure tetragon", zap.Error(err))
	}

	// 6.5 部署 TracingPolicy
	deployed := deployTracingPolicies()
	m.logger.Info("deployed tracing policies", zap.Int("count", deployed))

	// 7. 启动服务
	if err := startTetragon(); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("start failed: %v", err)}
	}

	ver := tetragonVersion()
	m.logger.Info("tetragon installed successfully", zap.String("version", ver))
	return Result{Success: true, Message: "installed successfully", Version: ver}
}

// uninstallTetragon 卸载 Tetragon
func (m *Manager) uninstallTetragon() Result {
	// 停止服务
	_, _ = runCommand("systemctl", "stop", "tetragon")
	_, _ = runCommand("systemctl", "disable", "tetragon")

	// 先尝试包管理器卸载（旧安装方式或用户手动包安装的情况）
	pkgMgr := detectPackageManager()
	switch pkgMgr {
	case "apt":
		_, _ = runCommand("apt-get", "remove", "-y", "tetragon")
	case "yum", "dnf":
		_, _ = runCommand(pkgMgr, "remove", "-y", "tetragon")
	}

	// 清理 tar.gz 安装的文件
	for _, f := range []string{
		"/usr/local/bin/tetragon",
		"/usr/local/bin/tetra",
		"/etc/systemd/system/tetragon.service",
	} {
		os.Remove(f)
	}
	_, _ = runCommand("systemctl", "daemon-reload")

	m.logger.Info("tetragon uninstalled")
	return Result{Success: true, Message: "uninstalled successfully"}
}

// statusTetragon 检查 Tetragon 状态
func (m *Manager) statusTetragon() Result {
	ver := tetragonVersion()
	if ver == "" {
		return Result{Success: true, Message: "not installed"}
	}

	out, err := runCommand("systemctl", "is-active", "tetragon")
	status := "unknown"
	if err == nil {
		status = out
	}

	// 检查 socket
	socketExists := false
	if _, err := os.Stat("/var/run/tetragon/tetragon.sock"); err == nil {
		socketExists = true
	}

	msg := fmt.Sprintf("version=%s, service=%s, socket=%v", ver, status, socketExists)
	return Result{Success: true, Message: msg, Version: ver}
}

// checkKernelVersion 检查内核版本 >= 4.19
func checkKernelVersion() error {
	out, err := runCommand("uname", "-r")
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}

	parts := strings.SplitN(out, ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("unexpected kernel version format: %s", out)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid kernel major version: %s", parts[0])
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid kernel minor version: %s", parts[1])
	}

	if major < 4 || (major == 4 && minor < 19) {
		return fmt.Errorf("kernel %d.%d < 4.19, tetragon requires kernel >= 4.19", major, minor)
	}
	return nil
}

// detectArch 检测系统架构
func detectArch() string {
	out, err := runCommand("uname", "-m")
	if err != nil {
		return ""
	}
	switch out {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return ""
	}
}

// tetragonVersion 获取已安装的 Tetragon 版本
func tetragonVersion() string {
	out, err := runCommand("tetra", "version")
	if err != nil {
		return ""
	}
	// tetra version 输出格式: "tetra version v1.2.0"
	fields := strings.Fields(out)
	for _, f := range fields {
		if strings.HasPrefix(f, "v") {
			return strings.TrimPrefix(f, "v")
		}
	}
	if len(fields) > 0 {
		return fields[len(fields)-1]
	}
	return out
}

// downloadAndInstallTetragon 下载并安装 Tetragon (tar.gz 方式)
// 优先从后台系统(backendURL)下载，失败时 fallback 到 GitHub
func downloadAndInstallTetragon(version, arch, backendURL string) error {
	tmpFile := fmt.Sprintf("/tmp/tetragon-%d.tar.gz", os.Getpid())

	// 优先从后台下载: {backendURL}/api/v1/dependency/download/tetragon?arch={arch}
	// 后台总是返回 is_latest=true 的版本，version 参数由后台管理
	downloaded := false
	var backendErr error
	if backendURL != "" {
		depURL := fmt.Sprintf("%s/api/v1/dependency/download/tetragon?arch=%s", strings.TrimRight(backendURL, "/"), arch)
		_, backendErr = runCommand("curl", "-sfL", depURL, "-o", tmpFile)
		if backendErr == nil {
			if info, _ := os.Stat(tmpFile); info != nil && info.Size() > 1024*1024 {
				downloaded = true
			} else {
				backendErr = fmt.Errorf("file too small or missing")
			}
		}
	} else {
		backendErr = fmt.Errorf("backend_url empty")
	}

	// Fallback: 从 GitHub 下载
	if !downloaded {
		ghURL := fmt.Sprintf("https://github.com/cilium/tetragon/releases/download/v%s/tetragon-v%s-%s.tar.gz", version, version, arch)
		if _, err := runCommand("curl", "-sfL", ghURL, "-o", tmpFile); err != nil {
			return fmt.Errorf("download failed (backend: %v, github: %w)", backendErr, err)
		}
	}
	defer os.Remove(tmpFile)

	// 检查文件大小
	info, err := os.Stat(tmpFile)
	if err != nil || info.Size() < 1024*1024 {
		return fmt.Errorf("downloaded file too small or missing")
	}

	// 解压: tar.gz 顶层目录为 tetragon-v{ver}-{arch}/，strip 1 层后直接放到 /
	// 内含 usr/local/bin/tetragon, usr/local/bin/tetra, usr/lib/systemd/system/tetragon.service 等
	if _, err := runCommand("tar", "-xzf", tmpFile, "-C", "/", "--strip-components=1"); err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}

	return nil
}

// configureTetragon 写入 Tetragon 配置
func configureTetragon() error {
	if err := os.MkdirAll("/etc/tetragon", 0755); err != nil {
		return err
	}
	return os.WriteFile("/etc/tetragon/tetragon.yaml", []byte(tetragonConfig), 0644)
}

// deployTracingPolicies 将内嵌的 TracingPolicy 写入 tetragon.tp.d 目录
func deployTracingPolicies() int {
	if err := os.MkdirAll(tetragonPolicyDir, 0755); err != nil {
		return 0
	}
	count := 0
	for name, content := range tracingPolicies {
		path := fmt.Sprintf("%s/%s", tetragonPolicyDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err == nil {
			count++
		}
	}
	return count
}

// updateTetragonPolicy 远程更新 TracingPolicy（不重新安装 Tetragon）
func (m *Manager) updateTetragonPolicy() Result {
	ver := tetragonVersion()
	if ver == "" {
		return Result{Success: false, Message: "tetragon not installed"}
	}

	deployed := deployTracingPolicies()
	if deployed == 0 {
		return Result{Success: false, Message: "failed to deploy policies"}
	}

	// 重启 Tetragon 使新策略生效
	if err := startTetragon(); err != nil {
		return Result{Success: false, Message: fmt.Sprintf("restart failed after policy update: %v", err)}
	}

	m.logger.Info("tracing policies updated", zap.Int("deployed", deployed))
	return Result{
		Success: true,
		Message: fmt.Sprintf("updated %d policies, tetragon restarted", deployed),
		Version: ver,
	}
}

// startTetragon 启动 Tetragon 服务
func startTetragon() error {
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := runCommand("systemctl", "enable", "tetragon"); err != nil {
		return err
	}
	if _, err := runCommand("systemctl", "restart", "tetragon"); err != nil {
		return err
	}
	return nil
}
