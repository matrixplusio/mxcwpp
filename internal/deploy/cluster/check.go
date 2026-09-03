package cluster

import (
	"fmt"
	"os/exec"
	"strings"
)

type PreflightOptions struct {
	ConfigDir string
}

// CheckLocalEnvironment 检查本地执行 mxctl 所需的命令是否存在。
func CheckLocalEnvironment() error {
	required := []string{"ssh", "scp"}
	for _, name := range required {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("本地缺少命令 %s", name)
		}
	}
	return nil
}

// PreflightCluster 在正式部署前检查本地环境、SSH 连通性与远端基础条件。
func PreflightCluster(cfg *Config, opts PreflightOptions) error {
	if err := CheckLocalEnvironment(); err != nil {
		return err
	}
	for _, node := range cfg.Nodes {
		if err := runRemote(node, opts.ConfigDir, remotePreflightCommand(node)); err != nil {
			return fmt.Errorf("节点 %s 预检查失败: %w", node.Name, err)
		}
	}
	return nil
}

func remotePreflightCommand(node Node) string {
	mkdirCmd := fmt.Sprintf("mkdir -p %s %s", shQuote(node.InstallDir), shQuote(node.DataRoot))
	if node.SSHUser != "root" {
		mkdirCmd += fmt.Sprintf(" && chown -R %s:%s %s %s", shQuote(node.SSHUser), shQuote(node.SSHUser), shQuote(node.InstallDir), shQuote(node.DataRoot))
	}
	parts := []string{
		"set -e",
		"test -f /etc/os-release",
		`. /etc/os-release; case "$ID" in ubuntu|debian|rocky|rhel|centos|almalinux|ol) ;; *) echo "unsupported_os=$ID" >&2; exit 21 ;; esac`,
		"command -v bash >/dev/null 2>&1",
		sudoWrap(node, mkdirCmd),
		fmt.Sprintf("echo preflight-ok node=%s", shQuote(node.Name)),
	}
	if node.SSHUser != "root" {
		parts = append(parts, "command -v sudo >/dev/null 2>&1", "sudo -n true >/dev/null 2>&1")
	}
	return strings.Join(parts, " && ")
}
