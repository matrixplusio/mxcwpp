package cluster

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type DeployOptions struct {
	ConfigDir       string
	SkipInstall     bool
	SkipHealthCheck bool
}

type deployedNode struct {
	Node          Node
	Assignment    RoleAssignment
	BundleDir     string
	RemoteRelease string
	RemoteCurrent string
}

// DeployCluster 将渲染好的 bundle 通过 SSH 下发到远端节点并启动服务。
func DeployCluster(cfg *Config, render *RenderResult, opts DeployOptions) error {
	releaseID := fmt.Sprintf("%s-%s", cfg.Release.Version, time.Now().Format("20060102-150405"))
	nodes := make([]deployedNode, 0, len(render.NodeBundles))
	for _, bundle := range render.NodeBundles {
		nodes = append(nodes, deployedNode{
			Node:          bundle.Node,
			Assignment:    bundle.Assignment,
			BundleDir:     bundle.BundleDir,
			RemoteRelease: filepath.ToSlash(filepath.Join(bundle.Node.InstallDir, "releases", releaseID)),
			RemoteCurrent: filepath.ToSlash(filepath.Join(bundle.Node.InstallDir, "current")),
		})
	}

	fmt.Println("[1/5] 准备远端节点...")
	for _, item := range nodes {
		fmt.Printf("  -> %s (%s)\n", item.Node.Name, item.Node.Host)
		if err := prepareRemoteNode(cfg, item, opts); err != nil {
			return err
		}
	}

	fmt.Println("[2/5] 启动 Kafka...")
	for _, item := range filterNodes(nodes, func(n deployedNode) bool { return n.Node.HasRole(RoleKafka) }) {
		fmt.Printf("  -> %s (%s)\n", item.Node.Name, item.Node.Host)
		if err := runRemote(item.Node, opts.ConfigDir, remoteUpKafka(item)); err != nil {
			return fmt.Errorf("启动 kafka 节点 %s 失败: %w", item.Node.Name, err)
		}
	}

	fmt.Println("[3/5] 启动 Storage (MySQL/Redis/ClickHouse)...")
	for _, item := range filterNodes(nodes, func(n deployedNode) bool { return n.Node.HasRole(RoleStorage) }) {
		fmt.Printf("  -> %s (%s)\n", item.Node.Name, item.Node.Host)
		if err := runRemote(item.Node, opts.ConfigDir, remoteUpStorage(item)); err != nil {
			return fmt.Errorf("启动 storage 节点 %s 失败: %w", item.Node.Name, err)
		}
	}

	fmt.Println("[4/5] 启动 Control (Manager/AgentCenter/Consumer/UI)...")
	for _, item := range filterNodes(nodes, func(n deployedNode) bool { return n.Node.HasRole(RoleControl) }) {
		fmt.Printf("  -> %s (%s)\n", item.Node.Name, item.Node.Host)
		if err := runRemote(item.Node, opts.ConfigDir, remoteUpControl(item)); err != nil {
			return fmt.Errorf("启动 control 节点 %s 失败: %w", item.Node.Name, err)
		}
	}

	if opts.SkipHealthCheck {
		return nil
	}
	fmt.Println("[5/5] 健康检查...")
	for _, item := range nodes {
		fmt.Printf("  -> %s (%s)\n", item.Node.Name, item.Node.Host)
		if err := runRemote(item.Node, opts.ConfigDir, remoteHealthCheck(cfg, item)); err != nil {
			return fmt.Errorf("节点 %s 健康检查失败: %w", item.Node.Name, err)
		}
	}
	return nil
}

func prepareRemoteNode(cfg *Config, node deployedNode, opts DeployOptions) error {
	// 创建 release 目录并确保 SSH 用户有写入权限（scp 不能用 sudo）
	fmt.Printf("    创建远端目录 %s\n", node.RemoteRelease)
	mkdirCmd := fmt.Sprintf("mkdir -p %s", shQuote(node.RemoteRelease))
	if node.Node.SSHUser != "root" {
		mkdirCmd += fmt.Sprintf(" && chown -R %s:%s %s", shQuote(node.Node.SSHUser), shQuote(node.Node.SSHUser), shQuote(node.Node.InstallDir))
	}
	if err := runRemote(node.Node, opts.ConfigDir, sudoWrap(node.Node, mkdirCmd)); err != nil {
		return fmt.Errorf("创建远端目录失败(%s): %w", node.Node.Name, err)
	}
	fmt.Printf("    上传 bundle...\n")
	if err := copyBundle(node.Node, opts.ConfigDir, node.BundleDir, node.RemoteRelease); err != nil {
		return fmt.Errorf("上传 bundle 失败(%s): %w", node.Node.Name, err)
	}
	fmt.Printf("    切换 current 软链\n")
	if err := runRemote(node.Node, opts.ConfigDir, sudoWrap(node.Node, fmt.Sprintf("mkdir -p %s && ln -sfn %s %s", shQuote(node.Node.InstallDir), shQuote(node.RemoteRelease), shQuote(node.RemoteCurrent)))); err != nil {
		return fmt.Errorf("切换 current 软链失败(%s): %w", node.Node.Name, err)
	}
	if !opts.SkipInstall {
		fmt.Printf("    安装远端依赖...\n")
		if err := runRemote(node.Node, opts.ConfigDir, sudoWrap(node.Node, fmt.Sprintf("bash %s/scripts/install-deps.sh", shQuote(node.RemoteCurrent)))); err != nil {
			return fmt.Errorf("安装依赖失败(%s): %w", node.Node.Name, err)
		}
	}
	if cfg.Registry.Domain != "" && cfg.Registry.Username != "" && cfg.Registry.Password != "" {
		fmt.Printf("    Docker login %s\n", cfg.Registry.Domain)
		cmd := fmt.Sprintf("docker login %s -u %s -p %s", shQuote(cfg.Registry.Domain), shQuote(cfg.Registry.Username), shQuote(cfg.Registry.Password))
		if err := runRemote(node.Node, opts.ConfigDir, sudoWrap(node.Node, cmd)); err != nil {
			return fmt.Errorf("docker login 失败(%s): %w", node.Node.Name, err)
		}
	}
	return nil
}

func remoteUpKafka(node deployedNode) string {
	compose := filepath.ToSlash(filepath.Join(node.RemoteCurrent, "compose", "docker-compose.kafka.yml"))
	return sudoWrap(node.Node, fmt.Sprintf("docker compose -f %s up -d --remove-orphans", shQuote(compose)))
}

func remoteUpStorage(node deployedNode) string {
	compose := filepath.ToSlash(filepath.Join(node.RemoteCurrent, "compose", "docker-compose.storage.yml"))
	return sudoWrap(node.Node, fmt.Sprintf("docker compose -f %s up -d --remove-orphans", shQuote(compose)))
}

func remoteUpControl(node deployedNode) string {
	compose := filepath.ToSlash(filepath.Join(node.RemoteCurrent, "compose", "docker-compose.control.yml"))
	return sudoWrap(node.Node, fmt.Sprintf("docker compose -f %s up -d --remove-orphans", shQuote(compose)))
}

func remoteHealthCheck(cfg *Config, node deployedNode) string {
	commands := make([]string, 0, 3)
	if node.Node.HasRole(RoleKafka) {
		compose := filepath.ToSlash(filepath.Join(node.RemoteCurrent, "compose", "docker-compose.kafka.yml"))
		commands = append(commands, sudoWrap(node.Node, fmt.Sprintf("docker compose -f %s ps", shQuote(compose))))
	}
	if node.Node.HasRole(RoleStorage) {
		compose := filepath.ToSlash(filepath.Join(node.RemoteCurrent, "compose", "docker-compose.storage.yml"))
		commands = append(commands, sudoWrap(node.Node, fmt.Sprintf("docker compose -f %s ps", shQuote(compose))))
	}
	if node.Node.HasRole(RoleControl) {
		compose := filepath.ToSlash(filepath.Join(node.RemoteCurrent, "compose", "docker-compose.control.yml"))
		commands = append(commands,
			sudoWrap(node.Node, fmt.Sprintf("docker compose -f %s ps", shQuote(compose))),
			fmt.Sprintf("curl -fsS http://127.0.0.1:%d/health >/dev/null", cfg.App.HTTPPort),
		)
	}
	return strings.Join(commands, " && ")
}

func filterNodes(nodes []deployedNode, fn func(deployedNode) bool) []deployedNode {
	filtered := make([]deployedNode, 0, len(nodes))
	for _, item := range nodes {
		if fn(item) {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Node.Name < filtered[j].Node.Name })
	return filtered
}

func copyBundle(node Node, configDir, localDir, remoteDir string) error {
	target := fmt.Sprintf("%s:%s/", sshTarget(node), remoteDir)
	args := scpBaseArgs(node, configDir)
	args = append(args, "-r", filepath.Clean(localDir)+string(filepath.Separator)+".", target)
	cmd := exec.Command("scp", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp 执行失败: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runRemote(node Node, configDir, remoteCmd string) error {
	args := sshBaseArgs(node, configDir)
	args = append(args, sshTarget(node), remoteCmd)
	cmd := exec.Command("ssh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh 执行失败: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func sshBaseArgs(node Node, configDir string) []string {
	args := []string{"-p", fmt.Sprintf("%d", node.SSHPort), "-o", "StrictHostKeyChecking=accept-new"}
	if node.SSHKeyPath != "" {
		resolved, err := expandPath(node.SSHKeyPath, configDir)
		if err == nil && resolved != "" {
			args = append(args, "-i", resolved)
		}
	}
	return args
}

// scpBaseArgs 与 sshBaseArgs 类似，但 scp 用大写 -P 指定端口。
func scpBaseArgs(node Node, configDir string) []string {
	args := []string{"-P", fmt.Sprintf("%d", node.SSHPort), "-o", "StrictHostKeyChecking=accept-new"}
	if node.SSHKeyPath != "" {
		resolved, err := expandPath(node.SSHKeyPath, configDir)
		if err == nil && resolved != "" {
			args = append(args, "-i", resolved)
		}
	}
	return args
}

func sshTarget(node Node) string {
	return fmt.Sprintf("%s@%s", node.SSHUser, node.Host)
}

func shQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// sudoWrap 在非 root 用户时用 sudo sh -c 包裹整个命令。
func sudoWrap(node Node, cmd string) string {
	if node.SSHUser == "root" {
		return cmd
	}
	return fmt.Sprintf("sudo sh -c %s", shQuote(cmd))
}
