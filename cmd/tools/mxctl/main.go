package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/imkerbos/mxsec-platform/internal/deploy/cluster"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "check", "validate":
		if err := runCheck(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
			os.Exit(1)
		}
	case "preflight":
		if err := runPreflight(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
			os.Exit(1)
		}
	case "render":
		if err := runRender(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
			os.Exit(1)
		}
	case "deploy":
		if err := runDeploy(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("f", "deploy/prod/cluster.example.yaml", "cluster.yaml 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := cluster.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	printSummary(cfg)
	fmt.Println("校验通过")
	return nil
}

func runPreflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	configPath := fs.String("f", "deploy/prod/cluster.example.yaml", "cluster.yaml 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, _, _, err := loadContext(*configPath, "")
	if err != nil {
		return err
	}
	printSummary(cfg)
	fmt.Println("开始预部署检查...")
	if err := cluster.PreflightCluster(cfg, cluster.PreflightOptions{
		ConfigDir: filepath.Dir(mustAbs(*configPath)),
	}); err != nil {
		return err
	}
	fmt.Println("预部署检查通过")
	return nil
}

func runRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	configPath := fs.String("f", "deploy/prod/cluster.example.yaml", "cluster.yaml 路径")
	outputDir := fs.String("o", "", "渲染输出根目录，默认 deploy/prod/out")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, repoRoot, outRoot, err := loadContext(*configPath, *outputDir)
	if err != nil {
		return err
	}
	result, err := cluster.RenderCluster(cfg, cluster.RenderOptions{
		ConfigPath: *configPath,
		OutputDir:  outRoot,
		RepoRoot:   repoRoot,
		Clean:      true,
	})
	if err != nil {
		return err
	}
	printSummary(cfg)
	fmt.Printf("渲染完成: %s\n", result.ClusterDir)
	for _, bundle := range result.NodeBundles {
		fmt.Printf("- %s -> %s\n", bundle.Node.Name, bundle.BundleDir)
	}
	return nil
}

func runDeploy(args []string) error {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	configPath := fs.String("f", "deploy/prod/cluster.example.yaml", "cluster.yaml 路径")
	outputDir := fs.String("o", "", "渲染输出根目录，默认 deploy/prod/out")
	skipInstall := fs.Bool("skip-install", false, "跳过远端依赖安装")
	skipHealthCheck := fs.Bool("skip-healthcheck", false, "跳过部署后的健康检查")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, repoRoot, outRoot, err := loadContext(*configPath, *outputDir)
	if err != nil {
		return err
	}
	result, err := cluster.RenderCluster(cfg, cluster.RenderOptions{
		ConfigPath: *configPath,
		OutputDir:  outRoot,
		RepoRoot:   repoRoot,
		Clean:      true,
	})
	if err != nil {
		return err
	}
	printSummary(cfg)
	fmt.Printf("开始部署，bundle: %s\n", result.ClusterDir)
	if err := cluster.DeployCluster(cfg, result, cluster.DeployOptions{
		ConfigDir:       filepath.Dir(mustAbs(*configPath)),
		SkipInstall:     *skipInstall,
		SkipHealthCheck: *skipHealthCheck,
	}); err != nil {
		return err
	}
	fmt.Println("部署完成")
	return nil
}

func loadContext(configPath, outputDir string) (*cluster.Config, string, string, error) {
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("解析配置路径失败: %w", err)
	}
	cfg, err := cluster.LoadConfig(absConfig)
	if err != nil {
		return nil, "", "", err
	}
	repoRoot, err := cluster.FindRepoRoot(filepath.Dir(absConfig))
	if err != nil {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return nil, "", "", err
		}
		repoRoot, err = cluster.FindRepoRoot(cwd)
		if err != nil {
			return nil, "", "", err
		}
	}
	if outputDir == "" {
		outputDir = filepath.Join(repoRoot, "deploy", "prod", "out")
	}
	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, "", "", fmt.Errorf("解析输出目录失败: %w", err)
	}
	return cfg, repoRoot, absOutput, nil
}

func printSummary(cfg *cluster.Config) {
	controlNodes := cfg.ControlNodes()
	storageNode, _ := cfg.StorageNode()
	kafkaNode, _ := cfg.KafkaNode()
	assignments := cfg.RoleAssignments()

	fmt.Printf("集群: %s (%s)\n", cfg.Metadata.Name, cfg.Metadata.Environment)
	fmt.Printf("版本: %s\n", cfg.Release.Version)
	fmt.Printf("入口: UI=%s://%s%s, gRPC=%s:%d\n",
		cfg.Network.UI.Scheme,
		cfg.Network.UI.Host,
		portSuffix(cfg.Network.UI.Scheme, cfg.Network.UI.Port),
		cfg.Network.GRPC.Host,
		cfg.Network.GRPC.Port,
	)
	fmt.Printf("控制面节点: %s\n", joinNodeNames(controlNodes))
	fmt.Printf("存储节点: %s, Kafka 节点: %s\n", storageNode.Name, kafkaNode.Name)
	for _, item := range assignments {
		if !item.Node.HasRole(cluster.RoleControl) {
			continue
		}
		fmt.Printf("- %s manager=%d agentcenter=%d consumer=%d\n", item.Node.Name, item.ManagerReplicas, item.AgentCenterReplicas, item.ConsumerReplicas)
	}
}

func portSuffix(scheme string, port int) string {
	if port == 0 {
		return ""
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return ""
	}
	return fmt.Sprintf(":%d", port)
}

func joinNodeNames(nodes []cluster.Node) string {
	parts := make([]string, 0, len(nodes))
	for _, node := range nodes {
		parts = append(parts, node.Name)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func usage() {
	fmt.Print(`mxctl - MxSec 生产集群部署工具

用法:
  go build -o ./bin/mxctl ./cmd/tools/mxctl
  ./bin/mxctl check     -f deploy/prod/cluster.example.yaml
  ./bin/mxctl preflight -f deploy/prod/cluster.example.yaml
  ./bin/mxctl render    -f deploy/prod/cluster.example.yaml
  ./bin/mxctl deploy    -f deploy/prod/cluster.example.yaml
`)
}
