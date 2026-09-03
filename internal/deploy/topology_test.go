package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// officialCompose 是唯一官方单机部署拓扑。
const officialCompose = "deploy/docker-compose.yml"

var serviceKeyRe = regexp.MustCompile(`(?m)^  ([a-z0-9][a-z0-9_-]*):`)

func repoRootFromDeploy(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// composeServices 解析 compose 里定义的服务名。
func composeServices(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	// 只取 services: 段，避免把 networks/volumes 的键当服务。
	src := string(data)
	start := strings.Index(src, "\nservices:")
	if start < 0 {
		t.Fatalf("%s 缺少 services 段", path)
	}
	rest := src[start+len("\nservices:"):]
	if end := regexp.MustCompile(`(?m)^(networks|volumes):`).FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}
	out := map[string]bool{}
	for _, m := range serviceKeyRe.FindAllStringSubmatch(rest, -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatalf("%s 未解析出任何服务——格式已变，测试失效", path)
	}
	return out
}

// TestOfficialTopology_CoversEveryServiceBinary 每个服务二进制都必须出现在官方拓扑里。
//
// 此前 deploy.sh 一键部署用的 docker-compose.yml 缺 engine / vulnsync / llmproxy：
// 装出来的系统没有检测引擎（不产告警）、没有漏洞同步（库不更新）。装得起来、
// 界面能开，核心能力却都不在——这正是"看起来功能都在，实际大量能力从未运行过"。
//
// 本闸门把 cmd/server/* 与官方拓扑绑定：新增微服务未加进部署即失败。
func TestOfficialTopology_CoversEveryServiceBinary(t *testing.T) {
	root := repoRootFromDeploy(t)
	services := composeServices(t, filepath.Join(root, officialCompose))

	entries, err := os.ReadDir(filepath.Join(root, "cmd", "server"))
	if err != nil {
		t.Fatalf("读取 cmd/server 失败: %v", err)
	}
	// scanner 是 agent 侧插件进程，不在服务端拓扑内。
	notServerSide := map[string]bool{"scanner": true}

	for _, e := range entries {
		if !e.IsDir() || notServerSide[e.Name()] {
			continue
		}
		if !services[e.Name()] {
			t.Errorf("服务 %s 有二进制入口 cmd/server/%s，但未出现在 %s\n"+
				"  一键部署装不出该服务，其能力在客户环境里从未运行。",
				e.Name(), e.Name(), officialCompose)
		}
	}
}

// TestOfficialTopology_HasSupportingServices 报告渲染等支撑服务不得缺失。
//
// 缺 gotenberg 时报告导出得到的是损坏的 .pdf 而非明确报错，属静默失败。
func TestOfficialTopology_HasSupportingServices(t *testing.T) {
	root := repoRootFromDeploy(t)
	services := composeServices(t, filepath.Join(root, officialCompose))

	required := map[string]string{
		"mysql":      "主存储",
		"redis":      "缓存与限流/黑名单依赖",
		"clickhouse": "时序事件存储",
		"ui":         "控制台",
		"gotenberg":  "报告 PDF 渲染，缺失时导出损坏文件而非报错",
	}
	for name, why := range required {
		if !services[name] {
			t.Errorf("官方拓扑缺少 %s（%s）", name, why)
		}
	}
	// Kafka 至少要有一个 broker，否则整条数据管道不存在。
	hasKafka := false
	for name := range services {
		if strings.HasPrefix(name, "kafka") {
			hasKafka = true
			break
		}
	}
	if !hasKafka {
		t.Error("官方拓扑缺少 Kafka，数据管道不存在")
	}
}

// TestSingleOfficialTopology 官方单机拓扑只能有一份。
//
// 曾同时存在 docker-compose.yml、docker-compose.v2.yml 和打包脚本内嵌生成的第三份，
// 三者服务集互不相同，客户实际拿到哪一份取决于走了哪条路径。
func TestSingleOfficialTopology(t *testing.T) {
	root := repoRootFromDeploy(t)
	if _, err := os.Stat(filepath.Join(root, "deploy", "docker-compose.v2.yml")); err == nil {
		t.Error("docker-compose.v2.yml 已在拓扑收敛中删除，不应重新出现")
	}

	// 打包脚本必须复用官方拓扑，而不是另外生成一份。
	data, err := os.ReadFile(filepath.Join(root, "scripts", "package-deploy.sh"))
	if err != nil {
		t.Skipf("读取打包脚本失败: %v", err)
	}
	script := string(data)
	if !strings.Contains(script, `cp "$PROJECT_ROOT/deploy/docker-compose.yml"`) {
		t.Error("打包脚本未复用官方拓扑；离线包与官方部署的服务集会再次分叉")
	}
	if strings.Contains(script, `cat > "$PACKAGE_DIR/docker-compose.yml"`) {
		t.Error("打包脚本仍在内嵌生成 compose，这正是分叉的来源")
	}
}
