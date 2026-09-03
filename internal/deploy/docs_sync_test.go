package deploy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// 文档同步门禁。
//
// 文档腐烂不是靠自觉能防住的：这一轮清理挖出的东西——指向已删文件的链接、
// 描述早已不存在的目录结构的 README、把已完成的事写成"待办"的计划文档——
// 全都是当初写下时正确、之后代码变了而文档没跟上。
//
// 靠"记得改文档"防不住这类漂移，只有让它在构建时失败才防得住。

// trackedMarkdown 返回 git 跟踪的 markdown 文档（排除前端目录）。
//
// 只看受跟踪文件：本地草稿、插件市场缓存里的 md 不属于本仓交付物，
// 把它们纳入校验只会制造噪声，最后没人再看这个测试的输出。
func trackedMarkdown(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "*.md")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("git ls-files 不可用: %v", err)
	}
	var docs []string
	for _, line := range strings.Fields(string(out)) {
		if strings.HasPrefix(line, "web/") {
			continue
		}
		docs = append(docs, line)
	}
	return docs
}

// TestDocLinksResolve 检查受跟踪文档里指向仓库内的路径引用是否真实存在。
//
// 只校验 markdown 链接（形如 [x](path)）中带路径分隔符的那些：
// 裸文件名（`service.go`）在正文里通常是简写指代，不是可点击的路径，
// 强制它们可解析只会逼着作者写一堆冗长路径，反而更难读。
func TestDocLinksResolve(t *testing.T) {
	root := repoRootFromDeploy(t)
	docs := trackedMarkdown(t, root)

	linkRe := regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)\)`)
	var broken []string

	for _, rel := range docs {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		for _, m := range linkRe.FindAllStringSubmatch(string(data), -1) {
			target := m[1]
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
				continue
			}
			target = strings.SplitN(target, "#", 2)[0]
			if target == "" || !strings.Contains(target, "/") {
				continue // 裸文件名视为正文指代，不校验
			}
			abs := filepath.Join(root, filepath.Dir(rel), target)
			if _, err := os.Stat(abs); err == nil {
				continue
			}
			if _, err := os.Stat(filepath.Join(root, target)); err == nil {
				continue
			}
			// 指向未随仓库发布的本地文件（如 CLAUDE.md）不算失效链接：
			// 它在开发者机器上存在，只是不入库。
			if strings.HasSuffix(target, "CLAUDE.md") {
				continue
			}
			broken = append(broken, rel+" → "+target)
		}
	}

	if len(broken) > 0 {
		t.Fatalf("文档里有 %d 条链接指向不存在的路径：\n  %s\n\n"+
			"链接失效说明文档描述的结构已经变了。修链接，或者把那段描述改成现状。",
			len(broken), strings.Join(broken, "\n  "))
	}
}

// TestBaselinePolicyCountMatchesDoc 校验基线策略数量与 README 声称的一致。
//
// 策略集是对外承诺合规覆盖范围的东西。README 说 30 个而实际 12 个，
// 意味着售前材料和交付内容对不上——这种偏差没人会主动发现，
// 直到客户按文档验收。
func TestBaselinePolicyCountMatchesDoc(t *testing.T) {
	root := repoRootFromDeploy(t)
	cfgDir := filepath.Join(root, "plugins", "baseline", "config")

	var policies, rules int
	err := filepath.Walk(cfgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var doc struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return nil
		}
		policies++
		rules += len(doc.Rules)
		return nil
	})
	if err != nil {
		t.Fatalf("遍历基线策略失败: %v", err)
	}

	readme, err := os.ReadFile(filepath.Join(cfgDir, "README.md"))
	if err != nil {
		t.Fatalf("基线策略 README 缺失: %v", err)
	}

	// README 里写的是「**30 个策略，614 条规则**」这种形式。
	claimRe := regexp.MustCompile(`\*\*(\d+)\s*个策略[，,]\s*(\d+)\s*条规则\*\*`)
	m := claimRe.FindStringSubmatch(string(readme))
	if m == nil {
		t.Fatal("基线策略 README 里找不到「**N 个策略，M 条规则**」的声明，" +
			"无法校验它与实际文件是否一致")
	}
	claimPolicies, _ := strconv.Atoi(m[1])
	claimRules, _ := strconv.Atoi(m[2])

	if claimPolicies != policies || claimRules != rules {
		t.Fatalf("基线策略 README 与实际不符：\n"+
			"  README 声称: %d 个策略 / %d 条规则\n"+
			"  实际文件是: %d 个策略 / %d 条规则\n\n"+
			"策略集是对外承诺的合规覆盖范围，数字对不上意味着交付内容与文档不一致。",
			claimPolicies, claimRules, policies, rules)
	}
}

// TestClaudeMdReferencesExist 校验 CLAUDE.md 里引用的文档确实存在。
//
// CLAUDE.md 是每次会话都会被读的入口文档。它指向一份不存在的文件时，
// 读者（人或模型）会以为那里有权威说明，实际什么都没有。
func TestClaudeMdReferencesExist(t *testing.T) {
	root := repoRootFromDeploy(t)
	data, err := os.ReadFile(filepath.Join(root, "CLAUDE.md"))
	if err != nil {
		t.Skip("CLAUDE.md 不存在")
	}

	linkRe := regexp.MustCompile(`\[[^\]]*\]\((docs/[^)\s#]+)\)`)
	var missing []string
	for _, m := range linkRe.FindAllStringSubmatch(string(data), -1) {
		if _, err := os.Stat(filepath.Join(root, m[1])); err != nil {
			missing = append(missing, m[1])
		}
	}
	if len(missing) > 0 {
		t.Fatalf("CLAUDE.md 引用了不存在的文档：%s\n\n"+
			"它是每次会话的入口文档，指向空气会让人以为那里有权威说明。",
			strings.Join(missing, ", "))
	}
}

// TestArchitectureDocCoversAllServices 校验架构文档与 CLAUDE.md 覆盖了全部服务。
//
// 新增一个服务却不写进架构文档，是文档腐烂最典型的入口：服务会一直跑下去，
// 而读文档的人不知道它存在——这一轮清理前，7 个服务里入口文档只提了 2 个。
func TestArchitectureDocCoversAllServices(t *testing.T) {
	root := repoRootFromDeploy(t)

	entries, err := os.ReadDir(filepath.Join(root, "cmd", "server"))
	if err != nil {
		t.Fatalf("读取 cmd/server 失败: %v", err)
	}
	var services []string
	for _, e := range entries {
		if e.IsDir() {
			services = append(services, e.Name())
		}
	}
	if len(services) == 0 {
		t.Fatal("cmd/server 下没有服务，检查测试假设是否已失效")
	}

	for _, doc := range []string{"docs/architecture.md", "CLAUDE.md"} {
		data, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			// CLAUDE.md 是本地开发约定，不随仓库发布（见 .gitignore）。
			// 干净克隆里没有它，这里跳过而不是判失败——否则任何人 clone
			// 之后跑测试都会看到一个与自己无关的红。
			if doc == "CLAUDE.md" && os.IsNotExist(err) {
				continue
			}
			t.Fatalf("读取 %s 失败: %v", doc, err)
		}
		body := string(data)
		var missing []string
		for _, svc := range services {
			if !strings.Contains(body, svc) {
				missing = append(missing, svc)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s 没有提到这些服务：%s\n"+
				"  服务在跑而文档不提它，读文档的人就不知道它存在。",
				doc, strings.Join(missing, ", "))
		}
	}
}

// TestRoadmapExistsAndIsDated 校验路线图存在且带核实日期。
//
// 状态文档没有日期，读的人无法判断它是上周写的还是去年写的，
// 于是只能默认它是旧的——那它就等于不存在。
func TestRoadmapExistsAndIsDated(t *testing.T) {
	root := repoRootFromDeploy(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "roadmap.md"))
	if err != nil {
		t.Fatalf("docs/roadmap.md 缺失：交付状态需要一个仓库内的权威来源，"+
			"放在 gitignore 目录里等于没有: %v", err)
	}
	if !regexp.MustCompile(`最后核实：\d{4}-\d{2}-\d{2}`).Match(data) {
		t.Fatal("docs/roadmap.md 缺少「最后核实：YYYY-MM-DD」。" +
			"状态文档没有日期，读的人无法判断它还作不作数。")
	}
}

// TestConfigKeysDocumented 校验 server.yaml 模板里的配置节都在配置文档里出现过。
//
// 只校验顶层节：逐个字段校验会把测试变成配置文件的副本，
// 改一个字段要改两处，最后大家会把测试删掉而不是维护它。
func TestConfigKeysDocumented(t *testing.T) {
	root := repoRootFromDeploy(t)
	tpl, err := os.ReadFile(filepath.Join(root, "deploy", "config", "server.yaml.tpl"))
	if err != nil {
		t.Skipf("读取 server.yaml.tpl 失败: %v", err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("读取 configuration.md 失败: %v", err)
	}
	docBody := string(doc)

	sectionRe := regexp.MustCompile(`(?m)^([a-z][a-z0-9_]*):`)
	seen := map[string]bool{}
	var missing []string
	for _, m := range sectionRe.FindAllStringSubmatch(string(tpl), -1) {
		key := m[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		if !strings.Contains(docBody, key) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("配置模板里有这些顶层配置节，但 docs/configuration.md 从未提及：%s\n"+
			"  没写进文档的配置项，部署时只能靠读模板猜。",
			strings.Join(missing, ", "))
	}
}

// TestRoadmapNumbersMatchReality 校验路线图里的规模数字与代码实际一致。
//
// 状态文档里的数字是最容易悄悄过期的东西：加一个服务、接一个 Stage、
// 加一份基线策略，代码里改了，文档里那个数字不会自己变。
// 而读文档的人拿它当事实——对外报「30 个基线策略」时尤其如此。
//
// 只校验能从代码可靠数出来的量。像「已上生产的能力」这种需要人判断的，
// 无法自动核对，只能靠 §八 的维护约定。
func TestRoadmapNumbersMatchReality(t *testing.T) {
	root := repoRootFromDeploy(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "roadmap.md"))
	if err != nil {
		t.Fatalf("读取 roadmap.md 失败: %v", err)
	}
	body := string(data)

	// --- 服务数 ---
	entries, err := os.ReadDir(filepath.Join(root, "cmd", "server"))
	if err != nil {
		t.Fatalf("读取 cmd/server 失败: %v", err)
	}
	services := 0
	for _, e := range entries {
		if e.IsDir() {
			services++
		}
	}
	assertRoadmapNumber(t, body, `后端服务 \| (\d+)`, services, "后端服务数")

	// --- 检测能力：总数 / 已接线 / 未接线 ---
	capSrc, err := os.ReadFile(filepath.Join(root,
		"internal", "server", "engine", "capability.go"))
	if err != nil {
		t.Fatalf("读取 capability.go 失败: %v", err)
	}
	capRe := regexp.MustCompile(`\{Name: "[a-z_0-9]+",\s*Constructor: "\w+",\s*Status: (\w+)`)
	var total, active, starved, unwired int
	for _, m := range capRe.FindAllStringSubmatch(string(capSrc), -1) {
		total++
		switch m[1] {
		case "StatusActive":
			active++
		case "StatusStarved":
			starved++
		case "StatusUnwired":
			unwired++
		}
	}
	assertRoadmapNumber(t, body, `(\d+) 定义`, total, "检测能力总数")
	assertRoadmapNumber(t, body, `\*\*(\d+) 已接线`, active, "已接线能力数")
	// starved 必须单独写出来：它既不是"能用"也不是"没接"，
	// 混进任何一档都会让这份对外规模说明失真。
	assertRoadmapNumber(t, body, `(\d+) 缺输入`, starved, "缺输入能力数")
	assertRoadmapNumber(t, body, `(\d+) 未接线`, unwired, "未接线能力数")

	// --- 插件数 ---
	pluginEntries, err := os.ReadDir(filepath.Join(root, "plugins"))
	if err != nil {
		t.Fatalf("读取 plugins 失败: %v", err)
	}
	plugins := 0
	for _, e := range pluginEntries {
		if e.IsDir() {
			plugins++
		}
	}
	assertRoadmapNumber(t, body, `Agent 插件 \| (\d+)`, plugins, "插件数")
}

// assertRoadmapNumber 比对路线图里的一处数字断言。
func assertRoadmapNumber(t *testing.T, body, pattern string, want int, what string) {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if m == nil {
		t.Errorf("roadmap.md 里找不到「%s」的数字断言（正则 %s）。"+
			"删掉断言不等于文档正确——它只是变得无法核对。", what, pattern)
		return
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Errorf("「%s」的数字无法解析: %q", what, m[1])
		return
	}
	if got != want {
		t.Errorf("roadmap.md 的「%s」写的是 %d，代码里实际是 %d。\n"+
			"  改了代码就要改这个数字——它是对外说明规模的依据。", what, got, want)
	}
}
