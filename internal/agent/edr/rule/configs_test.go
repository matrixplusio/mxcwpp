package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// ruleConfigDir 定位仓库内的真实规则目录。
func ruleConfigDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		candidate := filepath.Join(dir, "configs", "agent-rules")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("未找到 configs/agent-rules，跳过")
		}
		dir = parent
	}
}

// TestShippedRulesAllValid 随包发布的规则必须全部通过载入期校验。
//
// 载入是 Agent 启动路径：一条规则写坏，整个规则集加载失败，主机上的
// EDR 检测直接哑掉，而且是静默的——没有任何东西会在 CI 里替你发现。
// 这条测试就是那个东西。
func TestShippedRulesAllValid(t *testing.T) {
	dir := ruleConfigDir(t)
	m := NewManager(zap.NewNop(), dir)
	if err := m.Load(); err != nil {
		t.Fatalf("载入 %s 失败: %v", dir, err)
	}
}

// TestNetworkRulesExcludePrivateDestinations 网络端口类规则必须排除私网目的地址。
//
// 回归 2026-08 事故：c2_high_risk_port / cryptominer_pool_port / c2_tor_proxy
// 三条规则只匹配目的端口，不看目的地址，把内网正常东西向调用全判成 C2。
// 这类规则的命中全部落在内网、外网零命中，并把 storyline_events 撑到
// 亿级行、数百 GB，写满存储节点后级联拖垮整个平台。
//
// 判据：凡是按"目的端口在清单内"下结论的网络规则，必须同时约束目的地址范围。
func TestNetworkRulesExcludePrivateDestinations(t *testing.T) {
	dir := ruleConfigDir(t)
	m := NewManager(zap.NewNop(), dir)
	if err := m.Load(); err != nil {
		t.Fatalf("载入规则失败: %v", err)
	}

	for _, r := range m.Rules().All {
		if !r.Agent.Enabled || r.Category != "network" {
			continue
		}
		portOnly := false
		hasAddrScope := false
		for _, c := range r.Agent.Match.Conditions {
			if c.Field == "remote_port" && c.Op == OpIn {
				portOnly = true
			}
			if c.Field == "remote_addr" && (c.Op == OpNotInCIDR || c.Op == OpInCIDR) {
				hasAddrScope = true
			}
		}
		if portOnly && !hasAddrScope {
			t.Errorf("规则 %s (%s) 仅按目的端口判定且未约束目的地址范围。\n"+
				"  内网大量业务服务复用所谓“C2/矿池端口”，只看端口必然全量误报。\n"+
				"  修法：加一条 remote_addr not_in_cidr 私网网段。",
				r.ID, r.Name)
		}
	}
}

// TestIncidentRulesHaveCIDRGuard 三条肇事规则逐条点名核对，防止被回退。
func TestIncidentRulesHaveCIDRGuard(t *testing.T) {
	dir := ruleConfigDir(t)
	m := NewManager(zap.NewNop(), dir)
	if err := m.Load(); err != nil {
		t.Fatalf("载入规则失败: %v", err)
	}

	// 事故当事规则 → 内网误报样本
	want := map[string]string{
		"c2_high_risk_port":     "10.0.0.11", // 内网业务服务
		"cryptominer_pool_port": "10.0.0.21", // 内网业务服务
		"c2_tor_proxy":          "10.0.0.31", // 内网数据库服务
	}

	seen := map[string]bool{}
	for _, r := range m.Rules().All {
		internalAddr, ok := want[r.Name]
		if !ok {
			continue
		}
		seen[r.Name] = true

		var guard *Condition
		for i := range r.Agent.Match.Conditions {
			c := &r.Agent.Match.Conditions[i]
			if c.Field == "remote_addr" && c.Op == OpNotInCIDR {
				guard = c
				break
			}
		}
		if guard == nil {
			t.Errorf("规则 %s 缺少 remote_addr not_in_cidr 私网排除——事故会重演", r.Name)
			continue
		}
		if guard.Evaluate(internalAddr) {
			t.Errorf("规则 %s 对内网地址 %s 仍然命中，私网网段列表覆盖不全", r.Name, internalAddr)
		}
		if !guard.Evaluate("203.0.113.10") {
			t.Errorf("规则 %s 对公网地址不命中，检出能力被改没了", r.Name)
		}
	}

	for name := range want {
		if !seen[name] {
			t.Errorf("未在 configs/agent-rules 找到规则 %s；若已改名或下线，请同步更新本测试", name)
		}
	}
}

// TestRuleFilesUseTabFreeYAML 规则文件不得含 Tab —— YAML 规范不允许，
// 但部分编辑器会静默插入，载入失败时的报错又指不到具体位置。
func TestRuleFilesUseTabFreeYAML(t *testing.T) {
	dir := ruleConfigDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取规则目录失败: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", e.Name(), err)
		}
		if strings.Contains(string(data), "\t") {
			t.Errorf("%s 含 Tab 字符，YAML 不允许", e.Name())
		}
	}
}
