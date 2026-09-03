package rule

import "testing"

// privateCIDRs 是内网排除的标准网段集，与 configs/agent-rules 里网络类规则保持一致。
var privateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"127.0.0.0/8", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

func newCIDRCond(t *testing.T, op Operator) *Condition {
	t.Helper()
	c := &Condition{Field: "remote_addr", Op: op, Values: privateCIDRs}
	if err := c.validate("TEST-001", 0); err != nil {
		t.Fatalf("validate 失败: %v", err)
	}
	return c
}

// TestNotInCIDR_ProdFalsePositiveSamples 用 2026-08 事故的真实命中样本回归。
//
// 这批地址来自 prod storyline_events：三条端口类规则（c2_high_risk_port /
// cryptominer_pool_port / c2_tor_proxy）的命中全部落在内网目的地址、外网零命中。
// 端口本身确实在"C2 端口清单"里，但对端全是内网业务服务：
// 这些端口号在内网被业务与运维组件普遍占用。加上 not_in_cidr 私网排除后，这些必须一条都不再命中。
func TestNotInCIDR_ProdFalsePositiveSamples(t *testing.T) {
	c := newCIDRCond(t, OpNotInCIDR)

	samples := []struct{ addr, what string }{
		{"10.0.0.11", "内网业务服务"},
		{"10.0.0.12", "内网业务服务"},
		{"10.0.0.21", "内网业务服务"},
		{"10.0.0.31", "内网数据库服务"},
		{"10.0.0.16", "内网业务服务"},
		{"10.0.0.41", "内网业务服务"},
		{"192.168.1.10", "私网 B 段"},
		{"172.16.5.8", "私网 C 段"},
		{"127.0.0.1", "本机回环"},
		{"169.254.169.254", "云元数据服务"},
	}
	for _, s := range samples {
		if c.Evaluate(s.addr) {
			t.Errorf("%s (%s) 是内网地址，not_in_cidr 不应命中——这正是把 storyline_events 撑到数百 GB 的误报", s.addr, s.what)
		}
	}
}

// TestNotInCIDR_RealExternalStillDetected 检出能力不能被削弱：
// 真实 C2 必然打外网，公网地址必须照常命中。
func TestNotInCIDR_RealExternalStillDetected(t *testing.T) {
	c := newCIDRCond(t, OpNotInCIDR)

	samples := []struct{ addr, what string }{
		{"203.0.113.10", "微步确认恶意，2026-08 扫描 7 台主机"},
		{"203.0.113.11", "端口扫描源，平台曾漏报"},
		{"203.0.113.20", "SSH 爆破源 /24 段成员"},
		{"8.8.8.8", "公网"},
		{"2001:db8::1", "公网 IPv6"},
	}
	for _, s := range samples {
		if !c.Evaluate(s.addr) {
			t.Errorf("%s (%s) 是公网地址，not_in_cidr 必须命中，否则真实 C2 检不出来", s.addr, s.what)
		}
	}
}

// TestNotInCIDR_UnparsableAddrDoesNotMatch 地址采不到时不得命中。
//
// 网络事件的 remote_addr 并非总有值。若"解析不出就算外网"，
// 所有缺字段事件都会变成告警——那就是用一种全量误报换掉另一种。
func TestNotInCIDR_UnparsableAddrDoesNotMatch(t *testing.T) {
	c := newCIDRCond(t, OpNotInCIDR)

	for _, v := range []string{"", "unknown", "not-an-ip", "10.170", "999.1.1.1"} {
		if c.Evaluate(v) {
			t.Errorf("remote_addr=%q 无法解析为 IP，不应命中", v)
		}
	}
}

// TestInCIDR_Complements in_cidr 是 not_in_cidr 的补集，且同样对非法值返回 false。
func TestInCIDR_Complements(t *testing.T) {
	c := newCIDRCond(t, OpInCIDR)

	if !c.Evaluate("10.0.0.11") {
		t.Error("内网地址 in_cidr 应命中")
	}
	if c.Evaluate("203.0.113.10") {
		t.Error("公网地址 in_cidr 不应命中")
	}
	if c.Evaluate("not-an-ip") {
		t.Error("非法地址 in_cidr 不应命中")
	}
}

// TestCIDRValidation 载入期就必须拒绝坏配置，而不是运行时静默失效。
func TestCIDRValidation(t *testing.T) {
	t.Run("空 values 被拒", func(t *testing.T) {
		c := &Condition{Field: "remote_addr", Op: OpNotInCIDR}
		if err := c.validate("TEST-002", 0); err == nil {
			t.Error("values 为空应报错，否则规则会静默匹配不到任何网段")
		}
	})

	t.Run("非法 CIDR 被拒", func(t *testing.T) {
		c := &Condition{Field: "remote_addr", Op: OpNotInCIDR, Values: []string{"10.0.0.0/8", "10.0.0.1"}}
		if err := c.validate("TEST-003", 0); err == nil {
			t.Error("裸 IP 不是 CIDR，应在载入期报错")
		}
	})

	t.Run("代价排序低于正则", func(t *testing.T) {
		c := newCIDRCond(t, OpNotInCIDR)
		if c.cost >= operatorCost[OpRegex] {
			t.Errorf("CIDR 判断代价 %d 应低于正则 %d，否则条件排序会把它排到最后", c.cost, operatorCost[OpRegex])
		}
		if c.cost <= operatorCost[OpEquals] {
			t.Errorf("CIDR 判断代价 %d 应高于等值比较 %d", c.cost, operatorCost[OpEquals])
		}
	})
}

// TestNotInCIDR_FullRuleEndToEnd 端到端：端口条件 + 内网排除 组合成 AND。
// 复现事故规则的正确形态——同一个 :8888 连接，内网不报、公网才报。
func TestNotInCIDR_FullRuleEndToEnd(t *testing.T) {
	r := &Rule{
		SchemaVersion: 1, ID: "MXEDR-0080", Name: "c2_high_risk_port",
		Version: 1, Category: "network", Severity: SeverityHigh,
		Agent: AgentMatch{
			Enabled: true, Action: ActionAlert,
			Match: MatchSpec{
				EventType: "tcp_connect",
				Logic:     LogicAnd,
				Conditions: []Condition{
					{Field: "remote_port", Op: OpIn, Values: []string{"4444", "5555", "6666", "8888", "1337", "31337"}},
					{Field: "remote_addr", Op: OpNotInCIDR, Values: privateCIDRs},
				},
			},
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("规则校验失败: %v", err)
	}

	internal := map[string]string{"remote_addr": "10.0.0.11", "remote_port": "8888"}
	if evaluateRule(r, internal) {
		t.Error("内网 内网业务服务 是正常业务调用，不应命中")
	}

	external := map[string]string{"remote_addr": "203.0.113.10", "remote_port": "4444"}
	if !evaluateRule(r, external) {
		t.Error("公网 :4444 是真实 C2 特征，必须命中")
	}
}
