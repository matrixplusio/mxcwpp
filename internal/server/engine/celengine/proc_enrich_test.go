package celengine

import (
	"testing"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	builtinrules "github.com/matrixplusio/mxcwpp/configs/rules"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newEnrichEngine(t *testing.T) *Engine {
	t.Helper()
	env, err := newCELEnv()
	if err != nil {
		t.Fatalf("cel env: %v", err)
	}
	return &Engine{env: env, log: zap.NewNop(), procTree: NewProcessTree(zap.NewNop()), workers: 1}
}

func setInventory(e *Engine, host string, procs map[string]procInfo) {
	snap := map[string]map[string]procInfo{host: procs}
	e.procInventory.Store(&snap)
}

// 进程树优先于进程清单：进程号被复用时，新进程一定有启动事件，清单里的还是旧程序。
func TestEnrichProcessSources(t *testing.T) {
	e := newEnrichEngine(t)
	e.procTree.HandleExec("a1", map[string]string{"pid": "100", "exe": "/tmp/x", "cmdline": "/tmp/x -c"})
	setInventory(e, "h1", map[string]procInfo{
		"100": {exe: "/usr/sbin/nginx", cmdline: "nginx: worker"},
		"200": {exe: "/usr/bin/java", cmdline: "java -jar app.jar"},
	})

	f := map[string]string{"pid": "100", "event_type": "tcp_connect"}
	e.EnrichProcess("a1", "h1", 3002, f)
	if f["exe"] != "/tmp/x" || f["cmdline"] != "/tmp/x -c" || f["proc_source"] != ProcSourceExec {
		t.Errorf("进程树里有的应取进程树：%v", f)
	}

	f = map[string]string{"pid": "200", "event_type": "file_open"}
	e.EnrichProcess("a1", "h1", 3001, f)
	if f["exe"] != "/usr/bin/java" || f["proc_source"] != ProcSourceInventory {
		t.Errorf("常驻进程应从进程清单补上：%v", f)
	}

	f = map[string]string{"pid": "999", "event_type": "dns_query"}
	e.EnrichProcess("a1", "h1", 3003, f)
	if f["exe"] != "" || f["proc_source"] != "" {
		t.Errorf("查不到时应保持为空：%v", f)
	}

	// 自带程序信息的事件不动；进程事件不处理。
	f = map[string]string{"pid": "200", "exe": "/bin/own"}
	e.EnrichProcess("a1", "h1", 3001, f)
	if f["exe"] != "/bin/own" {
		t.Errorf("已有 exe 的事件被改写：%v", f)
	}
	f = map[string]string{"pid": "200"}
	e.EnrichProcess("a1", "h1", 3000, f)
	if f["exe"] != "" {
		t.Errorf("进程事件不该被补全：%v", f)
	}

	if tr, inv, miss := e.procStats.fromTree.Load(), e.procStats.fromInventory.Load(), e.procStats.miss.Load(); tr != 1 || inv != 1 || miss != 1 {
		t.Errorf("统计不符：exec=%d inventory=%d miss=%d", tr, inv, miss)
	}
}

// builtinExpr 取内置规则的表达式与数据类型，规则改名时这里会直接失败。
func builtinRule(t *testing.T, name string) model.DetectionRule {
	t.Helper()
	var doc struct {
		Rules []struct {
			Name       string   `yaml:"name"`
			Expression string   `yaml:"expression"`
			DataTypes  []string `yaml:"data_types"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(builtinrules.BuiltinRulesYAML, &doc); err != nil {
		t.Fatalf("parse builtin rules: %v", err)
	}
	for _, r := range doc.Rules {
		if r.Name == name {
			return model.DetectionRule{Name: r.Name, Expression: r.Expression, DataTypes: model.StringArray(r.DataTypes), Enabled: true}
		}
	}
	t.Fatalf("内置规则里找不到 %q", name)
	return model.DetectionRule{}
}

func loadRules(t *testing.T, e *Engine, names ...string) {
	t.Helper()
	compiled := make([]compiledRule, 0, len(names))
	for i, n := range names {
		r := builtinRule(t, n)
		r.ID = uint(i + 1)
		prog, err := e.compile(r.Expression)
		if err != nil {
			t.Fatalf("编译 %q 失败: %v", n, err)
		}
		compiled = append(compiled, compiledRule{rule: r, program: prog})
	}
	e.rules = compiled
	e.rebuildDataTypeIndex()
}

func hitNames(rules []model.DetectionRule) map[string]bool {
	out := make(map[string]bool, len(rules))
	for _, r := range rules {
		out[r.Name] = true
	}
	return out
}

// 「不是某某程序才告警」的规则：程序未知时不告警。
// 此前文件与网络事件的 exe 恒为空，这类条件恒成立，每台主机的每次 DNS 查询都命中。
func TestNegativeExeRulesNeedKnownExe(t *testing.T) {
	e := newEnrichEngine(t)
	const rule = "DNS 查询 - 非 DNS 工具"
	loadRules(t, e, rule)

	dns := func(exe string) bool {
		f := map[string]string{"agent_id": "a1", "event_type": "dns_query", "pid": "1"}
		if exe != "" {
			f["exe"] = exe
		}
		return hitNames(e.Evaluate(3003, f))[rule]
	}
	if dns("") {
		t.Error("程序未知时不该命中")
	}
	if dns("/usr/bin/dig") {
		t.Error("dig 发起的查询不该命中")
	}
	if !dns("/tmp/payload") {
		t.Error("非 DNS 工具发起的查询应当命中")
	}
}

// 写文件的规则在两种采集方式下都要能命中：内核探针报 file_open（只读打开已在内核丢弃），
// 用户态后备报 file_write。此前只认后者，绝大多数主机上这些规则形同不存在。
func TestFileWriteRulesMatchBothCollectors(t *testing.T) {
	e := newEnrichEngine(t)
	const passwd, sshd = "持久化 - /etc/passwd 直接写", "持久化 - SSH config Match 子句"
	loadRules(t, e, passwd, sshd)

	eval := func(eventType, path string) map[string]bool {
		return hitNames(e.Evaluate(3001, map[string]string{"agent_id": "a1", "event_type": eventType, "file_path": path, "pid": "1"}))
	}
	for _, et := range []string{"file_open", "file_write"} {
		if !eval(et, "/etc/passwd")[passwd] {
			t.Errorf("%s /etc/passwd 应命中", et)
		}
		if !eval(et, "/etc/ssh/sshd_config.d/x.conf")[sshd] {
			t.Errorf("%s sshd_config.d 应命中", et)
		}
	}
	if eval("file_unlink", "/etc/passwd")[passwd] {
		t.Error("删除事件不该被当成写入")
	}
	// 原式少一层括号，任何涉及 sshd_config.d 的事件（包括删除）都会命中。
	if eval("file_unlink", "/etc/ssh/sshd_config.d/x.conf")[sshd] {
		t.Error("非写入事件不该命中 SSH 配置规则")
	}
}

// 补全之后，依赖程序信息的规则在网络事件上才有判断依据。
func TestEnrichedEventFeedsRules(t *testing.T) {
	e := newEnrichEngine(t)
	const rule = "DNS 查询 - 可疑进程"
	loadRules(t, e, rule)
	e.procTree.HandleExec("a1", map[string]string{"pid": "77", "exe": "/tmp/.x/beacon", "cmdline": "/tmp/.x/beacon"})

	f := map[string]string{"agent_id": "a1", "event_type": "dns_query", "pid": "77"}
	if hitNames(e.Evaluate(3003, f))[rule] {
		t.Fatal("未补全时 exe 为空，不应命中（确认这条测试确实在测补全）")
	}
	e.EnrichProcess("a1", "h1", 3003, f)
	if !hitNames(e.Evaluate(3003, f))[rule] {
		t.Fatal("补全后应命中")
	}
}

// 认证事件的内置规则能编译，并按主机侧上报的字段命中。
func TestAuthEventRules(t *testing.T) {
	e := newEnrichEngine(t)
	names := []string{
		"认证 - 新建 UID 0 账号", "认证 - 账号加入特权用户组", "认证 - 新建账号",
		"认证 - root 密码登录", "认证 - 公网地址直接登录", "认证 - 无权用户尝试 sudo",
	}
	loadRules(t, e, names...)
	eval := func(f map[string]string) map[string]bool {
		f["agent_id"] = "a1"
		return hitNames(e.Evaluate(3020, f))
	}
	cases := []struct {
		name   string
		fields map[string]string
		want   []string
	}{
		{"新建 UID 0 账号", map[string]string{"event_type": "auth_account_change", "reason": "user_created_uid0", "username": "toor"},
			[]string{"认证 - 新建 UID 0 账号"}},
		{"加入 wheel", map[string]string{"event_type": "auth_account_change", "reason": "added_to_privileged_group", "detail": "wheel"},
			[]string{"认证 - 账号加入特权用户组"}},
		{"新建普通账号", map[string]string{"event_type": "auth_account_change", "reason": "user_created"},
			[]string{"认证 - 新建账号"}},
		{"root 从公网密码登录", map[string]string{"event_type": "auth_login_success", "username": "root", "auth_method": "password", "source_ip": "203.0.113.9"},
			[]string{"认证 - root 密码登录", "认证 - 公网地址直接登录"}},
		{"root 从内网密钥登录", map[string]string{"event_type": "auth_login_success", "username": "root", "auth_method": "publickey", "source_ip": "10.0.0.5"}, nil},
		{"登录失败不算登录", map[string]string{"event_type": "auth_login_failed", "username": "root", "auth_method": "password", "source_ip": "203.0.113.9"}, nil},
		{"不在 sudoers 里", map[string]string{"event_type": "auth_sudo_denied", "reason": "user NOT in sudoers"},
			[]string{"认证 - 无权用户尝试 sudo"}},
		{"sudo 输错密码", map[string]string{"event_type": "auth_sudo_denied", "reason": "1 incorrect password attempt"}, nil},
	}
	for _, c := range cases {
		got := eval(c.fields)
		if len(got) != len(c.want) {
			t.Errorf("%s：命中 %v，期望 %v", c.name, got, c.want)
			continue
		}
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%s：应命中 %q，实际 %v", c.name, w, got)
			}
		}
	}
}

// 只该由服务端写的字段，上报方带进来的要先清掉。
func TestStripServerOnlyFields(t *testing.T) {
	f := map[string]string{"exe": "/tmp/x", "proc_source": ProcSourceExec, "declared_severity": "low", "pid": "1"}
	StripServerOnlyFields(f)
	if len(f) != 2 || f["exe"] != "/tmp/x" || f["pid"] != "1" {
		t.Errorf("应只剩 exe 与 pid：%v", f)
	}
}
