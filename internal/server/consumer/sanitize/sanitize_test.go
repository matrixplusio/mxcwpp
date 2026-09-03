package sanitize

import "testing"

func TestCmdline(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"空字符串", "", ""},
		{"普通命令", "ls -la /tmp", "ls -la /tmp"},
		{"无敏感参数", "curl https://example.com", "curl https://example.com"},

		// --flag=value 模式
		{"password=value", "mysql --password=secret123 -u root", "mysql --password=*** -u root"},
		{"token=value", "curl --token=abc123def456", "curl --token=***"},
		{"secret=value", "app --secret=mysecret --port=8080", "app --secret=*** --port=8080"},
		{"api-key=value", "cli --api-key=ak_live_xxx", "cli --api-key=***"},
		{"api_key=value", "cli --api_key=ak_live_xxx", "cli --api_key=***"},

		// -flag value 模式
		{"password空格", "mysql -password secret123 -u root", "mysql -password *** -u root"},
		{"-p空格", "mysql -pass secret123", "mysql -pass ***"},

		// 大小写不敏感
		{"大写", "app --PASSWORD=abc", "app --PASSWORD=***"},
		{"混合大小写", "app --Token=abc", "app --Token=***"},

		// 环境变量泄漏
		{"env PASSWORD=", "PASSWORD=secret123 ./app", "PASSWORD=*** ./app"},
		{"env AWS_SECRET_ACCESS_KEY=", "AWS_SECRET_ACCESS_KEY=abcdef /bin/aws", "AWS_SECRET_ACCESS_KEY=*** /bin/aws"},
		{"env API_KEY=", "API_KEY=xxx ./start.sh", "API_KEY=*** ./start.sh"},

		// 多个敏感参数
		{"多个参数", "app --password=p1 --token=t1 --port=80", "app --password=*** --token=*** --port=80"},

		// 正常参数不受影响
		{"port不脱敏", "app --port=8080", "app --port=8080"},
		{"host不脱敏", "mysql --host=localhost --password=secret", "mysql --host=localhost --password=***"},

		// 挖矿进程不受影响
		{"挖矿命令行", "/tmp/xmrig --pool stratum+tcp://pool.com:3333 --user wallet", "/tmp/xmrig --pool stratum+tcp://pool.com:3333 --user wallet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Cmdline(tt.input)
			if got != tt.want {
				t.Errorf("Cmdline(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFields(t *testing.T) {
	fields := map[string]string{
		"exe":     "/usr/bin/mysql",
		"cmdline": "mysql --password=secret -u root",
		"pid":     "1234",
	}

	Fields(fields)

	if fields["cmdline"] != "mysql --password=*** -u root" {
		t.Errorf("Fields 未正确脱敏 cmdline: %q", fields["cmdline"])
	}
	if fields["exe"] != "/usr/bin/mysql" {
		t.Error("Fields 不应修改 exe")
	}
}

func TestFieldsNoCmdline(t *testing.T) {
	fields := map[string]string{
		"exe": "/bin/bash",
		"pid": "100",
	}
	Fields(fields)
	// 不含 cmdline，不应 panic
	if fields["exe"] != "/bin/bash" {
		t.Error("不应修改 exe")
	}
}

func BenchmarkCmdline(b *testing.B) {
	input := "app --password=secret123 --token=abc --port=8080 --host=localhost"
	for b.Loop() {
		Cmdline(input)
	}
}
