package auth

import (
	"strings"
	"testing"
	"time"
)

func parse(ident, msg string) *Event {
	return Parse(Entry{Time: time.Unix(1760000000, 0), Ident: ident, PID: 4321, Message: msg, Trust: TrustJournal})
}

func TestParseSSHD(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want Event
	}{
		{"密钥登录成功", "Accepted publickey for alice from 10.0.0.5 port 51022 ssh2: ED25519 SHA256:AbCdEf123",
			Event{Kind: KindLoginSuccess, Username: "alice", SourceIP: "10.0.0.5", SourcePort: "51022", Method: "publickey", KeyFP: "SHA256:AbCdEf123"}},
		{"密码登录成功", "Accepted password for root from 203.0.113.9 port 4022 ssh2",
			Event{Kind: KindLoginSuccess, Username: "root", SourceIP: "203.0.113.9", SourcePort: "4022", Method: "password"}},
		{"IPv6 来源", "Accepted password for bob from 2001:db8::1 port 22 ssh2",
			Event{Kind: KindLoginSuccess, Username: "bob", SourceIP: "2001:db8::1", SourcePort: "22", Method: "password"}},
		{"密码失败", "Failed password for root from 203.0.113.9 port 4022 ssh2",
			Event{Kind: KindLoginFailed, Username: "root", SourceIP: "203.0.113.9", SourcePort: "4022", Method: "password", Reason: "password"}},
		{"不存在的账号", "Failed password for invalid user admin from 203.0.113.9 port 4022 ssh2",
			Event{Kind: KindLoginFailed, Username: "admin", SourceIP: "203.0.113.9", SourcePort: "4022", Method: "password", Reason: "password", Invalid: true}},
		{"空用户名", "Failed none for invalid user  from 203.0.113.9 port 4022 ssh2",
			Event{Kind: KindLoginFailed, Username: "", SourceIP: "203.0.113.9", SourcePort: "4022", Method: "none", Reason: "none", Invalid: true}},
		{"超过最大尝试次数", "error: maximum authentication attempts exceeded for root from 203.0.113.9 port 4022 ssh2 [preauth]",
			Event{Kind: KindLoginFailed, Username: "root", SourceIP: "203.0.113.9", SourcePort: "4022", Reason: "max_attempts"}},
		{"认证前断开", "Connection closed by authenticating user root 203.0.113.9 port 4022 [preauth]",
			Event{Kind: KindPreauthClose, Username: "root", SourceIP: "203.0.113.9", SourcePort: "4022"}},
		{"认证前断开（不存在的账号）", "Disconnected from invalid user test 203.0.113.9 port 4022 [preauth]",
			Event{Kind: KindPreauthClose, Username: "test", SourceIP: "203.0.113.9", SourcePort: "4022", Invalid: true}},
		{"会话开始", "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)",
			Event{Kind: KindSessionOpen, Username: "alice"}},
		{"会话开始（旧格式）", "pam_unix(sshd:session): session opened for user alice by (uid=0)",
			Event{Kind: KindSessionOpen, Username: "alice"}},
		{"会话结束", "pam_unix(sshd:session): session closed for user alice",
			Event{Kind: KindSessionClose, Username: "alice"}},
	}
	for _, c := range cases {
		got := parse("sshd", c.msg)
		if got == nil {
			t.Errorf("%s：未解析出事件", c.name)
			continue
		}
		if got.Kind != c.want.Kind || got.Username != c.want.Username || got.SourceIP != c.want.SourceIP ||
			got.SourcePort != c.want.SourcePort || got.Method != c.want.Method || got.KeyFP != c.want.KeyFP ||
			got.Reason != c.want.Reason || got.Invalid != c.want.Invalid {
			t.Errorf("%s：得 %+v", c.name, *got)
		}
		if got.Service != "sshd" || got.PID != 4321 || got.Trust != TrustJournal || got.Count != 1 || got.Raw != c.msg {
			t.Errorf("%s：公共字段不完整 %+v", c.name, *got)
		}
	}
}

// sshd 把对方提交的用户名原样写进日志。攻击者用精心构造的用户名去尝试登录，
// 不能因此造出「登录成功」，也不能改变事件里的来源地址。
// 证书登录、公钥被拒、keyboard-interactive。样本格式取自 OpenSSH 9.9。
func TestParseSSHDCertAndKeyVariants(t *testing.T) {
	ev := parse("sshd-session", "Accepted publickey for deploy from 10.0.0.5 port 63487 ssh2: ED25519-CERT SHA256:examplekeyfingerprint0000000000000000000001 ID deploy-cert (serial 0) CA ED25519 SHA256:examplekeyfingerprint0000000000000000000002")
	if ev == nil || ev.Kind != KindLoginSuccess || ev.Username != "deploy" || ev.Method != "publickey" ||
		ev.SourceIP != "10.0.0.5" || ev.KeyFP != "SHA256:examplekeyfingerprint0000000000000000000001" ||
		ev.Detail != "ca=SHA256:examplekeyfingerprint0000000000000000000002 serial=0 cert_id=deploy-cert" {
		t.Fatalf("证书登录：%+v", ev)
	}
	ev = parse("sshd-session", "Failed publickey for root from 10.0.0.5 port 63490 ssh2: ED25519 SHA256:examplekeyfingerprint0000000000000000000003")
	if ev == nil || ev.Kind != KindLoginFailed || ev.Username != "root" || ev.Method != "publickey" ||
		ev.KeyFP != "SHA256:examplekeyfingerprint0000000000000000000003" {
		t.Fatalf("公钥被拒：%+v", ev)
	}
	ev = parse("sshd-session", "Accepted keyboard-interactive/pam for deploy from 10.0.0.5 port 63488 ssh2")
	if ev == nil || ev.Kind != KindLoginSuccess || ev.Method != "keyboard-interactive/pam" {
		t.Fatalf("keyboard-interactive 登录：%+v", ev)
	}
	ev = parse("sshd-session", "Failed keyboard-interactive/pam for root from 10.0.0.5 port 63489 ssh2")
	if ev == nil || ev.Kind != KindLoginFailed || ev.Username != "root" {
		t.Fatalf("keyboard-interactive 失败：%+v", ev)
	}
}

// 证书标识是签证书的人起的，里面可以伪造一整段「 from … port … ssh2: …」。
// 来源地址和账号名必须仍是行首 sshd 自己写的那一份。
func TestParseSSHDCertIDCannotForgeSource(t *testing.T) {
	ev := parse("sshd-session", "Accepted publickey for deploy from 10.0.0.5 port 63487 ssh2: ED25519-CERT SHA256:aaa ID x from 6.6.6.6 port 1 ssh2: T F ID y (serial 9) CA ED25519 SHA256:fake (serial 0) CA ED25519 SHA256:realca")
	if ev == nil || ev.Username != "deploy" || ev.SourceIP != "10.0.0.5" || ev.SourcePort != "63487" || ev.KeyFP != "SHA256:aaa" {
		t.Fatalf("证书标识改写了来源或账号：%+v", ev)
	}
	if !strings.HasPrefix(ev.Detail, "ca=SHA256:realca serial=0 cert_id=") {
		t.Fatalf("签发 CA 与序号应取行尾 sshd 写的那一份，并排在证书标识之前：%q", ev.Detail)
	}
	// 出示证书被拒的行也要能认出来。
	ev = parse("sshd-session", "Failed publickey for root from 10.0.0.5 port 63490 ssh2: ED25519-CERT SHA256:bbb ID someone (serial 3) CA ED25519 SHA256:ccc")
	if ev == nil || ev.Kind != KindLoginFailed || ev.Username != "root" || ev.SourceIP != "10.0.0.5" || ev.KeyFP != "SHA256:bbb" {
		t.Fatalf("出示证书被拒：%+v", ev)
	}
}

// 被 sshd 按来源惩罚丢掉的连接算一次失败。样本格式取自 OpenSSH 9.9。
func TestParseSSHDPenaltyDrop(t *testing.T) {
	ev := parse("sshd", "drop connection #0 from [203.0.113.9]:64208 on [10.0.0.8]:22 penalty: failed authentication")
	if ev == nil || ev.Kind != KindLoginFailed || ev.SourceIP != "203.0.113.9" || ev.SourcePort != "64208" ||
		ev.Reason != "penalty_drop" || ev.Detail != "failed authentication" || ev.Username != "" {
		t.Fatalf("惩罚丢弃：%+v", ev)
	}
	ev = parse("sshd", "drop connection #2 from [2001:db8::9]:5000 on [2001:db8::1]:22 penalty: exceeded LoginGraceTime")
	if ev == nil || ev.SourceIP != "2001:db8::9" {
		t.Fatalf("IPv6 来源：%+v", ev)
	}
}

func TestParseSSHDResistsUsernameInjection(t *testing.T) {
	// 真实来源是 198.51.100.7，用户名试图伪装成另一条成功登录。
	forged := "Failed password for invalid user root from 10.0.0.1 port 22 ssh2: Accepted password for root from 10.0.0.1 port 22 ssh2 from 198.51.100.7 port 40000 ssh2"
	ev := parse("sshd", forged)
	if ev == nil {
		t.Fatal("应解析为一次失败登录")
	}
	if ev.Kind != KindLoginFailed {
		t.Fatalf("被伪造成了 %s", ev.Kind)
	}
	if ev.SourceIP != "198.51.100.7" || ev.SourcePort != "40000" {
		t.Fatalf("来源被用户名里的内容带偏：%s:%s", ev.SourceIP, ev.SourcePort)
	}

	// 用户名里塞一整句成功登录：整行锚定下它仍只是一次失败。
	forged = "Failed password for invalid user Accepted password for root from 10.0.0.1 port 22 ssh2 from 198.51.100.7 port 40000 ssh2"
	if ev = parse("sshd", forged); ev == nil || ev.Kind != KindLoginFailed || ev.SourceIP != "198.51.100.7" {
		t.Fatalf("注入样本解析结果不对：%+v", ev)
	}

	// 不以 sshd 自己的固定开头起始的行不认。
	for _, msg := range []string{
		"hello Accepted password for root from 10.0.0.1 port 22 ssh2",
		"Invalid user Accepted password for root from 10.0.0.1 port 22 ssh2 from 198.51.100.7 port 4000",
		"Accepted password for root from 10.0.0.1 port 22 ssh2 trailing garbage",
	} {
		if ev := parse("sshd", msg); ev != nil && ev.Kind == KindLoginSuccess {
			t.Errorf("不该解析为登录成功：%q → %+v", msg, *ev)
		}
	}
}

// 进程名决定用哪套格式：别的进程写出一行长得像 sshd 的内容，不能被当成登录。
func TestParseDispatchesByIdent(t *testing.T) {
	const line = "Accepted password for root from 10.0.0.1 port 22 ssh2"
	for _, ident := range []string{"logger", "cron", "sudo", "myapp", ""} {
		if ev := parse(ident, line); ev != nil {
			t.Errorf("进程 %q 写的内容被解析成了 %s", ident, ev.Kind)
		}
	}
}

func TestParseSudo(t *testing.T) {
	ev := parse("sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
	if ev == nil || ev.Kind != KindSudo || ev.Username != "alice" || ev.TargetUser != "root" ||
		ev.TTY != "pts/0" || ev.Cwd != "/home/alice" || ev.Command != "/usr/bin/systemctl restart nginx" {
		t.Fatalf("sudo 执行：%+v", ev)
	}
	ev = parse("sudo", "bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
	if ev == nil || ev.Kind != KindSudoDenied || ev.Reason != "3 incorrect password attempts" || ev.Username != "bob" {
		t.Fatalf("sudo 口令错误：%+v", ev)
	}
	ev = parse("sudo", "eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
	if ev == nil || ev.Kind != KindSudoDenied || ev.Reason != "user NOT in sudoers" || ev.Command != "/usr/bin/cat /etc/shadow" {
		t.Fatalf("不在 sudoers 里：%+v", ev)
	}
	ev = parse("sudo", "deploy : TTY=unknown ; PWD=/ ; USER=root ; GROUP=root ; COMMAND=/usr/bin/id")
	if ev == nil || ev.Kind != KindSudo || ev.Command != "/usr/bin/id" {
		t.Fatalf("带 GROUP 的格式：%+v", ev)
	}
	// 命令里出现分号与关键字不影响前面的字段。
	ev = parse("sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c echo ; USER=nobody ; COMMAND=x")
	if ev == nil || ev.TargetUser != "root" || ev.Command != "/bin/sh -c echo ; USER=nobody ; COMMAND=x" {
		t.Fatalf("命令里带分号：%+v", ev)
	}
	// sudo 的 PAM 会话行不是一次登录，不上报。
	if ev := parse("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)"); ev != nil {
		t.Fatalf("sudo 的会话行不该上报：%+v", ev)
	}
}

// 没有终端的 sudo 不写 TTY 一段。样本格式取自 OpenSSH 9.9。
func TestParseSudoWithoutTTY(t *testing.T) {
	ev := parse("sudo", "  deploy : PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id")
	if ev == nil || ev.Kind != KindSudo || ev.Username != "deploy" || ev.TargetUser != "root" ||
		ev.TTY != "" || ev.Cwd != "/home/deploy" || ev.Command != "/usr/bin/id" || ev.Detail != "" {
		t.Fatalf("无终端的 sudo：%+v", ev)
	}
	ev = parse("sudo", "mallory : user NOT in sudoers ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/true")
	if ev == nil || ev.Kind != KindSudoDenied || ev.Reason != "user NOT in sudoers" || ev.Username != "mallory" || ev.Command != "/bin/true" {
		t.Fatalf("无终端、不在 sudoers 里：%+v", ev)
	}
	ev = parse("sudo", "    root : PWD=/home/deploy ; USER=deploy ; COMMAND=/bin/bash -c 'echo wrong | su bob -c true'")
	if ev == nil || ev.Kind != KindSudo || ev.Username != "root" || ev.TargetUser != "deploy" {
		t.Fatalf("root 用 sudo 切到普通用户：%+v", ev)
	}
	// 续行不是一次新的 sudo。
	if ev := parse("sudo", "  deploy : (command continued) aaaaaaaa"); ev != nil {
		t.Fatalf("续行不该产生事件：%+v", ev)
	}
}

// 命令参数里单独出现的 PWD= 不是重复字段；带 CHROOT 的格式能解析。
func TestParseSudoFieldVariants(t *testing.T) {
	ev := parse("sudo", "  deploy : PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/env PWD=/tmp /usr/bin/id")
	if ev == nil || ev.Detail != "" || ev.Command != "/usr/bin/env PWD=/tmp /usr/bin/id" {
		t.Fatalf("命令里的 PWD= 不该被当成重复字段：%+v", ev)
	}
	ev = parse("sudo", "alice : TTY=pts/0 ; CHROOT=/srv/jail ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id")
	if ev == nil || ev.Kind != KindSudo || ev.Cwd != "/" || ev.Command != "/usr/bin/id" {
		t.Fatalf("带 CHROOT 的格式：%+v", ev)
	}
}

// 目录名或命令参数里夹带伪造字段时标出来，不假装能分清哪份是真的。样本格式取自 OpenSSH 9.9。
func TestParseSudoFlagsInjectedFields(t *testing.T) {
	ev := parse("sudo", "  deploy : PWD=/tmp/x ; USER=root ; COMMAND=/bin/fake-injected ; USER=root ; COMMAND=/usr/bin/id")
	if ev == nil || ev.Kind != KindSudo || ev.Username != "deploy" || ev.Detail != DetailAmbiguousFields {
		t.Fatalf("目录名里夹带字段应被标记：%+v", ev)
	}
	ev = parse("sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c echo ; USER=nobody ; COMMAND=x")
	if ev == nil || ev.Detail != DetailAmbiguousFields {
		t.Fatalf("命令参数里夹带字段应被标记：%+v", ev)
	}
	// 原因一段不能被「PWD=…」冒充成失败。
	ev = parse("sudo", "  deploy : PWD=/tmp/a ; PWD=/tmp/b ; USER=root ; COMMAND=/usr/bin/id")
	if ev == nil || ev.Kind != KindSudo || ev.Detail != DetailAmbiguousFields {
		t.Fatalf("重复的 PWD 不该被当成失败原因：%+v", ev)
	}
}

func TestParseSu(t *testing.T) {
	ev := parse("su", "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)")
	if ev == nil || ev.Kind != KindSuSuccess || ev.Username != "alice" || ev.TargetUser != "root" {
		t.Fatalf("su 成功：%+v", ev)
	}
	ev = parse("su", "pam_unix(su-l:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root")
	if ev == nil || ev.Kind != KindSuFailed || ev.Username != "alice" || ev.TargetUser != "root" || ev.TTY != "pts/0" {
		t.Fatalf("su 失败：%+v", ev)
	}
	if ev := parse("su", "pam_unix(su:session): session closed for user root"); ev != nil {
		t.Fatalf("su 会话结束不上报：%+v", ev)
	}
}

func TestParseAccountChanges(t *testing.T) {
	cases := []struct {
		ident, msg, user, reason, detail string
	}{
		{"useradd", "new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/0", "bob", "user_created", "uid=1001"},
		{"useradd", "new user: name=toor, UID=0, GID=0, home=/root, shell=/bin/bash", "toor", "user_created_uid0", "uid=0"},
		{"groupadd", "new group: name=dev, GID=1002", "", "group_created", "dev"},
		{"userdel", "delete user 'bob'", "bob", "user_deleted", ""},
		{"usermod", "add 'bob' to group 'wheel'", "bob", "added_to_privileged_group", "wheel"},
		{"usermod", "add 'bob' to group 'dev'", "bob", "added_to_group", "dev"},
		{"gpasswd", "user bob added by root to group sudo", "bob", "added_to_privileged_group", "sudo"},
		{"usermod", "change user 'bob' password", "bob", "user_modified_password", ""},
		{"passwd", "pam_unix(passwd:chauthtok): password changed for bob", "bob", "password_changed", ""},
	}
	for _, c := range cases {
		ev := parse(c.ident, c.msg)
		if ev == nil || ev.Kind != KindAccountChange || ev.Username != c.user || ev.Reason != c.reason || ev.Detail != c.detail {
			t.Errorf("%s %q：%+v", c.ident, c.msg, ev)
		}
	}
	// usermod 加组时连写两行（group 与 shadow group），是同一个动作，只报第一行。
	if ev := parse("usermod", "add 'bob' to shadow group 'wheel'"); ev != nil {
		t.Errorf("shadow group 一行不该再报一次：%+v", ev)
	}
	if ev := parse("useradd", "failed adding user 'x', exit code: 9"); ev != nil {
		t.Errorf("无关内容不该上报：%+v", ev)
	}
}

func TestEventFields(t *testing.T) {
	ev := parse("sshd", "Failed password for invalid user admin from 203.0.113.9 port 4022 ssh2")
	ev.Count = 7
	f := ev.Fields()
	want := map[string]string{
		"event_type": KindLoginFailed, "service": "sshd", "trust": TrustJournal, "username": "admin",
		"source_ip": "203.0.113.9", "source_port": "4022", "invalid_user": "true", "count": "7",
		"pid": "4321", "timestamp": "1760000000", "reason": "password", "auth_method": "password",
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("字段 %s = %q，期望 %q", k, f[k], v)
		}
	}
	if _, ok := f["command"]; ok {
		t.Error("空字段不该出现在上报里")
	}
	long := parse("sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo "+string(make([]byte, 2000)))
	if long == nil || len(long.Fields()["raw"]) != rawMaxLen {
		t.Errorf("原始内容应截断到 %d", rawMaxLen)
	}
}
