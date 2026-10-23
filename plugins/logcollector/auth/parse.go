package auth

import (
	"regexp"
	"strings"
)

// 解析原则：
//
//  1. 按进程名分派，再用整行锚定（^…$）的格式匹配，不做「内容里包含某个词」的判断。
//     sshd 会把对方提交的用户名原样写进日志，用户名完全由攻击者控制。
//  2. 用户名用贪婪匹配取到「最后一个 from」之前：攻击者可以让用户名里出现
//     "root from 1.2.3.4 port 22 ssh2"，但改变不了行尾由 sshd 自己写的真实来源。
//  3. 认不出的行直接丢弃，不猜。

var (
	// Accepted publickey for alice from 10.0.0.5 port 51022 ssh2: ED25519 SHA256:abc…
	// 用证书登录时后面还跟着证书标识与签发 CA（样本取自 OpenSSH 9.9）：
	// Accepted publickey for alice from 10.0.0.5 port 51022 ssh2: ED25519-CERT SHA256:abc… ID ops-alice (serial 7) CA ED25519 SHA256:def…
	//
	// 账号名只取不含空格的一段、从左往右匹配。登录成功的一定是本机存在的账号，名字里没有空格；
	// 而行尾的证书标识是签证书的人起的，可以包含「 from 6.6.6.6 port 1 ssh2: …」。
	// 账号名若沿用「取到最后一个 from 之前」的写法，一个精心起名的证书就能改写来源地址。
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+)(?: ID (.+) \(serial (\d+)\) CA (\S+) (\S+))?)?$`)
	// Failed password for invalid user admin from 203.0.113.9 port 4022 ssh2
	// 公钥被拒时行尾带着对方出示的那把公钥：
	// Failed publickey for root from 203.0.113.9 port 4022 ssh2: ED25519 SHA256:abc…
	// 出示的是证书时后面同样跟着证书标识，不取，只要这一行能认出来。
	reSSHFailed = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+)(?: ID .*)?)?$`)
	// OpenSSH 9.8 起按来源惩罚：一个来源连续认证失败后，sshd 在握手前就把它的新连接丢掉，
	// 不再有 Failed password 那一行。爆破中后段留下的只有这个（样本取自 OpenSSH 9.9）：
	// drop connection #0 from [203.0.113.9]:64208 on [10.0.0.8]:22 penalty: failed authentication
	reSSHPenaltyDrop = regexp.MustCompile(`^drop connection #\d+ from \[([0-9a-fA-F:.]+)\]:(\d+) on \S+ penalty: (.+)$`)
	// error: maximum authentication attempts exceeded for invalid user x from 1.2.3.4 port 22 ssh2 [preauth]
	reSSHMaxAttempts = regexp.MustCompile(`^error: maximum authentication attempts exceeded for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?(?: \[preauth\])?$`)
	// Connection closed by authenticating user root 203.0.113.9 port 4022 [preauth]
	// Disconnected from invalid user test 203.0.113.9 port 4022 [preauth]
	reSSHPreauthClose = regexp.MustCompile(`^(?:Connection closed by|Disconnected from|Connection reset by) (authenticating|invalid) user (.*) (\S+) port (\d+) \[preauth\]$`)
	// pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)
	// pam_unix(sshd:session): session opened for user alice by (uid=0)
	rePAMSession = regexp.MustCompile(`^pam_unix\(([a-z0-9_-]+):session\): session (opened|closed) for user ([^\s(]+)(?:\(uid=\d+\))?(?: by ([^\s(]*)\(uid=(\d+)\))?$`)
	// pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root
	rePAMSuAuthFail = regexp.MustCompile(`^pam_unix\(su(?:-l)?:auth\): authentication failure; logname=(\S*) uid=\d+ euid=\d+ tty=(\S*) ruser=(\S*) rhost=\S*\s+user=(\S+)$`)

	// alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
	// alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
	// alice : PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
	//
	// TTY 一段是可选的：没有终端时（ssh 主机 命令、脚本、自动化工具）sudo 不写它。
	// 这恰恰是拿到 shell 之后最常见的用法，要求它存在等于漏掉这一整类。
	// 失败原因不含等号，用它把「原因」和后面的 KEY=VALUE 字段分开。
	reSudo = regexp.MustCompile(`^\s*(\S+) : (?:([^=;]+?) ; )?(?:TTY=(\S+) ; )?(?:CHROOT=.*? ; )?PWD=(.*?) ; USER=(\S+) ; (?:GROUP=\S+ ; )?(?:TSID=\S+ ; )?(?:ENV=.*? ; )?COMMAND=(.*)$`)

	// new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/0
	reUserAdd = regexp.MustCompile(`^new user: name=([^,\s]+), UID=(\d+), GID=(\d+)`)
	// new group: name=dev, GID=1002
	reGroupAdd = regexp.MustCompile(`^new group: name=([^,\s]+), GID=(\d+)`)
	// delete user 'bob'
	reUserDel = regexp.MustCompile(`^delete user '([^']+)'$`)
	// add 'bob' to group 'wheel'
	// usermod 紧接着还会写一行 add 'bob' to shadow group 'wheel'，是同一个动作，不重复上报。
	reUserModGroup = regexp.MustCompile(`^add '([^']+)' to group '([^']+)'$`)
	// change user 'bob' password   /   change user 'bob' shell from '/bin/sh' to '/bin/bash'
	reUserModChange = regexp.MustCompile(`^change user '([^']+)' (\S+)`)
	// user bob added by root to group wheel
	reGpasswdAdd = regexp.MustCompile(`^user (\S+) added by (\S+) to group (\S+)$`)
	// pam_unix(passwd:chauthtok): password changed for bob
	rePasswdChanged = regexp.MustCompile(`^pam_unix\(passwd:chauthtok\): password changed for (\S+)$`)
)

// 会话事件只保留真正代表「有人登进来」的服务。sudo 每执行一条命令、cron 每分钟起一次任务，
// PAM 都会打一行 session opened，量比真实登录高几个数量级。
var loginSessionServices = map[string]bool{"sshd": true, "login": true, "sshd-session": true}

// privilegedGroups 加入这些用户组等于拿到管理员权限。
var privilegedGroups = map[string]bool{"wheel": true, "sudo": true, "root": true, "admin": true, "docker": true}

// Parse 把一条日志记录解析成事件；不是关心的内容或格式不符时返回 nil。
func Parse(en Entry) *Event {
	msg := strings.TrimRight(en.Message, "\r\n")
	if msg == "" || len(msg) > 8192 {
		return nil
	}
	var ev *Event
	switch en.Ident {
	case "sshd", "sshd-session", "sshd-auth":
		ev = parseSSHD(msg)
	case "sudo":
		ev = parseSudo(msg)
	case "su", "su-l":
		ev = parseSu(msg)
	case "login":
		ev = parseSession(msg)
	case "useradd", "userdel", "usermod", "groupadd", "gpasswd", "passwd":
		ev = parseAccount(en.Ident, msg)
	}
	if ev == nil {
		return nil
	}
	ev.Time = en.Time
	ev.PID = en.PID
	ev.Trust = en.Trust
	if ev.Service == "" {
		ev.Service = en.Ident
	}
	ev.Raw = msg
	ev.Count = 1
	return ev
}

func parseSSHD(msg string) *Event {
	if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
		ev := &Event{Kind: KindLoginSuccess, Service: "sshd", Method: m[1], Username: m[2],
			SourceIP: m[3], SourcePort: m[4], KeyFP: m[6]}
		if m[7] != "" {
			// 证书登录：谁签的证书和签给谁，与用了哪把密钥同样要紧。
			// 证书标识放最后：它的内容不受我们控制，放在前面的话可以在里面伪造后面的 serial= 与 ca=。
			ev.Detail = "ca=" + m[10] + " serial=" + m[8] + " cert_id=" + m[7]
		}
		return ev
	}
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		return &Event{Kind: KindLoginFailed, Service: "sshd", Method: m[1], Reason: m[1],
			Invalid: m[2] != "", Username: m[3], SourceIP: m[4], SourcePort: m[5], KeyFP: m[7]}
	}
	if m := reSSHPenaltyDrop.FindStringSubmatch(msg); m != nil {
		// 没有账号名：连接在认证开始之前就被丢了。算作一次失败，暴力破解的计数才不会在
		// sshd 开始惩罚之后停住。
		return &Event{Kind: KindLoginFailed, Service: "sshd", Reason: "penalty_drop",
			SourceIP: m[1], SourcePort: m[2], Detail: m[3]}
	}
	if m := reSSHMaxAttempts.FindStringSubmatch(msg); m != nil {
		return &Event{Kind: KindLoginFailed, Service: "sshd", Reason: "max_attempts",
			Invalid: m[1] != "", Username: m[2], SourceIP: m[3], SourcePort: m[4]}
	}
	if m := reSSHPreauthClose.FindStringSubmatch(msg); m != nil {
		return &Event{Kind: KindPreauthClose, Service: "sshd", Invalid: m[1] == "invalid",
			Username: m[2], SourceIP: m[3], SourcePort: m[4]}
	}
	return parseSession(msg)
}

// parseSession 解析 PAM 的会话开始与结束，只认登录类服务。
func parseSession(msg string) *Event {
	m := rePAMSession.FindStringSubmatch(msg)
	if m == nil || !loginSessionServices[m[1]] {
		return nil
	}
	kind := KindSessionOpen
	if m[2] == "closed" {
		kind = KindSessionClose
	}
	return &Event{Kind: kind, Service: m[1], Username: m[3]}
}

func parseSudo(msg string) *Event {
	m := reSudo.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	ev := &Event{Kind: KindSudo, Service: "sudo", Username: m[1], TTY: m[3], Cwd: m[4],
		TargetUser: m[5], Command: m[6]}
	// 第二段有内容说明这次没有执行成功：口令错误、不在 sudoers 里、命令不被允许。
	if m[2] != "" {
		ev.Kind = KindSudoDenied
		ev.Reason = m[2]
	}
	// sudo 写日志时不转义：当前目录和命令参数都由执行的人控制，里面可以夹带
	// 「 ; USER=root ; COMMAND=/bin/别的」。出现两份同名字段时分不出哪份是真的——
	// 目录在前、命令在后，两头都能伪造。不去猜，标出来；原文在 raw 里。
	// 正常使用几乎不会碰到，本身就值得看一眼。
	// 字段都以「 ; 」或开头的「 : 」分隔；命令参数里单独出现的 PWD=（sudo env PWD=/tmp …）不算。
	pwdFields := strings.Count(msg, " ; PWD=") + strings.Count(msg, " : PWD=")
	if pwdFields > 1 || strings.Count(msg, " ; USER=") > 1 || strings.Count(msg, " ; COMMAND=") > 1 {
		ev.Detail = DetailAmbiguousFields
	}
	return ev
}

func parseSu(msg string) *Event {
	if m := rePAMSession.FindStringSubmatch(msg); m != nil && (m[1] == "su" || m[1] == "su-l") && m[2] == "opened" {
		return &Event{Kind: KindSuSuccess, Service: "su", Username: m[4], TargetUser: m[3]}
	}
	if m := rePAMSuAuthFail.FindStringSubmatch(msg); m != nil {
		user := m[3]
		if user == "" {
			user = m[1]
		}
		return &Event{Kind: KindSuFailed, Service: "su", Username: user, TargetUser: m[4], TTY: m[2]}
	}
	return nil
}

func parseAccount(ident, msg string) *Event {
	ev := &Event{Kind: KindAccountChange, Service: ident}
	switch {
	case reUserAdd.MatchString(msg):
		m := reUserAdd.FindStringSubmatch(msg)
		ev.Username, ev.Reason, ev.Detail = m[1], "user_created", "uid="+m[2]
		// UID 0 的新账号就是第二个 root。
		if m[2] == "0" {
			ev.Reason = "user_created_uid0"
		}
	case reGroupAdd.MatchString(msg):
		m := reGroupAdd.FindStringSubmatch(msg)
		ev.Reason, ev.Detail = "group_created", m[1]
	case reUserDel.MatchString(msg):
		ev.Username, ev.Reason = reUserDel.FindStringSubmatch(msg)[1], "user_deleted"
	case reUserModGroup.MatchString(msg):
		m := reUserModGroup.FindStringSubmatch(msg)
		ev.Username, ev.Detail, ev.Reason = m[1], m[2], groupReason(m[2])
	case reGpasswdAdd.MatchString(msg):
		m := reGpasswdAdd.FindStringSubmatch(msg)
		ev.Username, ev.Detail, ev.Reason = m[1], m[3], groupReason(m[3])
	case reUserModChange.MatchString(msg):
		m := reUserModChange.FindStringSubmatch(msg)
		ev.Username, ev.Reason = m[1], "user_modified_"+m[2]
	case rePasswdChanged.MatchString(msg):
		ev.Username, ev.Reason = rePasswdChanged.FindStringSubmatch(msg)[1], "password_changed"
	default:
		return nil
	}
	return ev
}

func groupReason(group string) string {
	if privilegedGroups[group] {
		return "added_to_privileged_group"
	}
	return "added_to_group"
}
