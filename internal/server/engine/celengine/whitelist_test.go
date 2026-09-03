package celengine

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestIsAlertWhitelisted(t *testing.T) {
	cases := []struct {
		name         string
		ruleName     string
		ruleCategory string
		fields       map[string]string
		wantWL       bool
		wantReason   string
	}{
		{
			name:         "中文 rule name + c2_communication category + nginx 被抑制",
			ruleName:     "高危端口外连",
			ruleCategory: "c2_communication",
			fields:       map[string]string{"exe": "/usr/sbin/nginx", "dst_ip": "8.8.8.8"},
			wantWL:       true,
			wantReason:   "reverse_proxy_upstream",
		},
		{
			name:         "中文 rule name + c2_communication category + 内网 IP 被抑制",
			ruleName:     "Cobalt Strike 默认端口",
			ruleCategory: "c2_communication",
			fields:       map[string]string{"exe": "/opt/app/bin/srv", "dst_ip": "10.0.0.50"},
			wantWL:       true,
			wantReason:   "internal_network_connection",
		},
		{
			name:       "nginx 反代到 8888 高危端口规则被抑制",
			ruleName:   "c2_high_risk_port",
			fields:     map[string]string{"exe": "/usr/sbin/nginx", "dst_ip": "8.8.8.8", "dst_port": "8888"},
			wantWL:     true,
			wantReason: "reverse_proxy_upstream",
		},
		{
			name:       "envoy 反代被抑制",
			ruleName:   "c2_high_risk_port",
			fields:     map[string]string{"exe": "/usr/local/bin/envoy", "dst_ip": "8.8.8.8"},
			wantWL:     true,
			wantReason: "reverse_proxy_upstream",
		},
		{
			name:       "应用进程访问内网 8888 被抑制（cross-node）",
			ruleName:   "c2_high_risk_port",
			fields:     map[string]string{"exe": "/opt/app/bin/srv", "dst_ip": "10.0.0.50"},
			wantWL:     true,
			wantReason: "internal_network_connection",
		},
		{
			name:       "未知进程访问公网 4444 不抑制（保留告警）",
			ruleName:   "c2_high_risk_port",
			fields:     map[string]string{"exe": "/tmp/.x/payload", "dst_ip": "1.2.3.4"},
			wantWL:     false,
			wantReason: "",
		},
		{
			name:       "矿池端口访问内网被抑制",
			ruleName:   "cryptominer_pool_port",
			fields:     map[string]string{"exe": "/opt/app/x", "dst_ip": "172.16.5.5"},
			wantWL:     true,
			wantReason: "internal_network_connection",
		},
		{
			name:       "矿池端口访问公网不抑制",
			ruleName:   "cryptominer_pool_port",
			fields:     map[string]string{"exe": "/tmp/xmrig", "dst_ip": "203.0.113.5"},
			wantWL:     false,
			wantReason: "",
		},
		{
			name:       "IRC 端口内网通信被抑制",
			ruleName:   "c2_irc_connect",
			fields:     map[string]string{"exe": "/opt/chat/bin/server", "dst_ip": "192.168.1.10"},
			wantWL:     true,
			wantReason: "internal_network_connection",
		},
		{
			name:       "其他规则（非 C2/cryptominer）不受白名单影响",
			ruleName:   "reverse_shell_bash",
			fields:     map[string]string{"exe": "/usr/sbin/nginx", "dst_ip": "10.0.0.1"},
			wantWL:     false,
			wantReason: "",
		},
		{
			name:       "IPv6 回环也算 private",
			ruleName:   "c2_high_risk_port",
			fields:     map[string]string{"exe": "/opt/app/x", "dst_ip": "::1"},
			wantWL:     true,
			wantReason: "internal_network_connection",
		},
		{
			name:       "remote_addr 字段也被识别（agent ebpf 用 remote_addr）",
			ruleName:   "c2_high_risk_port",
			fields:     map[string]string{"exe": "/opt/app/x", "remote_addr": "10.0.0.1"},
			wantWL:     true,
			wantReason: "internal_network_connection",
		},
		{
			name:       "nil rule 不抑制（防御性）",
			ruleName:   "",
			fields:     map[string]string{},
			wantWL:     false,
			wantReason: "",
		},
		{
			name:         "agent ebpf 用 comm 字段（无 exe）也能命中反代白名单",
			ruleName:     "高危端口外连",
			ruleCategory: "c2_communication",
			fields:       map[string]string{"comm": "nginx", "remote_addr": "10.0.0.50"},
			wantWL:       true,
			// 反代规则 + 内网 IP 都满足，匹配第一条 c2_communication+exe
			wantReason: "reverse_proxy_upstream",
		},
		{
			name:       "fork bomb 规则 + sshd-session 被抑制（每连接子进程,非失控派生）",
			ruleName:   "进程异常 - 同 ppid 高频 fork (fork bomb 嫌疑)",
			fields:     map[string]string{"comm": "sshd-session"},
			wantWL:     true,
			wantReason: "benign_high_fork_process",
		},
		{
			name:       "fork 规则 + systemctl 轮询被抑制",
			ruleName:   "进程异常 - 同 ppid 高频 fork (fork bomb 嫌疑)",
			fields:     map[string]string{"exe": "/usr/bin/systemctl"},
			wantWL:     true,
			wantReason: "benign_high_fork_process",
		},
		{
			name:     "fork 规则 + 未知进程不抑制（保留真 fork bomb）",
			ruleName: "进程异常 - 同 ppid 高频 fork (fork bomb 嫌疑)",
			fields:   map[string]string{"comm": "bash"},
			wantWL:   false,
		},
		{
			name:       "反弹 Shell 规则 + runc 容器运行时被抑制",
			ruleName:   "反弹 Shell - nc/ncat",
			fields:     map[string]string{"comm": "runc"},
			wantWL:     true,
			wantReason: "container_runtime_or_dns_anchor",
		},
		{
			name:     "反弹 Shell 规则 + bash 不抑制（保留真反弹 shell）",
			ruleName: "反弹 Shell - nc/ncat",
			fields:   map[string]string{"comm": "bash"},
			wantWL:   false,
		},
		// ===== H2 系统/云进程默认白名单 =====
		{
			name:         "ld.so 劫持 + dracut 临时目录 file_path 被抑制",
			ruleName:     "动态链接劫持 - ld.so.preload",
			ruleCategory: "defense_evasion",
			fields:       map[string]string{"comm": "rm", "file_path": "/var/tmp/dracut.hMphBL/initramfs/etc/ld.so.conf"},
			wantWL:       true,
			wantReason:   "dracut_initramfs_rebuild",
		},
		{
			name:         "memfd 执行 + runc init 被抑制",
			ruleName:     "执行 - memfd_create 文件落地",
			ruleCategory: "defense_evasion",
			fields:       map[string]string{"comm": "6", "cmdline": "runc init"},
			wantWL:       true,
			wantReason:   "container_runtime_or_systemd_exec",
		},
		{
			name:         "内核模块修改 + dnf-automatic 自动更新被抑制",
			ruleName:     "内核模块配置修改",
			ruleCategory: "persistence",
			fields:       map[string]string{"comm": "dnf-automatic"},
			wantWL:       true,
			wantReason:   "auto_update",
		},
		{
			name:         "真实 ld.so 劫持（非 dracut 路径）不抑制",
			ruleName:     "动态链接劫持 - ld.so.preload",
			ruleCategory: "defense_evasion",
			fields:       map[string]string{"comm": "curl", "file_path": "/etc/ld.so.preload"},
			wantWL:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rule *model.DetectionRule
			if tc.ruleName != "" || tc.ruleCategory != "" {
				rule = &model.DetectionRule{Name: tc.ruleName, Category: tc.ruleCategory}
			}
			got, reason := IsAlertWhitelisted(rule, tc.fields)
			if got != tc.wantWL {
				t.Fatalf("whitelisted = %v want %v", got, tc.wantWL)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestIpIsPrivate(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.0.0.50", "172.16.5.5", "172.31.255.255",
		"192.168.1.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1",
	}
	public := []string{
		"8.8.8.8", "1.1.1.1", "203.0.113.5", "2001:db8::1",
	}
	for _, ip := range private {
		if !ipIsPrivate(ip) {
			t.Errorf("expected %q to be private", ip)
		}
	}
	for _, ip := range public {
		if ipIsPrivate(ip) {
			t.Errorf("expected %q to be public", ip)
		}
	}
}

func TestExeBasenameMatch(t *testing.T) {
	list := []string{"nginx", "httpd"}
	cases := map[string]bool{
		"/usr/sbin/nginx":         true,
		"/usr/local/sbin/nginx":   true,
		"/usr/sbin/httpd":         true,
		"/usr/sbin/NGINX":         true, // 大小写不敏感
		"/usr/local/bin/envoy":    false,
		"":                        false,
		"/sbin/nginx-custom-edge": false, // basename != "nginx"
	}
	for exe, want := range cases {
		if got := exeBasenameMatch(exe, list); got != want {
			t.Errorf("exe=%q got=%v want=%v", exe, got, want)
		}
	}
}
