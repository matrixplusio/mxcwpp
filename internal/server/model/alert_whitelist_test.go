package model

import "testing"

func TestAlertWhitelistMatchesAlert(t *testing.T) {
	fields := map[string]string{
		"exe":     "/usr/local/bin/node_exporter",
		"cmdline": "/usr/local/bin/node_exporter --collector.textfile",
	}
	cases := []struct {
		name string
		wl   AlertWhitelist
		want bool
	}{
		{
			name: "exe basename 命中",
			wl:   AlertWhitelist{RuleID: "cel-1", Exe: "node_exporter"},
			want: true,
		},
		{
			name: "exe 写完整路径时按路径精确匹配",
			wl:   AlertWhitelist{RuleID: "cel-1", Exe: "/usr/local/bin/node_exporter"},
			want: true,
		},
		{
			// 同名程序放在别的目录：按程序名豁免会被借用，写了路径的不能被借用。
			name: "exe 路径不同即使同名也不命中",
			wl:   AlertWhitelist{RuleID: "cel-1", Exe: "/opt/node_exporter"},
			want: false,
		},
		{
			name: "exe 不符不命中",
			wl:   AlertWhitelist{RuleID: "cel-1", Exe: "nginx"},
			want: false,
		},
		{
			name: "cmdline 子串命中",
			wl:   AlertWhitelist{RuleID: "cel-1", Cmdline: "collector.textfile"},
			want: true,
		},
		{
			name: "exe + cmdline 同时约束，cmdline 不符则不命中",
			wl:   AlertWhitelist{RuleID: "cel-1", Exe: "node_exporter", Cmdline: "not-present"},
			want: false,
		},
		{
			name: "rule_id 不符不命中",
			wl:   AlertWhitelist{RuleID: "cel-999", Exe: "node_exporter"},
			want: false,
		},
		{
			name: "全通配(无具体收窄)拒绝匹配，防误抑制",
			wl:   AlertWhitelist{RuleID: "cel-1"},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.wl.MatchesAlert("cel-1", "host-a", "cryptomining", "high", fields)
			if got != c.want {
				t.Fatalf("MatchesAlert = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAlertWhitelistScopeProblem(t *testing.T) {
	cases := []struct {
		name string
		wl   AlertWhitelist
		ok   bool
	}{
		{"只写程序名不行", AlertWhitelist{RuleID: "cel-1", Exe: "bash"}, false},
		{"限定主机也不能只写程序名", AlertWhitelist{RuleID: "cel-1", HostID: "h1", Exe: "bash"}, false},
		{"完整路径可以", AlertWhitelist{RuleID: "cel-1", Exe: "/usr/bin/dnf"}, true},
		{"全部主机只写命令行不行：可被借用", AlertWhitelist{RuleID: "cel-1", Cmdline: "--collector.textfile"}, false},
		{"限定主机后只写命令行可以", AlertWhitelist{RuleID: "cel-1", HostID: "h1", Cmdline: "--collector.textfile"}, true},
		{"完整路径加命令行可以", AlertWhitelist{RuleID: "cel-1", Exe: "/usr/local/bin/node_exporter", Cmdline: "--collector.textfile"}, true},
		{"全部主机不指定规则不行", AlertWhitelist{Exe: "/usr/bin/bash"}, false},
		{"限定主机也不能不指定规则就豁免进程", AlertWhitelist{HostID: "h1", Exe: "/usr/bin/bash"}, false},
		{"限定主机、不写进程的整机豁免照旧允许", AlertWhitelist{HostID: "h1", Severity: "medium"}, true},
		{"限定主机可以", AlertWhitelist{RuleID: "cel-1", HostID: "h1"}, true},
		{"只按来源网段可以（扫描探测类）", AlertWhitelist{RuleID: "scan-probe", SourceIPCIDR: "10.0.0.0/24"}, true},
		{"什么都没限定不行", AlertWhitelist{RuleID: "cel-1", Category: "x"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.wl.ScopeProblem() == ""; got != c.ok {
				t.Fatalf("ScopeProblem() 通过=%v，期望 %v（%q）", got, c.ok, c.wl.ScopeProblem())
			}
		})
	}
}

func TestAlertWhitelistConflictsWithRule(t *testing.T) {
	const logClear = `(cmdline.contains(">/dev/null") || cmdline.contains("history -c")) && exe.contains("bash")`
	cases := []struct {
		name string
		wl   AlertWhitelist
		expr string
		want bool
	}{
		// 规则要求进程是 bash，豁免又写进程是 bash，规则整体失效。
		{"豁免的进程正是规则要求的进程", AlertWhitelist{Exe: "bash"}, logClear, true},
		{"写成路径也一样", AlertWhitelist{Exe: "/usr/bin/bash"}, logClear, true},
		{"再约束了命令行就不算抵消", AlertWhitelist{Exe: "/usr/bin/bash", Cmdline: "/opt/backup.sh"}, logClear, false},
		{"限定了主机就不算抵消", AlertWhitelist{Exe: "/usr/bin/bash", HostID: "h1"}, logClear, false},
		{"无关的进程", AlertWhitelist{Exe: "/usr/bin/dnf"}, logClear, false},
		// 解释器的真实路径带版本号：豁免 python3.9 等于停用 python 反弹 shell 检测。
		{"带版本号的同名程序", AlertWhitelist{Exe: "/usr/bin/python3.9"}, `exe.contains("python") && cmdline.contains("socket")`, true},
		{"名字以字面量开头但不是版本号", AlertWhitelist{Exe: "/usr/bin/pythonista"}, `exe.contains("python")`, false},
		{"规则用 == 判断", AlertWhitelist{Exe: "/usr/bin/nc"}, `comm == "nc" && cmdline.contains(" -e ")`, true},
		{"取反的判断是规则自己排除的进程", AlertWhitelist{Exe: "/usr/lib/systemd/systemd"}, `!exe.contains("systemd") && file_path.startsWith("/etc/")`, false},
		// 包管理器写在取反的括号组里，是规则自己排除的。
		{"取反括号组里的进程", AlertWhitelist{Exe: "rpm"},
			`file_path.contains("/etc/init.d/") && !(exe.contains("dpkg") || exe.contains("rpm") || exe.contains("yum"))`, false},
		{"双重取反等于没取反", AlertWhitelist{Exe: "rpm"}, `!(!(exe.contains("rpm")))`, true},
		{"引号里的括号不影响判断", AlertWhitelist{Exe: "bash"}, `cmdline.contains("!(") && exe.contains("bash")`, true},
		{"没写进程不判", AlertWhitelist{Cmdline: "history -c"}, logClear, false},
		// 规则按子串命中了一个无关程序，豁免这个程序只是排除误命中，不抵消规则。
		{"名字里碰巧含规则字面量的程序", AlertWhitelist{Exe: "sssd"}, `exe.contains("ss") && cmdline.contains("-tunlp")`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.wl.ConflictsWithRule(c.expr); got != c.want {
				t.Fatalf("ConflictsWithRule = %v，期望 %v", got, c.want)
			}
		})
	}
}
