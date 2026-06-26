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
			name: "exe 全路径也按 basename 匹配",
			wl:   AlertWhitelist{RuleID: "cel-1", Exe: "/opt/node_exporter"},
			want: true,
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
