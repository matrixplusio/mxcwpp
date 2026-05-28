package biz

import "testing"

func TestFixedVersionValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0", false},
		{"  0  ", false},
		{"unknown", false},
		{"UNKNOWN", false},
		{"-", false},
		{"any", false},
		{"n/a", false},
		{"none", false},
		{"null", false},
		{"1.2.3", true},
		{"6.12.85-1", true},
		{"6.1.170-1~deb11u1", true},
		{"4.11.0-9.el9_4", true},
	}
	for _, c := range cases {
		if got := fixedVersionValid(c.in); got != c.want {
			t.Errorf("fixedVersionValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestVulnApplicableToHost(t *testing.T) {
	cases := []struct {
		source, os string
		want       bool
	}{
		// OS-specific source 必须匹配
		{"debian-tracker", "centos", false}, // 主案例：触发 prod 78 个失败
		{"debian-tracker", "rhel", false},
		{"debian-tracker", "debian", true},
		{"usn", "centos", false},
		{"usn", "ubuntu", true},
		{"rhsa", "ubuntu", false},
		{"rhsa", "centos", true},
		{"rhsa", "rocky", true},
		{"rhsa", "almalinux", true},
		{"rhsa", "oracle", true},
		{"rhsa", "debian", false},
		{"rocky-apollo", "rhel", false},
		{"rocky-apollo", "rocky", true},
		{"alpine", "centos", false},
		{"alpine", "alpine", true},
		// 通用源（无 OS scope）一律放行
		{"mitre-cve", "centos", true},
		{"nvd", "ubuntu", true},
		{"osv", "alpine", true},
		{"cisa-kev", "rhel", true},
		{"exploit-db", "debian", true},
		{"cnnvd", "centos", true},
		{"cnvd", "ubuntu", true},
		{"", "centos", true}, // source 缺失视为通用
		// case-insensitive
		{"DEBIAN-TRACKER", "CentOS", false},
		{"USN", "Ubuntu", true},
	}
	for _, c := range cases {
		if got := VulnApplicableToHost(c.source, c.os); got != c.want {
			t.Errorf("VulnApplicableToHost(%q, %q) = %v, want %v", c.source, c.os, got, c.want)
		}
	}
}
