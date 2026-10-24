package osfamily

import (
	"strings"
	"testing"
)

func TestContains(t *testing.T) {
	policy := []string{"rocky", "centos", "oracle", "almalinux"}
	cases := []struct {
		host string
		want bool
	}{
		{"ol", true}, // Oracle Linux 的 os-release ID
		{"OracleLinux", true},
		{"oracle", true},
		{"Rocky", true},
		{"alma", true},
		{"ubuntu", false},
		{"", false},
	}
	for _, c := range cases {
		if got := Contains(policy, c.host); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	if !Contains([]string{"ol"}, "oracle") {
		t.Error("别名应双向成立")
	}
}

func TestRHELCompatible(t *testing.T) {
	for _, f := range []string{"ol", "oracle", "OracleLinux", "Oracle Linux", "rocky", "alma", "rhel", "redhat", "centos-stream"} {
		if !RHELCompatible(f) {
			t.Errorf("RHELCompatible(%q) = false", f)
		}
	}
	for _, f := range []string{"ubuntu", "debian", "fedora", "openeuler", ""} {
		if RHELCompatible(f) {
			t.Errorf("RHELCompatible(%q) = true", f)
		}
	}
}

func TestRHELCompatibleSQLListHasEverySpelling(t *testing.T) {
	list := RHELCompatibleSQLList()
	for _, f := range []string{"'ol'", "'oracle'", "'oraclelinux'", "'oracle linux'", "'rocky'", "'alma'", "'almalinux'", "'redhat'", "'rhel'"} {
		if !strings.Contains(list, f) {
			t.Errorf("SQL 列表缺 %s: %s", f, list)
		}
	}
	if strings.Contains(list, "ubuntu") {
		t.Errorf("SQL 列表不该含 ubuntu: %s", list)
	}
}
