package osfamily

import "testing"

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
