package api

import "testing"

// Oracle Linux 上报 os_family="ol"，原先落到兜底分支：8+ 也按 yum 下发。
func TestDetectPackageManager_OracleLinux(t *testing.T) {
	cases := []struct{ family, version, want string }{
		{"ol", "9.4", "rpm-dnf"},
		{"ol", "7.9", "rpm-yum"},
		{"oracle", "8.10", "rpm-dnf"},
	}
	for _, c := range cases {
		if got := detectPackageManager(c.family, c.version); got != c.want {
			t.Errorf("detectPackageManager(%q, %q) = %q, want %q", c.family, c.version, got, c.want)
		}
	}
}
