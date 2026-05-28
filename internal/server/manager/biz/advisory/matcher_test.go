package advisory

import "testing"

func TestCompareRPMVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// 数字段按数值比较（不是字符串）
		{"3.5.10", "3.5.9", 1},
		{"3.5.5", "3.5.5", 0},
		{"3.5.1", "3.5.5", -1},

		// epoch 优先
		{"1:3.5.1", "3.5.5", 1},
		{"0:3.5.5", "3.5.5", 0},
		{"2:1.0", "1:9.9", 1},

		// release 段
		{"3.5.5-1.el9_4", "3.5.5-2.el9_4", -1},
		{"3.5.5-10.el9", "3.5.5-9.el9", 1},

		// 数字 > 字母（rpm 约定）
		{"3.5.5a", "3.5.51", -1},

		// leading zero 不影响
		{"3.005.5", "3.5.5", 0},

		// 真实 prod 案例
		{"3.5.1-3.el9", "1:3.5.5-1.el9_4", -1},
		{"1:3.5.5-1.el9_4", "1:3.5.5-1.el9_4", 0},
	}
	for _, tc := range cases {
		got, err := CompareRPMVersion(tc.a, tc.b)
		if err != nil {
			t.Errorf("CompareRPMVersion(%q,%q) err: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CompareRPMVersion(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDefaultMatcher_OSStrict(t *testing.T) {
	adv := &Advisory{
		OSFamily:   "rhel",
		OSMajorVer: "9",
		AffectedPkgs: []PkgFix{
			{Name: "openssl", Arch: "x86_64", FixedVersion: "1:3.5.5-1.el9_4"},
		},
	}
	hosts := []HostSoftware{
		{HostID: "h1", OSFamily: "rocky", OSMajor: "9", PkgName: "openssl",
			PkgArch: "x86_64", PkgVer: "3.5.1-3.el9"}, // 受影响
		{HostID: "h2", OSFamily: "ubuntu", OSMajor: "22.04", PkgName: "openssl",
			PkgArch: "x86_64", PkgVer: "3.0.0"}, // OS 不匹配，跳过
		{HostID: "h3", OSFamily: "rhel", OSMajor: "8", PkgName: "openssl",
			PkgArch: "x86_64", PkgVer: "3.0.0"}, // OS 主版本不匹配
		{HostID: "h4", OSFamily: "centos", OSMajor: "9", PkgName: "openssl",
			PkgArch: "x86_64", PkgVer: "1:3.5.5-1.el9_4"}, // 已修复
	}
	m := &DefaultMatcher{}
	out := m.Match(adv, hosts)
	if len(out) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(out))
	}
	// h1: 受影响
	if out[0].HostID != "h1" || !out[0].NeedsUpdate {
		t.Errorf("h1 should be NeedsUpdate, got %+v", out[0])
	}
	// h4: 已修复
	if out[1].HostID != "h4" || out[1].NeedsUpdate {
		t.Errorf("h4 should NOT NeedsUpdate, got %+v", out[1])
	}
}

func TestValidateAdvisory_RejectWindowsCVEOnLinuxOS(t *testing.T) {
	// 回归 CVE-2026-6482 bug：Rapid7 Insight Agent Windows 提权
	// 被错关联到 Linux openssl，描述含 "Windows host"
	adv := &Advisory{
		OSFamily:    "rhel",
		OSMajorVer:  "9",
		CVEIDs:      []string{"CVE-2026-6482"},
		Description: "Rapid7 Insight Agent vulnerable on Microsoft Windows host via openssl.cnf",
		AffectedPkgs: []PkgFix{
			{Name: "openssl", FixedVersion: "4.1.0.2"},
		},
	}
	if validateAdvisory(adv) {
		t.Error("Linux advisory 描述含 Microsoft Windows 应被拒绝")
	}
}

func TestValidateAdvisory_RejectEmptyFields(t *testing.T) {
	cases := []struct {
		name string
		adv  *Advisory
	}{
		{"nil", nil},
		{"no_cve", &Advisory{AffectedPkgs: []PkgFix{{Name: "p", FixedVersion: "1"}}}},
		{"no_pkg", &Advisory{CVEIDs: []string{"CVE-1"}}},
		{"no_fixed_ver", &Advisory{CVEIDs: []string{"CVE-1"}, AffectedPkgs: []PkgFix{{Name: "p"}}}},
		{"no_pkg_name", &Advisory{CVEIDs: []string{"CVE-1"}, AffectedPkgs: []PkgFix{{FixedVersion: "1"}}}},
	}
	for _, tc := range cases {
		if validateAdvisory(tc.adv) {
			t.Errorf("%s should be rejected", tc.name)
		}
	}
}

func TestOSCompatible(t *testing.T) {
	cases := []struct {
		advFamily, advMajor, hostFamily, hostMajor string
		want                                       bool
	}{
		{"rhel", "9", "rocky", "9", true},
		{"rhel", "9", "centos", "9", true},
		{"rhel", "9", "almalinux", "9", true},
		{"rhel", "9", "ubuntu", "9", false},
		{"rhel", "9", "rhel", "8", false},
		{"ubuntu", "22.04", "ubuntu", "22.04", true},
		{"ubuntu", "22.04", "debian", "22.04", false},
		{"", "9", "rhel", "9", false},
		{"rhel", "", "rhel", "9", false},
	}
	for _, tc := range cases {
		got := osCompatible(tc.advFamily, tc.advMajor, tc.hostFamily, tc.hostMajor)
		if got != tc.want {
			t.Errorf("osCompatible(%q,%q,%q,%q) = %v, want %v",
				tc.advFamily, tc.advMajor, tc.hostFamily, tc.hostMajor, got, tc.want)
		}
	}
}

func TestArchMatch(t *testing.T) {
	cases := []struct {
		advArch, hostArch string
		want              bool
	}{
		{"x86_64", "x86_64", true},
		{"x86_64", "aarch64", false},
		{"noarch", "x86_64", true},
		{"src", "aarch64", true},
		{"", "x86_64", true},
	}
	for _, tc := range cases {
		got := archMatch(tc.advArch, tc.hostArch)
		if got != tc.want {
			t.Errorf("archMatch(%q,%q) = %v, want %v", tc.advArch, tc.hostArch, got, tc.want)
		}
	}
}
