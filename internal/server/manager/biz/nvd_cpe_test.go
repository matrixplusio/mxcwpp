package biz

import "testing"

func TestParseCPE23(t *testing.T) {
	cases := []struct {
		name   string
		cpe    string
		part   string
		vendor string
		prod   string
		ver    string
		tgtSW  string
	}{
		{
			name: "openssl_linux",
			cpe:  "cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:linux:*:*",
			part: "a", vendor: "openssl", prod: "openssl", ver: "3.5.1", tgtSW: "linux",
		},
		{
			name: "rapid7_windows",
			cpe:  "cpe:2.3:a:rapid7:insight_agent:4.1.0.2:*:*:*:*:windows:*:*",
			part: "a", vendor: "rapid7", prod: "insight_agent", ver: "4.1.0.2", tgtSW: "windows",
		},
		{
			name: "wildcard_target_sw",
			cpe:  "cpe:2.3:a:gnu:glibc:2.34:*:*:*:*:*:*:*",
			part: "a", vendor: "gnu", prod: "glibc", ver: "2.34", tgtSW: "*",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCPE23(tc.cpe)
			if got == nil {
				t.Fatalf("parse 失败")
			}
			if got.part != tc.part || got.vendor != tc.vendor ||
				got.product != tc.prod || got.version != tc.ver || got.targetSW != tc.tgtSW {
				t.Errorf("got %+v", got)
			}
		})
	}
}

// 回归 CVE-2026-6482：Rapid7 Insight Agent Windows-only CVE 必须被 CPE target_sw 过滤拒绝。
func TestCPETargetSWLinuxCompatible(t *testing.T) {
	cases := []struct {
		targetSW string
		want     bool
	}{
		{"linux", true},
		{"linux_kernel", true},
		{"*", true},
		{"", true},
		{"windows", false},
		{"windows_10", false},
		{"windows_server_2019", false},
		{"macos", false},
		{"mac_os_x", false},
		{"android", false},
		{"ios", false},
	}
	for _, tc := range cases {
		got := cpeTargetSWLinuxCompatible(tc.targetSW)
		if got != tc.want {
			t.Errorf("cpeTargetSWLinuxCompatible(%q) = %v, want %v", tc.targetSW, got, tc.want)
		}
	}
}

func TestCompareVerRange(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"3.5.10", "3.5.9", 1}, // 数字段不是字符串比
		{"3.5.5", "3.5.5", 0},
		{"3.5.5-1", "3.5.5-2", -1},
		{"10.0", "9.9", 1}, // 不被字符串"10"<"9"骗
		{"1.2.3", "1.2", 1},
	}
	for _, tc := range cases {
		got, err := compareVerRange(tc.a, tc.b)
		if err != nil {
			t.Errorf("err: %v", err)
			continue
		}
		if got != tc.want {
			t.Errorf("compareVerRange(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCPEVersionInRange(t *testing.T) {
	// CPE versionStartIncluding=3.0.0 versionEndExcluding=3.5.5 表达 [3.0.0, 3.5.5)
	cpe := nvdCPEMatch{
		Criteria:              "cpe:2.3:a:openssl:openssl:*:*:*:*:*:linux:*:*",
		VersionStartIncluding: "3.0.0",
		VersionEndExcluding:   "3.5.5",
	}
	cases := []struct {
		installed string
		want      bool
	}{
		{"3.0.0", true},  // 边界 incl
		{"3.5.4", true},  // 上界 excl 内
		{"3.5.5", false}, // 上界 excl
		{"2.9.9", false}, // 下界外
		{"3.5.6", false}, // 上界外
	}
	for _, tc := range cases {
		got := cpeVersionInRange(tc.installed, "*", cpe)
		if got != tc.want {
			t.Errorf("cpeVersionInRange(%q) = %v, want %v", tc.installed, got, tc.want)
		}
	}
}

func TestSplitVersionSegments(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"3.5.5", []string{"3", "5", "5"}},
		{"3.5.5-1.el9_4", []string{"3", "5", "5", "1", "el9", "4"}},
		{"1.2+rc1", []string{"1", "2", "rc1"}},
	}
	for _, tc := range cases {
		got := splitVersionSegments(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("len mismatch: %v vs %v", got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("seg[%d] %q vs %q", i, got[i], tc.want[i])
			}
		}
	}
}

func TestParseUint(t *testing.T) {
	if n, ok := parseUint("123"); !ok || n != 123 {
		t.Errorf("parseUint(123) = %d, %v", n, ok)
	}
	if _, ok := parseUint("3a"); ok {
		t.Errorf("parseUint(3a) should fail")
	}
	if _, ok := parseUint(""); ok {
		t.Errorf("parseUint('') should fail")
	}
}
