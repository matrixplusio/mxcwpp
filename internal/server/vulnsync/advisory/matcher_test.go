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

// TestDefaultMatcher_PerHostMatchedPkg 锁定：多包 advisory 下，AffectedHost 的 PkgName/FixedVersion
// 必须是**该主机实际装的那个包**及其修复版本，而非 advisory 里任意第一个包/异 OS-major 版本。
// 这是 host_vulnerabilities.matched_component/matched_fixed_version 正确性的根基——避免 CVE 级
// 塌缩（如 glibc CVE 塌成 glibc-langpack-el/el10）导致 cleanup 误删。
func TestDefaultMatcher_PerHostMatchedPkg(t *testing.T) {
	adv := &Advisory{
		OSFamily:   "rocky",
		OSMajorVer: "9",
		AffectedPkgs: []PkgFix{
			// advisory 第一个包是主机没装的 langpack（模拟塌缩误取）
			{Name: "glibc-langpack-el", Arch: "x86_64", FixedVersion: "0:2.34-270.el9_8"},
			{Name: "glibc", Arch: "x86_64", FixedVersion: "0:2.34-270.el9_8"},
		},
	}
	hosts := []HostSoftware{
		{HostID: "h1", OSFamily: "centos", OSMajor: "9", PkgName: "glibc",
			PkgArch: "x86_64", PkgVer: "2.34-270.el9"}, // 只装 glibc，没装 langpack-el
	}
	out := (&DefaultMatcher{}).Match(adv, hosts)
	if len(out) != 1 {
		t.Fatalf("expected 1 match (glibc only), got %d: %+v", len(out), out)
	}
	if out[0].PkgName != "glibc" {
		t.Errorf("matched PkgName should be host's real pkg 'glibc', got %q", out[0].PkgName)
	}
	if out[0].FixedVersion != "0:2.34-270.el9_8" || !out[0].NeedsUpdate {
		t.Errorf("expected el9 fixed_version + NeedsUpdate, got %+v", out[0])
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

func TestDefaultMatcher_EcosystemGate(t *testing.T) {
	// 语言包 advisory（如 OSV/GHSA 报 npm braces）只允许匹配同 ecosystem 主机软件，
	// 不允许匹配 OS pkg 或其他生态包。
	adv := &Advisory{
		Ecosystem: "npm",
		AffectedPkgs: []PkgFix{
			{Name: "braces", FixedVersion: "3.0.3"},
		},
	}
	hosts := []HostSoftware{
		{HostID: "h1", PkgEcosystem: "npm", PkgName: "braces", PkgVer: "1.8.5"},  // 受影响
		{HostID: "h2", PkgEcosystem: "PyPI", PkgName: "braces", PkgVer: "1.0.0"}, // 跨生态，必拒
		{HostID: "h3", PkgEcosystem: "", OSFamily: "centos", OSMajor: "9",
			PkgName: "braces", PkgVer: "1.8.5"}, // OS pkg 同名，必拒
	}
	m := &DefaultMatcher{}
	out := m.Match(adv, hosts)
	if len(out) != 1 || out[0].HostID != "h1" {
		t.Fatalf("ecosystem gate fail: expected only h1, got %+v", out)
	}
}

func TestDefaultMatcher_RejectDoubleEmptyGate(t *testing.T) {
	// advisory 既无 OSFamily 也无 Ecosystem → 无法 gate，全部拒绝。
	adv := &Advisory{
		AffectedPkgs: []PkgFix{
			{Name: "openssl", FixedVersion: "3.5.5"},
		},
	}
	hosts := []HostSoftware{
		{HostID: "h1", OSFamily: "centos", OSMajor: "9", PkgName: "openssl", PkgVer: "3.0.0"},
		{HostID: "h2", PkgEcosystem: "npm", PkgName: "openssl", PkgVer: "3.0.0"},
	}
	m := &DefaultMatcher{}
	out := m.Match(adv, hosts)
	if len(out) != 0 {
		t.Fatalf("双空 gate advisory 应全拒，got %+v", out)
	}
}

func TestDefaultMatcher_RejectMixedGate(t *testing.T) {
	// advisory 同时声明 Ecosystem 与 OSFamily（数据异常）→ 全部拒绝。
	adv := &Advisory{
		OSFamily:   "rhel",
		OSMajorVer: "9",
		Ecosystem:  "npm",
		AffectedPkgs: []PkgFix{
			{Name: "x", FixedVersion: "1"},
		},
	}
	hosts := []HostSoftware{
		{HostID: "h1", OSFamily: "centos", OSMajor: "9", PkgName: "x", PkgVer: "0"},
		{HostID: "h2", PkgEcosystem: "npm", PkgName: "x", PkgVer: "0"},
	}
	m := &DefaultMatcher{}
	out := m.Match(adv, hosts)
	if len(out) != 0 {
		t.Fatalf("混合 gate advisory 应全拒，got %+v", out)
	}
}

func TestDefaultMatcher_NEVRAEpochOverridesVersion(t *testing.T) {
	// 回归 prod 残留:libpng 1.6.37 vs fix 2:1.0.14-11
	// 不带 epoch 字符串比对会被 epoch 翻转：installed 1.6.37 > 1.0.14 但 epoch 0 < 2，
	// NEVRA 严格比较会认 fix > installed → host needs update。
	// 这是 RHEL/Rocky 实际语义。
	adv := &Advisory{
		OSFamily:   "rhel",
		OSMajorVer: "9",
		AffectedPkgs: []PkgFix{
			{Name: "libpng", Arch: "x86_64", FixedVersion: "2:1.0.14-11"},
		},
	}
	hosts := []HostSoftware{
		// host pkg epoch=0 但 version 1.6.37 大于 fix epoch=2 的 version 1.0.14。
		// 旧字符串比对(PkgVer="1.6.37") 错认 host 已超新；NEVRA 比对认 epoch 主导。
		{HostID: "h1", OSFamily: "rocky", OSMajor: "9", PkgName: "libpng",
			PkgArch: "x86_64", PkgEpoch: "0", PkgVerRaw: "1.6.37", PkgRelease: "1.el9"},
	}
	m := &DefaultMatcher{}
	out := m.Match(adv, hosts)
	if len(out) != 1 {
		t.Fatalf("expected 1 match, got %d", len(out))
	}
	if !out[0].NeedsUpdate {
		t.Errorf("NEVRA epoch 0<2 应判 needs update，实测 %+v", out[0])
	}
}

func TestDefaultMatcher_NEVRAFallback(t *testing.T) {
	// 缺 NEVRA 字段时退回 PkgVer 字符串。
	adv := &Advisory{
		OSFamily:   "rhel",
		OSMajorVer: "9",
		AffectedPkgs: []PkgFix{
			{Name: "openssl", Arch: "x86_64", FixedVersion: "1:3.5.5-1.el9_4"},
		},
	}
	hosts := []HostSoftware{
		// 旧 collector 数据：PkgVer="3.5.1-3.el9"，无 PkgEpoch/PkgVerRaw/PkgRelease
		{HostID: "h1", OSFamily: "rocky", OSMajor: "9", PkgName: "openssl",
			PkgArch: "x86_64", PkgVer: "3.5.1-3.el9"},
	}
	m := &DefaultMatcher{}
	out := m.Match(adv, hosts)
	if len(out) != 1 || !out[0].NeedsUpdate {
		t.Errorf("fallback 应判 needs update，实测 %+v", out)
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
