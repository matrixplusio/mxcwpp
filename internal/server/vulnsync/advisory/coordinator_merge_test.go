package advisory

import (
	"testing"
)

// 主测：同 CVE 在 RHSA(rhel,10) 和 Rocky(rocky,9) 各自 match 不同 host 时，
// 旧实现 affectedHosts 会被覆盖，新实现并集保留。
func TestMergeByConfidence_UnionAffectedHostsAcrossOSSources(t *testing.T) {
	cve := "CVE-2026-99999"

	rhsaAdv := &Advisory{
		AdvisoryID:   "RHSA-2026:1234",
		CVEIDs:       []string{cve},
		OSFamily:     "rhel",
		OSMajorVer:   "10",
		AffectedPkgs: []PkgFix{{Name: "openssl", FixedVersion: "1:3.5.1-7.el10_1"}},
	}
	rockyAdv := &Advisory{
		AdvisoryID:   "RLSA-2026:1234",
		CVEIDs:       []string{cve},
		OSFamily:     "rocky",
		OSMajorVer:   "9",
		AffectedPkgs: []PkgFix{{Name: "openssl", FixedVersion: "1:3.5.1-7.el9_7"}},
	}

	rhel10Host := HostSoftware{
		HostID: "host-rhel10", OSFamily: "rhel", OSMajor: "10",
		PkgName: "openssl", PkgEpoch: "1", PkgVerRaw: "3.5.1", PkgRelease: "3.el10_1",
		PkgManager: "rpm",
	}
	rocky9Host := HostSoftware{
		HostID: "host-rocky9", OSFamily: "rocky", OSMajor: "9",
		PkgName: "openssl", PkgEpoch: "1", PkgVerRaw: "3.5.1", PkgRelease: "3.el9",
		PkgManager: "rpm",
	}

	items := []sourcedAdvisory{
		{sourceName: "rhsa", advisory: rhsaAdv, confidence: ConfidenceHigh},
		{sourceName: "rocky-apollo", advisory: rockyAdv, confidence: ConfidenceHigh},
	}
	merged := mergeByConfidence(items, &DefaultMatcher{}, []HostSoftware{rhel10Host, rocky9Host})

	mv, ok := merged[cve]
	if !ok {
		t.Fatalf("CVE %s not in merged map", cve)
	}
	if len(mv.affectedHosts) < 2 {
		t.Fatalf("expected affectedHosts union of 2 hosts, got %d: %+v",
			len(mv.affectedHosts), mv.affectedHosts)
	}
	hostsHit := map[string]bool{}
	for _, a := range mv.affectedHosts {
		hostsHit[a.HostID] = true
	}
	if !hostsHit["host-rhel10"] || !hostsHit["host-rocky9"] {
		t.Errorf("expected both hosts in affectedHosts, got: %v", hostsHit)
	}
	// allAdvisories 应保留两个 source 的 advisory（供 upsertAdvisoryPackages 写）
	if len(mv.allAdvisories) != 2 {
		t.Errorf("expected 2 allAdvisories (RHSA + Rocky), got %d", len(mv.allAdvisories))
	}
}

// 边界：同 source 同 advisory 重复条目时 affectedHosts 去重
func TestMergeByConfidence_DedupSameHostSameCVE(t *testing.T) {
	cve := "CVE-2026-88888"
	adv := &Advisory{
		AdvisoryID:   "RHSA-2026:9999",
		CVEIDs:       []string{cve},
		OSFamily:     "rhel",
		OSMajorVer:   "9",
		AffectedPkgs: []PkgFix{{Name: "kernel", FixedVersion: "0:5.14.0-700.el9_8"}},
	}
	host := HostSoftware{
		HostID: "host-x", OSFamily: "rocky", OSMajor: "9",
		PkgName: "kernel", PkgEpoch: "0", PkgVerRaw: "5.14.0", PkgRelease: "596.el9",
		PkgManager: "rpm",
	}
	items := []sourcedAdvisory{
		{sourceName: "rhsa", advisory: adv, confidence: ConfidenceHigh},
		{sourceName: "rhsa", advisory: adv, confidence: ConfidenceHigh}, // 重复
	}
	merged := mergeByConfidence(items, &DefaultMatcher{}, []HostSoftware{host})
	mv := merged[cve]
	if mv == nil {
		t.Fatal("merged nil")
	}
	if len(mv.affectedHosts) != 1 {
		t.Errorf("expected dedup to 1 host, got %d", len(mv.affectedHosts))
	}
}

func TestDedupAffectedHosts(t *testing.T) {
	in := []AffectedHost{
		{HostID: "h1", PkgName: "openssl"},
		{HostID: "h1", PkgName: "openssl"},
		{HostID: "h1", PkgName: "kernel"},
		{HostID: "h2", PkgName: "openssl"},
	}
	out := dedupAffectedHosts(in)
	if len(out) != 3 {
		t.Errorf("expected 3, got %d: %+v", len(out), out)
	}
}

// 选 metadata 时必须看该 advisory 是否真的覆盖了匹配到的主机。
//
// CVE 的 source 与 fixed_version 是 CVE 级的塌缩值。此前只按 confidence 挑赢家，
// 完全不看这条 advisory 有没有匹配到任何主机——于是一条对本环境毫不相关的
// debian advisory，只要 confidence 不低于 rpm 那条，就能把 rpm 主机的修复版本
// 标成 deb 的版本。
//
// 曾出现 debian 标签挂在 rpm 主机上，运维照着修根本修不掉。
func TestMergeByConfidence_PrefersAdvisoryCoveringMatchedHosts(t *testing.T) {
	cve := "CVE-2026-88888"

	// 该环境里只有 rocky 主机
	rockyHost := HostSoftware{
		HostID: "host-rocky9", OSFamily: "rocky", OSMajor: "9",
		PkgName: "openssl", PkgEpoch: "1", PkgVerRaw: "3.5.1", PkgRelease: "3.el9",
		PkgManager: "rpm",
	}

	// debian advisory：同 confidence，但匹配不到本环境任何主机
	debAdv := &Advisory{
		AdvisoryID:   "DSA-2026-1",
		CVEIDs:       []string{cve},
		OSFamily:     "debian",
		OSMajorVer:   "12",
		AffectedPkgs: []PkgFix{{Name: "openssl", FixedVersion: "3.0.11-1~deb12u2"}},
	}
	// rocky advisory：匹配到了主机
	rockyAdv := &Advisory{
		AdvisoryID:   "RLSA-2026:8888",
		CVEIDs:       []string{cve},
		OSFamily:     "rocky",
		OSMajorVer:   "9",
		AffectedPkgs: []PkgFix{{Name: "openssl", FixedVersion: "1:3.5.1-7.el9_7"}},
	}

	// debian 排在前面（同 confidence 时顺序即胜负），复现最坏情况
	items := []sourcedAdvisory{
		{sourceName: "debian", advisory: debAdv, confidence: ConfidenceHigh},
		{sourceName: "rocky-apollo", advisory: rockyAdv, confidence: ConfidenceHigh},
	}
	merged := mergeByConfidence(items, &DefaultMatcher{}, []HostSoftware{rockyHost})

	mv, ok := merged[cve]
	if !ok {
		t.Fatalf("CVE %s 不在合并结果里", cve)
	}
	if mv.source == "debian" {
		t.Fatalf("选中了 debian advisory，但它匹配不到本环境任何主机；"+
			"rocky 主机会被标上 deb 的修复版本 %q，照着修根本修不掉",
			debAdv.AffectedPkgs[0].FixedVersion)
	}
	if mv.source != "rocky-apollo" {
		t.Fatalf("应选中覆盖了匹配主机的 rocky advisory，实际 source=%q", mv.source)
	}
	if got := mv.advisory.AffectedPkgs[0].FixedVersion; got != "1:3.5.1-7.el9_7" {
		t.Fatalf("fixed_version 应取 rocky 的 el9 版本，实际 %q", got)
	}
}

// 都没匹配到主机时退回原有的 confidence 规则。
//
// 没有覆盖信息可用时不该凭空改变行为——那只会把一个确定的选择换成另一个。
func TestMergeByConfidence_FallsBackToConfidenceWhenNoCoverage(t *testing.T) {
	cve := "CVE-2026-77777"
	// 环境里没有任何相关主机
	var noHosts []HostSoftware

	low := &Advisory{
		AdvisoryID: "NVD-1", CVEIDs: []string{cve}, OSFamily: "debian", OSMajorVer: "12",
		AffectedPkgs: []PkgFix{{Name: "openssl", FixedVersion: "1.0"}},
	}
	high := &Advisory{
		AdvisoryID: "RLSA-1", CVEIDs: []string{cve}, OSFamily: "rocky", OSMajorVer: "9",
		AffectedPkgs: []PkgFix{{Name: "openssl", FixedVersion: "2.0"}},
	}
	items := []sourcedAdvisory{
		{sourceName: "nvd", advisory: low, confidence: ConfidenceLow},
		{sourceName: "rocky-apollo", advisory: high, confidence: ConfidenceHigh},
	}
	merged := mergeByConfidence(items, &DefaultMatcher{}, noHosts)

	mv := merged[cve]
	if mv == nil {
		t.Fatal("CVE 不在合并结果里")
	}
	if mv.source != "rocky-apollo" {
		t.Fatalf("无覆盖信息时应按 confidence 选高者，实际 source=%q", mv.source)
	}
}
