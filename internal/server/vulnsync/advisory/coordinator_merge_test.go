package advisory

import (
	"context"
	"testing"
	"time"
)

// fakeSource 不发起网络调用，仅持有名字 + confidence
type fakeSource struct {
	name string
	conf Confidence
}

func (f *fakeSource) Name() string                                              { return f.name }
func (f *fakeSource) Confidence() Confidence                                    { return f.conf }
func (f *fakeSource) Fetch(_ context.Context, _ time.Time) ([]*Advisory, error) { return nil, nil }

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
		{src: &fakeSource{name: "rhsa", conf: ConfidenceHigh}, advisory: rhsaAdv, confidence: ConfidenceHigh},
		{src: &fakeSource{name: "rocky-apollo", conf: ConfidenceHigh}, advisory: rockyAdv, confidence: ConfidenceHigh},
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
		{src: &fakeSource{name: "rhsa", conf: ConfidenceHigh}, advisory: adv, confidence: ConfidenceHigh},
		{src: &fakeSource{name: "rhsa", conf: ConfidenceHigh}, advisory: adv, confidence: ConfidenceHigh}, // 重复
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
