package advisory

import (
	"testing"
	"time"
)

// TestAdvisoryMessageRoundTrip 验证 Kafka wire 契约：富 advisory（含 AffectedPkgs
// NEVRA/fixed_version + OS gate）经 Marshal → Unmarshal 后匹配关键字段无损。
// 这是 VulnSync producer 与 Manager consumer 之间的契约红线：字段丢失 = 漏报。
func TestAdvisoryMessageRoundTrip(t *testing.T) {
	issued := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	orig := AdvisoryMessage{
		Source:     "rhsa",
		Confidence: ConfidenceHigh,
		Advisory: &Advisory{
			AdvisoryID:   "RHSA-2024:1234",
			CVEIDs:       []string{"CVE-2024-0001", "CVE-2024-0002"},
			Severity:     SeverityHigh,
			CVSSScore:    7.5,
			CVSSVector:   "CVSS:3.1/AV:N/AC:L",
			Description:  "openssl flaw",
			ReferenceURL: "https://access.redhat.com/errata/RHSA-2024:1234",
			IssuedAt:     issued,
			UpdatedAt:    issued,
			OSFamily:     "rhel",
			OSMajorVer:   "9",
			AffectedPkgs: []PkgFix{
				{Name: "openssl-libs", Arch: "x86_64", FixedVersion: "1:3.5.5-1.el9_4"},
				{Name: "openssl", Arch: "noarch", FixedVersion: "1:3.5.5-1.el9_4", Module: "perl:5.32"},
			},
		},
	}

	body, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := UnmarshalAdvisoryMessage(body)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Source != "rhsa" {
		t.Errorf("Source = %q, want rhsa", got.Source)
	}
	if got.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", got.Confidence)
	}
	if got.Advisory == nil {
		t.Fatal("Advisory is nil after round-trip")
	}
	if got.Advisory.AdvisoryID != orig.Advisory.AdvisoryID {
		t.Errorf("AdvisoryID = %q, want %q", got.Advisory.AdvisoryID, orig.Advisory.AdvisoryID)
	}
	// OS gate 必须存活，否则 matcher 无法过滤主机
	if got.Advisory.OSFamily != "rhel" || got.Advisory.OSMajorVer != "9" {
		t.Errorf("OS gate lost: family=%q major=%q", got.Advisory.OSFamily, got.Advisory.OSMajorVer)
	}
	// 匹配核心：AffectedPkgs 的 NEVRA fixed_version 必须存活
	if len(got.Advisory.AffectedPkgs) != 2 {
		t.Fatalf("AffectedPkgs len = %d, want 2", len(got.Advisory.AffectedPkgs))
	}
	p0 := got.Advisory.AffectedPkgs[0]
	if p0.Name != "openssl-libs" || p0.Arch != "x86_64" || p0.FixedVersion != "1:3.5.5-1.el9_4" {
		t.Errorf("PkgFix[0] lost fidelity: %+v", p0)
	}
	if len(got.Advisory.CVEIDs) != 2 || got.Advisory.CVEIDs[0] != "CVE-2024-0001" {
		t.Errorf("CVEIDs lost: %v", got.Advisory.CVEIDs)
	}
}

// TestAdvisoryMessagePartitionKey 验证分区键格式 source:advisory_id，
// 保证同源同 advisory 的更新落同一分区、顺序一致。
func TestAdvisoryMessagePartitionKey(t *testing.T) {
	m := AdvisoryMessage{Source: "usn", Advisory: &Advisory{AdvisoryID: "USN-7890-1"}}
	if got := m.PartitionKey(); got != "usn:USN-7890-1" {
		t.Errorf("PartitionKey = %q, want usn:USN-7890-1", got)
	}
}
