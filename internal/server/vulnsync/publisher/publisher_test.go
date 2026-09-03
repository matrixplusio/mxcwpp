package publisher

import (
	"context"
	"testing"

	"github.com/IBM/sarama/mocks"

	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

func TestPublisher_PublishAdvisory(t *testing.T) {
	t.Parallel()
	mp := mocks.NewSyncProducer(t, nil)
	defer mp.Close()
	mp.ExpectSendMessageAndSucceed()

	p := &Publisher{producer: mp, topic: "mxcwpp.vuln.advisory"}
	msg := advisory.AdvisoryMessage{
		Source: "rhsa",
		Advisory: &advisory.Advisory{
			AdvisoryID: "RHSA-2024:0001",
			CVEIDs:     []string{"CVE-2024-1"},
			Severity:   advisory.SeverityHigh,
			OSFamily:   "rhel",
			OSMajorVer: "9",
		},
	}
	if err := p.PublishAdvisory(context.Background(), msg); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func TestPublisher_PublishBatch(t *testing.T) {
	t.Parallel()
	mp := mocks.NewSyncProducer(t, nil)
	defer mp.Close()
	mp.ExpectSendMessageAndSucceed()
	mp.ExpectSendMessageAndSucceed()

	p := &Publisher{producer: mp, topic: "x"}
	msgs := []advisory.AdvisoryMessage{
		{Source: "usn", Advisory: &advisory.Advisory{AdvisoryID: "USN-1", Severity: advisory.SeverityLow}},
		{Source: "usn", Advisory: &advisory.Advisory{AdvisoryID: "USN-2", Severity: advisory.SeverityLow}},
	}
	n, err := p.PublishBatch(context.Background(), msgs)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 succ, got %d", n)
	}
}
