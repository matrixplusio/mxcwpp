package publisher

import (
	"context"
	"testing"
	"time"

	"github.com/IBM/sarama/mocks"

	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/sources"
)

func TestPublisher_PublishAdvisory(t *testing.T) {
	t.Parallel()
	mp := mocks.NewSyncProducer(t, nil)
	defer mp.Close()
	mp.ExpectSendMessageAndSucceed()

	p := &Publisher{producer: mp, topic: "mxsec.vuln.advisory"}
	adv := sources.Advisory{
		Source:     "nvd",
		SourceID:   "CVE-2024-1",
		CVE:        "CVE-2024-1",
		Severity:   "high",
		ModifiedAt: time.Now(),
	}
	if err := p.PublishAdvisory(context.Background(), adv); err != nil {
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
	advs := []sources.Advisory{
		{Source: "nvd", SourceID: "1", Severity: "low", ModifiedAt: time.Now()},
		{Source: "nvd", SourceID: "2", Severity: "low", ModifiedAt: time.Now()},
	}
	n, err := p.PublishBatch(context.Background(), advs)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 succ, got %d", n)
	}
}
