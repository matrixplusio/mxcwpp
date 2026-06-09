// Package publisher 把 Advisory 推送到 Kafka mxsec.vuln.advisory。
package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/sources"
)

// Publisher 包装 sarama.SyncProducer。
type Publisher struct {
	producer sarama.SyncProducer
	topic    string
	logger   *zap.Logger
}

// New 构造 publisher。
func New(brokers []string, topic string, logger *zap.Logger) (*Publisher, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("vulnsync publisher: brokers must not be empty")
	}
	if topic == "" {
		topic = "mxsec.vuln.advisory"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Producer.RequiredAcks = sarama.WaitForAll
	cfg.Producer.Retry.Max = 3
	cfg.Producer.Return.Successes = true
	cfg.Producer.Compression = sarama.CompressionSnappy

	p, err := sarama.NewSyncProducer(brokers, cfg)
	if err != nil {
		return nil, fmt.Errorf("vulnsync publisher: new producer: %w", err)
	}
	return &Publisher{producer: p, topic: topic, logger: logger}, nil
}

// PublishAdvisory 推送单条 advisory。
//
// Partition Key = source:source_id 保证同源同 ID 的更新顺序一致。
func (p *Publisher) PublishAdvisory(ctx context.Context, a sources.Advisory) error {
	if a.ModifiedAt.IsZero() {
		a.ModifiedAt = time.Now().UTC()
	}
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	key := a.Source + ":" + a.SourceID
	msg := &sarama.ProducerMessage{
		Topic: p.topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(body),
		Headers: []sarama.RecordHeader{
			{Key: []byte("source"), Value: []byte(a.Source)},
			{Key: []byte("cve"), Value: []byte(a.CVE)},
			{Key: []byte("severity"), Value: []byte(a.Severity)},
		},
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	part, off, err := p.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	if p.logger != nil {
		p.logger.Debug("advisory published",
			zap.String("topic", p.topic),
			zap.Int32("partition", part),
			zap.Int64("offset", off),
			zap.String("source", a.Source),
			zap.String("source_id", a.SourceID),
		)
	}
	return nil
}

// PublishBatch 批量推送。
func (p *Publisher) PublishBatch(ctx context.Context, advs []sources.Advisory) (int, error) {
	succ := 0
	for _, a := range advs {
		if err := p.PublishAdvisory(ctx, a); err != nil {
			return succ, err
		}
		succ++
	}
	return succ, nil
}

// Close 关闭 producer。
func (p *Publisher) Close() error {
	return p.producer.Close()
}
