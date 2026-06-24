// Package publisher 把 advisory.AdvisoryMessage 推送到 Kafka mxcwpp.vuln.advisory。
package publisher

import (
	"context"
	"fmt"
	"strings"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
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
		topic = "mxcwpp.vuln.advisory"
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

// PublishAdvisory 推送单条富 advisory 消息。
//
// Partition Key = source:advisory_id，保证同源同 advisory 的更新顺序一致。
// 富 payload（含 AffectedPkgs NEVRA/fixed_version + OS gate）由 Manager consumer
// 反序列化后交给 Matcher 比对主机软件清单。
func (p *Publisher) PublishAdvisory(ctx context.Context, msg advisory.AdvisoryMessage) error {
	if msg.Advisory == nil {
		return fmt.Errorf("vulnsync publisher: nil advisory payload")
	}
	body, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	pm := &sarama.ProducerMessage{
		Topic: p.topic,
		Key:   sarama.StringEncoder(msg.PartitionKey()),
		Value: sarama.ByteEncoder(body),
		Headers: []sarama.RecordHeader{
			{Key: []byte("source"), Value: []byte(msg.Source)},
			{Key: []byte("cve"), Value: []byte(strings.Join(msg.Advisory.CVEIDs, ","))},
			{Key: []byte("severity"), Value: []byte(string(msg.Advisory.Severity))},
		},
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	part, off, err := p.producer.SendMessage(pm)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	if p.logger != nil {
		p.logger.Debug("advisory published",
			zap.String("topic", p.topic),
			zap.Int32("partition", part),
			zap.Int64("offset", off),
			zap.String("source", msg.Source),
			zap.String("advisory_id", msg.Advisory.AdvisoryID),
		)
	}
	return nil
}

// PublishBatch 批量推送。返回成功条数；遇错即停并返回已成功数。
func (p *Publisher) PublishBatch(ctx context.Context, msgs []advisory.AdvisoryMessage) (int, error) {
	succ := 0
	for _, m := range msgs {
		if err := p.PublishAdvisory(ctx, m); err != nil {
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
