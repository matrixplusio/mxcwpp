package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// IOCSyncScheduler 把威胁情报 IOC (域名 / IP / hash) 同步推送到 AC。
//
// 通过 mxcwpp.engine.command Topic 解耦:
//
//	Engine.IOCSyncScheduler → Kafka → AC.commandsub → Agent
type IOCSyncScheduler struct {
	producer sarama.SyncProducer
	topic    string
	logger   *zap.Logger
}

// IOCBundle 是一次 IOC 同步的载荷。
type IOCBundle struct {
	Version    string   `json:"version"`   // 版本号 / 时间戳
	FullSync   bool     `json:"full_sync"` // true=全量,false=增量
	Domains    []string `json:"domains,omitempty"`
	IPv4       []string `json:"ipv4,omitempty"`
	HashSHA256 []string `json:"hash_sha256,omitempty"`
	URLs       []string `json:"urls,omitempty"`
}

// NewIOCSyncScheduler 构造。
func NewIOCSyncScheduler(brokers []string, topic string, logger *zap.Logger) (*IOCSyncScheduler, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("ioc_sync: brokers must not be empty")
	}
	if topic == "" {
		topic = "mxcwpp.engine.command"
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Producer.RequiredAcks = sarama.WaitForLocal
	cfg.Producer.Retry.Max = 3
	cfg.Producer.Return.Successes = true
	cfg.Producer.Compression = sarama.CompressionSnappy

	p, err := sarama.NewSyncProducer(brokers, cfg)
	if err != nil {
		return nil, fmt.Errorf("ioc_sync: new producer: %w", err)
	}
	return &IOCSyncScheduler{producer: p, topic: topic, logger: logger}, nil
}

// PushIOCBundle 推送 IOC 包到 AC。
func (s *IOCSyncScheduler) PushIOCBundle(ctx context.Context, tenantID string, agentIDs []string, bundle IOCBundle) error {
	cmd := struct {
		TenantID    string    `json:"tenant_id"`
		AgentIDs    []string  `json:"agent_ids"`
		CommandType string    `json:"command_type"`
		Payload     IOCBundle `json:"payload"`
		IssuedAt    int64     `json:"issued_at"`
	}{
		TenantID:    tenantID,
		AgentIDs:    agentIDs,
		CommandType: "ioc_sync",
		Payload:     bundle,
		IssuedAt:    time.Now().UnixMilli(),
	}
	body, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("ioc_sync: marshal: %w", err)
	}

	key := tenantID
	if len(agentIDs) == 1 {
		key = tenantID + ":" + agentIDs[0]
	}
	msg := &sarama.ProducerMessage{
		Topic: s.topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(body),
		Headers: []sarama.RecordHeader{
			{Key: []byte("command_type"), Value: []byte("ioc_sync")},
			{Key: []byte("tenant_id"), Value: []byte(tenantID)},
			{Key: []byte("full_sync"), Value: []byte(fmt.Sprintf("%v", bundle.FullSync))},
		},
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, _, err = s.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("ioc_sync: send: %w", err)
	}
	s.logger.Info("ioc_sync 命令已推送",
		zap.String("tenant_id", tenantID),
		zap.Int("agent_count", len(agentIDs)),
		zap.Bool("full_sync", bundle.FullSync),
		zap.Int("domains", len(bundle.Domains)),
		zap.Int("ipv4", len(bundle.IPv4)),
		zap.Int("hash_sha256", len(bundle.HashSHA256)),
	)
	return nil
}

// Close 关闭 producer。
func (s *IOCSyncScheduler) Close() error {
	return s.producer.Close()
}
