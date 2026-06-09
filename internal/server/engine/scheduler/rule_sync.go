package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// RuleSyncScheduler 把规则版本变更推送到 AC (通过 Kafka mxsec.engine.command)。
//
// 触发条件:
//   - 周期 tick (默认 5min) 检查 detection_rules / agent_rules 表 updated_at > lastSyncAt
//   - 命中变更时 → 推 mxsec.engine.command (type=rule_sync, payload=rule_id 列表)
//
// AC 端 commandsub.Consumer (PR15) 接收 + transfer.PushToAgents 下发。
type RuleSyncScheduler struct {
	producer sarama.SyncProducer
	topic    string
	tick     time.Duration
	logger   *zap.Logger
}

// NewRuleSyncScheduler 构造。
func NewRuleSyncScheduler(brokers []string, topic string, tick time.Duration, logger *zap.Logger) (*RuleSyncScheduler, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("rule_sync: brokers must not be empty")
	}
	if topic == "" {
		topic = "mxsec.engine.command"
	}
	if tick <= 0 {
		tick = 5 * time.Minute
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
		return nil, fmt.Errorf("rule_sync: new producer: %w", err)
	}
	return &RuleSyncScheduler{
		producer: p,
		topic:    topic,
		tick:     tick,
		logger:   logger,
	}, nil
}

// SyncRules 立即触发一次规则同步推送。
//
// agentIDs 留空表示推所有在线 Agent (AC 侧处理),
// ruleIDs 传需要重新推送的规则 ID 列表。
func (s *RuleSyncScheduler) SyncRules(ctx context.Context, tenantID string, agentIDs []string, ruleIDs []int64) error {
	cmd := struct {
		TenantID    string   `json:"tenant_id"`
		AgentIDs    []string `json:"agent_ids"`
		CommandType string   `json:"command_type"`
		Payload     struct {
			RuleIDs []int64 `json:"rule_ids"`
		} `json:"payload"`
		IssuedAt int64 `json:"issued_at"`
	}{
		TenantID:    tenantID,
		AgentIDs:    agentIDs,
		CommandType: "rule_sync",
		IssuedAt:    time.Now().UnixMilli(),
	}
	cmd.Payload.RuleIDs = ruleIDs

	body, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("rule_sync: marshal: %w", err)
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
			{Key: []byte("command_type"), Value: []byte("rule_sync")},
			{Key: []byte("tenant_id"), Value: []byte(tenantID)},
		},
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, _, err = s.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("rule_sync: send: %w", err)
	}
	s.logger.Info("rule_sync 命令已推送",
		zap.String("tenant_id", tenantID),
		zap.Int("agent_count", len(agentIDs)),
		zap.Int("rule_count", len(ruleIDs)),
	)
	return nil
}

// Close 关闭 producer。
func (s *RuleSyncScheduler) Close() error {
	return s.producer.Close()
}
