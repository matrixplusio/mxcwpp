// Package audit 把 LLM 调用日志推到 Kafka mxsec.llm.audit Topic。
//
// 字段对齐 docs/llmproxy-design.md §3.6 audit。
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// Event 是单次 LLM 调用的审计事件。
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id,omitempty"`
	Scene     string    `json:"scene"`
	Provider  string    `json:"provider"`
	Model     string    `json:"model"`
	TokensIn  int       `json:"tokens_in"`
	TokensOut int       `json:"tokens_out"`
	CostUSD   float64   `json:"cost_usd"`
	LatencyMS int64     `json:"latency_ms"`
	Status    string    `json:"status"` // success / failure / quota_exceeded
	Err       string    `json:"err,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	// 不写入入参内容 (隐私), 仅记录元数据
}

// Logger 把 Event 写到 Kafka mxsec.llm.audit。
type Logger struct {
	producer sarama.SyncProducer
	topic    string
	logger   *zap.Logger
}

// New 构造 audit logger。
func New(brokers []string, topic string, logger *zap.Logger) (*Logger, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("audit: brokers must not be empty")
	}
	if topic == "" {
		topic = "mxsec.llm.audit"
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Producer.RequiredAcks = sarama.WaitForLocal // 审计可放宽 ack
	cfg.Producer.Retry.Max = 2
	cfg.Producer.Return.Successes = true
	cfg.Producer.Compression = sarama.CompressionSnappy

	p, err := sarama.NewSyncProducer(brokers, cfg)
	if err != nil {
		return nil, fmt.Errorf("audit: new producer: %w", err)
	}
	return &Logger{producer: p, topic: topic, logger: logger}, nil
}

// Log 写入审计事件。
func (l *Logger) Log(ctx context.Context, ev Event) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	key := ev.TenantID
	if key == "" {
		key = "global"
	}
	msg := &sarama.ProducerMessage{
		Topic: l.topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(body),
		Headers: []sarama.RecordHeader{
			{Key: []byte("tenant_id"), Value: []byte(ev.TenantID)},
			{Key: []byte("scene"), Value: []byte(ev.Scene)},
			{Key: []byte("status"), Value: []byte(ev.Status)},
		},
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, _, err = l.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("audit: send: %w", err)
	}
	return nil
}

// Close 关闭 producer。
func (l *Logger) Close() error {
	return l.producer.Close()
}
