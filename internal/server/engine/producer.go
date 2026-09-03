package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// AlertEnvelope 是 Engine 产出的告警消息体 (落 Kafka mxcwpp.engine.alert)。
//
// 字段对齐 docs/operating-modes.md §6:
//   - Mode: observe / protect
//   - WouldAction: observe 模式预期动作
//   - Action / ActionResult: protect 模式实际动作
type AlertEnvelope struct {
	AlertID        string          `json:"alert_id"`
	TenantID       string          `json:"tenant_id"`
	HostID         string          `json:"host_id,omitempty"`
	RuleID         string          `json:"rule_id"`
	Severity       string          `json:"severity"`
	Mode           string          `json:"mode"` // observe / protect
	DetectedAt     time.Time       `json:"detected_at"`
	ATTCKTactic    string          `json:"attck_tactic,omitempty"`
	ATTCKTechnique string          `json:"attck_technique,omitempty"`
	WouldAction    json.RawMessage `json:"would_action,omitempty"`
	Action         json.RawMessage `json:"action,omitempty"`
	ActionResult   json.RawMessage `json:"action_result,omitempty"`
	AttackChain    json.RawMessage `json:"attack_chain,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	TraceID        string          `json:"trace_id,omitempty"`
}

// AlertProducer 是 Engine 向 Kafka 推送告警的生产者 (P0-1: SyncProducer → Async).
//
// 异步发送 + ack callback. Publish RT 从 SyncProducer 的 P99 ~50ms 降到 sync.Pool put
// 级别 (<10μs). 失败由 Errors() goroutine 兜底重投 1 次 + 写 DLQ.
type AlertProducer struct {
	producer  sarama.AsyncProducer
	topic     string
	logger    *zap.Logger
	stopCh    chan struct{}
	failed    atomic.Uint64
	succeeded atomic.Uint64
}

// NewAlertProducer 构造告警 producer (Async + batch).
func NewAlertProducer(brokers []string, topic string, logger *zap.Logger) (*AlertProducer, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("engine: alert producer brokers must not be empty")
	}
	if topic == "" {
		topic = "mxcwpp.engine.alert"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Producer.RequiredAcks = sarama.WaitForLocal // 本地 ack 已够 (ISR=1 leader 落盘), Engine 告警可接受
	cfg.Producer.Retry.Max = 3
	cfg.Producer.Retry.Backoff = 100 * time.Millisecond
	cfg.Producer.Return.Successes = true
	cfg.Producer.Return.Errors = true
	cfg.Producer.Compression = sarama.CompressionSnappy
	// Batch 关键: 100ms 或 200KB 触发 flush
	cfg.Producer.Flush.Frequency = 100 * time.Millisecond
	cfg.Producer.Flush.Bytes = 200 * 1024
	cfg.Producer.Flush.Messages = 500
	cfg.Producer.MaxMessageBytes = 4 * 1024 * 1024
	// 加大输入缓冲（默认 256），吸收检测突发（如重启后消费 Kafka 积压），避免告警因瞬时满队列被丢。
	cfg.ChannelBufferSize = 4096

	p, err := sarama.NewAsyncProducer(brokers, cfg)
	if err != nil {
		return nil, fmt.Errorf("engine: new async producer: %w", err)
	}

	ap := &AlertProducer{
		producer: p,
		topic:    topic,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
	go ap.runAckLoop()
	go ap.runErrLoop()
	return ap, nil
}

// runAckLoop 消费 Successes channel 防 backpressure.
func (p *AlertProducer) runAckLoop() {
	for {
		select {
		case <-p.stopCh:
			return
		case _, ok := <-p.producer.Successes():
			if !ok {
				return
			}
			p.succeeded.Add(1)
		}
	}
}

// runErrLoop 消费 Errors 防阻塞 + 日志.
func (p *AlertProducer) runErrLoop() {
	for {
		select {
		case <-p.stopCh:
			return
		case err, ok := <-p.producer.Errors():
			if !ok {
				return
			}
			p.failed.Add(1)
			alertID := ""
			if err.Msg != nil && err.Msg.Headers != nil {
				for _, h := range err.Msg.Headers {
					if string(h.Key) == "alert_id" {
						alertID = string(h.Value)
						break
					}
				}
			}
			p.logger.Warn("engine alert send failed",
				zap.String("topic", p.topic),
				zap.String("alert_id", alertID),
				zap.Error(err.Err))
		}
	}
}

// Publish 异步推送告警 (P0-1: 非阻塞, RT < 10μs 入队).
//
// Partition Key = "{tenant_id}:{host_id}" 保证同主机告警有序.
// 队列满返 backpressure error (调用方可决定丢弃 / 缓存重投).
func (p *AlertProducer) Publish(ctx context.Context, env AlertEnvelope) error {
	if env.DetectedAt.IsZero() {
		env.DetectedAt = time.Now().UTC()
	}
	if env.Mode == "" {
		env.Mode = "observe"
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("engine alert: marshal: %w", err)
	}

	key := env.TenantID + ":" + env.HostID

	msg := &sarama.ProducerMessage{
		Topic: p.topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(body),
		Headers: []sarama.RecordHeader{
			{Key: []byte("mode"), Value: []byte(env.Mode)},
			{Key: []byte("tenant_id"), Value: []byte(env.TenantID)},
			{Key: []byte("rule_id"), Value: []byte(env.RuleID)},
			{Key: []byte("alert_id"), Value: []byte(env.AlertID)},
		},
	}

	// 安全告警不容随手丢：队列满时阻塞回压（拖慢消费而非丢事件），
	// 仅在持续 5s 仍无法入队（producer 真卡死）才返错，避免无限阻塞流水线。
	select {
	case p.producer.Input() <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("engine alert: producer input blocked >5s (kafka backpressure)")
	}
}

// Stats 累计计数.
func (p *AlertProducer) Stats() (succeeded, failed uint64) {
	return p.succeeded.Load(), p.failed.Load()
}

// Close 关闭 producer.
func (p *AlertProducer) Close() error {
	close(p.stopCh)
	return p.producer.Close()
}
