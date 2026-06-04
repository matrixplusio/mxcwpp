package kafka

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
)

// Producer 是 Kafka 生产者接口
type Producer interface {
	Send(topic, key string, msg *MQMessage) error
	Close() error
}

const (
	// 降级队列消息最大重试次数
	fallbackMaxRetries = 5
	// 降级队列消息过期时间（超过此时间丢弃）
	fallbackMsgTTL = 5 * time.Minute
)

// pendingMsg 是降级队列中暂存的消息
type pendingMsg struct {
	topic      string
	key        string
	msg        *MQMessage
	retryCount int
	enqueuedAt time.Time
}

// AsyncProducer 封装 sarama AsyncProducer，含降级内存队列
//
// 注意: 调用方传入 Send/enqueueToFallback 的 topic 必须是已包含 TopicPrefix 的
// 完整 topic 名称（kafka.RouteDataType / kafka.DLQTopic 已负责拼接）。
// 历史上 Producer 内部又拼一次 prefix，导致出现 "prodprodmxsec.agent.ebpf"
// 这类不存在的 topic，引发 circuit breaker 永久打开 → 所有 EDR 消息被丢弃。
type AsyncProducer struct {
	producer sarama.AsyncProducer
	logger   *zap.Logger

	// 降级队列：Kafka 不可用时暂存，容量 10000
	fallback    chan *pendingMsg
	fallbackLen int64 // atomic counter

	// 对象池：复用 ProducerMessage 减少 GC
	msgPool sync.Pool

	closeOnce sync.Once
	closed    chan struct{}
}

// NewAsyncProducer 初始化 Kafka 异步生产者
func NewAsyncProducer(cfg config.KafkaConfig, logger *zap.Logger) (*AsyncProducer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, fmt.Errorf("Kafka brokers 未配置")
	}

	saramaCfg := sarama.NewConfig()
	saramaCfg.Producer.Return.Successes = false // 异步模式不等成功回调
	saramaCfg.Producer.Return.Errors = true
	saramaCfg.Producer.MaxMessageBytes = 4 * 1024 * 1024 // 4MB
	saramaCfg.Producer.Timeout = 6 * time.Second
	saramaCfg.Producer.Flush.Bytes = 4 * 1024 * 1024 // 4MB 触发 flush
	saramaCfg.Producer.Flush.Frequency = 10 * time.Second
	saramaCfg.Producer.Retry.Max = 3
	saramaCfg.Producer.Compression = sarama.CompressionSnappy
	switch cfg.Producer.RequiredAcks {
	case 0:
		saramaCfg.Producer.RequiredAcks = sarama.NoResponse
	case 1:
		saramaCfg.Producer.RequiredAcks = sarama.WaitForLocal
	default:
		saramaCfg.Producer.RequiredAcks = sarama.WaitForAll
	}

	// 从配置覆盖（如果有）
	if cfg.Producer.MaxMessageBytes > 0 {
		saramaCfg.Producer.MaxMessageBytes = cfg.Producer.MaxMessageBytes
	}
	if cfg.Producer.RetryMax > 0 {
		saramaCfg.Producer.Retry.Max = cfg.Producer.RetryMax
	}

	producer, err := sarama.NewAsyncProducer(cfg.Brokers, saramaCfg)
	if err != nil {
		return nil, fmt.Errorf("创建 Kafka 生产者失败: %w", err)
	}

	p := &AsyncProducer{
		producer: producer,
		logger:   logger,
		fallback: make(chan *pendingMsg, 10000),
		closed:   make(chan struct{}),
		msgPool: sync.Pool{
			New: func() any { return &sarama.ProducerMessage{} },
		},
	}

	// 异步消费 Kafka 错误
	go p.errorLoop()
	// 后台重放降级队列
	go p.replayLoop()

	return p, nil
}

// Send 发送消息到指定 Topic（异步，不阻塞）
func (p *AsyncProducer) Send(topic, key string, msg *MQMessage) error {
	msg.SvrTime = time.Now().Unix()
	msg.ReceivedAt = time.Now()

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("序列化 MQMessage 失败: %w", err)
	}

	pm := p.msgPool.Get().(*sarama.ProducerMessage)
	pm.Topic = topic
	pm.Key = sarama.StringEncoder(key)
	pm.Value = sarama.ByteEncoder(body)

	select {
	case p.producer.Input() <- pm:
		return nil
	default:
		// Kafka 输入缓冲满，写降级队列
		p.msgPool.Put(pm)
		return p.enqueueToFallback(topic, key, msg)
	}
}

// enqueueToFallback 写入降级内存队列（首次入队）
func (p *AsyncProducer) enqueueToFallback(topic, key string, msg *MQMessage) error {
	return p.enqueueToFallbackWithRetry(topic, key, msg, 0)
}

// enqueueToFallbackWithRetry 写入降级内存队列（含重试计数）
func (p *AsyncProducer) enqueueToFallbackWithRetry(topic, key string, msg *MQMessage, retryCount int) error {
	if retryCount >= fallbackMaxRetries {
		p.logger.Warn("Kafka 降级队列消息超过最大重试次数，丢弃",
			zap.String("topic", topic),
			zap.Int32("data_type", msg.DataType),
			zap.String("agent_id", msg.AgentID),
			zap.Int("retry_count", retryCount),
		)
		return fmt.Errorf("kafka fallback max retries exceeded, message dropped")
	}

	select {
	case p.fallback <- &pendingMsg{topic: topic, key: key, msg: msg, retryCount: retryCount, enqueuedAt: time.Now()}:
		atomic.AddInt64(&p.fallbackLen, 1)
		return nil
	default:
		p.logger.Warn("Kafka 降级队列已满，消息丢弃",
			zap.String("topic", topic),
			zap.Int32("data_type", msg.DataType),
			zap.String("agent_id", msg.AgentID),
		)
		return fmt.Errorf("kafka fallback queue full, message dropped")
	}
}

// replayLoop 后台重放降级队列（Kafka 恢复后生效）
func (p *AsyncProducer) replayLoop() {
	for {
		select {
		case <-p.closed:
			return
		case pm := <-p.fallback:
			atomic.AddInt64(&p.fallbackLen, -1)

			// 检查消息是否已过期
			if time.Since(pm.enqueuedAt) > fallbackMsgTTL {
				p.logger.Warn("Kafka 降级队列消息已过期，丢弃",
					zap.String("topic", pm.topic),
					zap.Duration("age", time.Since(pm.enqueuedAt)),
					zap.Int("retry_count", pm.retryCount),
				)
				continue
			}

			// 重放：直接放入 Kafka 输入通道，如失败再放回队列
			if err := p.Send(pm.topic, pm.key, pm.msg); err != nil {
				time.Sleep(1 * time.Second)
				_ = p.enqueueToFallbackWithRetry(pm.topic, pm.key, pm.msg, pm.retryCount+1)
			}
		}
	}
}

// errorLoop 消费 Kafka 生产者错误
func (p *AsyncProducer) errorLoop() {
	for {
		select {
		case <-p.closed:
			return
		case err, ok := <-p.producer.Errors():
			if !ok {
				return
			}
			p.logger.Error("Kafka 发送失败",
				zap.String("topic", err.Msg.Topic),
				zap.Error(err.Err),
			)
			// 从 ProducerMessage 恢复消息并写入降级队列
			if body, e := err.Msg.Value.Encode(); e == nil {
				var msg MQMessage
				if e := json.Unmarshal(body, &msg); e == nil {
					_ = p.enqueueToFallback(err.Msg.Topic, "", &msg)
				}
			}
			p.msgPool.Put(err.Msg)
		}
	}
}

// FallbackQueueLen 返回当前降级队列长度（用于监控）
func (p *AsyncProducer) FallbackQueueLen() int64 {
	return atomic.LoadInt64(&p.fallbackLen)
}

// Close 关闭生产者
func (p *AsyncProducer) Close() error {
	var retErr error
	p.closeOnce.Do(func() {
		close(p.closed)
		retErr = p.producer.Close()
	})
	return retErr
}
