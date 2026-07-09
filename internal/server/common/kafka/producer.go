package kafka

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// Kafka 生产者可靠性指标。
// 此前消息丢弃（队列满/重试耗尽/过期）仅 30s 汇总打 Warn 日志，对监控不可见，
// burst 下丢消息（含基线完成信号）无法被告警发现。暴露为 Prometheus 指标以便监控/告警。
var (
	// reason: fallback_full / retry_exhausted / expired
	producerDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_kafka_producer_dropped_total",
		Help: "Total messages dropped by the kafka async producer (never delivered)",
	}, []string{"reason"})

	producerFallbackLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_kafka_producer_fallback_len",
		Help: "Current length of the kafka producer in-memory fallback queue",
	})
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
// 历史上 Producer 内部又拼一次 prefix，导致出现 "prodprodmxcwpp.agent.ebpf"
// 这类不存在的 topic，引发 circuit breaker 永久打开 → 所有 EDR 消息被丢弃。
type AsyncProducer struct {
	producer sarama.AsyncProducer
	logger   *zap.Logger

	// 降级队列：Kafka 不可用时暂存，容量 10000
	fallback    chan *pendingMsg
	fallbackLen int64 // atomic counter
	// dropped 累计被丢弃的消息数（队列满/重试耗尽），由 dropSummaryLoop 周期汇总后清零。
	// Kafka 不可用时丢弃可达每秒数千条，逐条打日志会撑爆磁盘（prod 实测 ~130GB/天），
	// 故只累加计数，按固定间隔汇总成一行。
	dropped int64 // atomic counter

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
	// ChannelBufferSize / Flush 直接吸收 burst 与加快排空，是抗 burst 丢弃的关键旋钮
	if cfg.Producer.ChannelBufferSize > 0 {
		saramaCfg.ChannelBufferSize = cfg.Producer.ChannelBufferSize
	}
	if cfg.Producer.FlushFrequency > 0 {
		saramaCfg.Producer.Flush.Frequency = cfg.Producer.FlushFrequency
	}
	if cfg.Producer.FlushMessages > 0 {
		saramaCfg.Producer.Flush.Messages = cfg.Producer.FlushMessages
	}

	producer, err := sarama.NewAsyncProducer(cfg.Brokers, saramaCfg)
	if err != nil {
		return nil, fmt.Errorf("创建 Kafka 生产者失败: %w", err)
	}

	fallbackSize := cfg.Producer.FallbackQueueSize
	if fallbackSize <= 0 {
		fallbackSize = 10000
	}
	p := &AsyncProducer{
		producer: producer,
		logger:   logger,
		fallback: make(chan *pendingMsg, fallbackSize),
		closed:   make(chan struct{}),
		msgPool: sync.Pool{
			New: func() any { return &sarama.ProducerMessage{} },
		},
	}

	// 异步消费 Kafka 错误
	go p.errorLoop()
	// 后台重放降级队列
	go p.replayLoop()
	// 周期汇总丢弃计数（替代逐条日志，防磁盘被刷爆）
	go p.dropSummaryLoop()

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

// producerReliableSendTimeout 是 SendReliable 在 Kafka Input 满时的最长阻塞等待时间。
// 为 var 以便测试压缩等待时间。
var producerReliableSendTimeout = 3 * time.Second

// SendReliable 发送控制面/关键低频消息（如任务完成信号）：Kafka Input 满时阻塞等待
// （有界超时）而非像 Send 那样立即丢弃，超时后退降级队列（含重试）。避免高频遥测 burst
// 把关键消息首先挤丢。仅用于低频消息——高频遥测仍用 Send（非阻塞）以免阻塞 Recv 循环。
func (p *AsyncProducer) SendReliable(topic, key string, msg *MQMessage) error {
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

	timer := time.NewTimer(producerReliableSendTimeout)
	defer timer.Stop()
	select {
	case p.producer.Input() <- pm:
		return nil
	case <-timer.C:
		// Input 持续满（Kafka 慢），退降级队列（有重试），不直接丢弃
		p.msgPool.Put(pm)
		return p.enqueueToFallback(topic, key, msg)
	case <-p.closed:
		p.msgPool.Put(pm)
		return fmt.Errorf("producer 已关闭")
	}
}

// enqueueToFallback 写入降级内存队列（首次入队）
func (p *AsyncProducer) enqueueToFallback(topic, key string, msg *MQMessage) error {
	return p.enqueueToFallbackWithRetry(topic, key, msg, 0)
}

// enqueueToFallbackWithRetry 写入降级内存队列（含重试计数）
func (p *AsyncProducer) enqueueToFallbackWithRetry(topic, key string, msg *MQMessage, retryCount int) error {
	if retryCount >= fallbackMaxRetries {
		// 只累加计数，由 dropSummaryLoop 周期汇总（逐条打日志会撑爆磁盘）。
		atomic.AddInt64(&p.dropped, 1)
		producerDropped.WithLabelValues("retry_exhausted").Inc()
		return fmt.Errorf("kafka fallback max retries exceeded, message dropped")
	}

	select {
	case p.fallback <- &pendingMsg{topic: topic, key: key, msg: msg, retryCount: retryCount, enqueuedAt: time.Now()}:
		atomic.AddInt64(&p.fallbackLen, 1)
		return nil
	default:
		// 只累加计数，由 dropSummaryLoop 周期汇总（逐条打日志会撑爆磁盘）。
		atomic.AddInt64(&p.dropped, 1)
		producerDropped.WithLabelValues("fallback_full").Inc()
		return fmt.Errorf("kafka fallback queue full, message dropped")
	}
}

// dropSummaryLoop 周期汇总被丢弃的消息数为一行日志，替代逐条 Warn。
// Kafka 不可用时丢弃速率极高（prod 实测 ~130GB/天日志），逐条记录会撑爆磁盘。
func (p *AsyncProducer) dropSummaryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.closed:
			if n := atomic.SwapInt64(&p.dropped, 0); n > 0 {
				p.logger.Warn("Kafka 降级队列丢弃消息（退出前汇总）", zap.Int64("dropped", n))
			}
			return
		case <-ticker.C:
			producerFallbackLen.Set(float64(atomic.LoadInt64(&p.fallbackLen)))
			if n := atomic.SwapInt64(&p.dropped, 0); n > 0 {
				p.logger.Warn("Kafka 降级队列丢弃消息汇总",
					zap.Int64("dropped_last_30s", n),
					zap.Int64("fallback_len", atomic.LoadInt64(&p.fallbackLen)),
				)
			}
		}
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
				atomic.AddInt64(&p.dropped, 1)
				producerDropped.WithLabelValues("expired").Inc()
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
