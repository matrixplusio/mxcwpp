package kafka

import (
	"encoding/json"
	"errors"
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

	// 只看降级队列无法区分两种截然不同的故障：消息推不进 sarama（Input 满，下游慢），
	// 还是推得进但排空太慢（Input 空，恢复路径慢）。两者的修法相反，缺这个指标只能猜。
	producerInputLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_kafka_producer_input_len",
		Help: "Current length of the producer pending buffer feeding sarama",
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

// replayBatch 是单轮连续排空的上限：一条一条喂 sarama 攒不出批次，
// 吞吐会被钉死在"批大小 ÷ RTT"而不是链路能力。
const replayBatch = 512

// replayBackoff 是 replayLoop 在 Kafka Input 仍满时的短退避（避免热自旋）。
// var 以便测试压缩。注意：仅在 Input 满时退避，成功入通道时不退避，故恢复期可全速排空——
// 区别于旧实现"每条失败 sleep 1s"把恢复串行成 1 条/秒。
var replayBackoff = 100 * time.Millisecond

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
	// Kafka 不可用时丢弃可达每秒数千条，逐条打日志会撑爆磁盘（可达每天上百 GB），
	// 故只累加计数，按固定间隔汇总成一行。
	dropped int64 // atomic counter

	// pending 是本包自有的入站缓冲。
	//
	// 必须有它：sarama 的 Input() 是**无缓冲**通道（async_producer.go:139），
	// ChannelBufferSize 只作用于其内部 partition/broker 通道。对无缓冲通道做非阻塞发送，
	// 只有恰好有接收者 parked 在那一瞬间才成功，因此绝大多数发送会落空——与 Kafka
	// 是否健康完全无关。表现为：broker 全空闲、消费无延迟、链路本身吞吐充裕，
	// 而 AC 只推得出 640 条/秒，其余全进降级队列直到过期。
	// 由专职 feeder 对 sarama 做阻塞投递，把调用方与这个竞态解耦。
	pending chan *sarama.ProducerMessage

	// 对象池：复用 ProducerMessage 减少 GC
	msgPool sync.Pool

	closeOnce sync.Once
	closed    chan struct{}
}

// NewAsyncProducer 初始化 Kafka 异步生产者
func NewAsyncProducer(cfg config.KafkaConfig, logger *zap.Logger) (*AsyncProducer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka brokers 未配置")
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
	pendingSize := cfg.Producer.ChannelBufferSize
	if pendingSize <= 0 {
		pendingSize = 8192
	}
	p := &AsyncProducer{
		producer: producer,
		logger:   logger,
		fallback: make(chan *pendingMsg, fallbackSize),
		pending:  make(chan *sarama.ProducerMessage, pendingSize),
		closed:   make(chan struct{}),
		msgPool: sync.Pool{
			New: func() any { return &sarama.ProducerMessage{} },
		},
	}

	// 专职投递：对 sarama 无缓冲 Input 做阻塞发送
	go p.feedLoop()
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
	case p.pending <- pm:
		return nil
	default:
		// 自有缓冲已满（下游确实堵了），才退降级队列
		p.msgPool.Put(pm)
		return p.enqueueToFallback(topic, key, msg)
	}
}

// feedLoop 把自有缓冲里的消息阻塞投递给 sarama。
//
// 阻塞是关键：sarama 的 Input() 无缓冲，非阻塞发送会因为"此刻没有接收者 parked"
// 而失败，与下游是否有能力无关。阻塞发送则等到 dispatcher 就绪即交付，
// 真正的背压体现为 pending 缓冲变长，而不是消息被误判为投递失败。
func (p *AsyncProducer) feedLoop() {
	for {
		select {
		case <-p.closed:
			return
		case pm := <-p.pending:
			select {
			case p.producer.Input() <- pm:
			case <-p.closed:
				return
			}
		}
	}
}

// trySendInput 非阻塞地把消息投入 Kafka Input，返回是否成功入通道。
//
// 与 Send 的区别：满时 **不** 自动回落降级队列（不重置 retryCount）。供 replayLoop 使用，
// 以便由调用方保留并递增重试计数——旧实现 replayLoop 调 Send 导致每次重放都以 retryCount=0
// 回落，fallbackMaxRetries 永不触发。
func (p *AsyncProducer) trySendInput(topic, key string, msg *MQMessage) bool {
	body, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	pm := p.msgPool.Get().(*sarama.ProducerMessage)
	pm.Topic = topic
	pm.Key = sarama.StringEncoder(key)
	pm.Value = sarama.ByteEncoder(body)
	select {
	case p.pending <- pm:
		return true
	default:
		p.msgPool.Put(pm)
		return false
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
	case p.pending <- pm:
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
	}

	// 队列满：淘汰最旧的一条给新消息让位，而不是拒收新消息。
	//
	// 拒收新消息会让队列变成一潭死水——里面全是接近 TTL 的陈货，占着全部容量空转，
	// 而每一条新到达的消息都被丢在门外。队头的消息离过期最近、被成功重放的机会最小，
	// 淘汰它的代价最低。只累加计数，由 dropSummaryLoop 周期汇总（逐条打日志会撑爆磁盘）。
	select {
	case <-p.fallback:
		atomic.AddInt64(&p.fallbackLen, -1)
		atomic.AddInt64(&p.dropped, 1)
		producerDropped.WithLabelValues("fallback_evicted").Inc()
	default:
	}

	select {
	case p.fallback <- &pendingMsg{topic: topic, key: key, msg: msg, retryCount: retryCount, enqueuedAt: time.Now()}:
		atomic.AddInt64(&p.fallbackLen, 1)
		return nil
	default:
		atomic.AddInt64(&p.dropped, 1)
		producerDropped.WithLabelValues("fallback_full").Inc()
		return errors.New("kafka fallback queue full, message dropped")
	}
}

// dropSummaryLoop 周期汇总被丢弃的消息数为一行日志，替代逐条 Warn。
// Kafka 不可用时丢弃速率极高（可达每天上百 GB 日志），逐条记录会撑爆磁盘。
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
			producerInputLen.Set(float64(len(p.pending)))
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
			_, inputFull := p.replayOne(pm)
			if !inputFull {
				// Input 还有空间就连续排空，不再逐条返回外层 select。
				_, inputFull = p.drainFallback(replayBatch - 1)
			}
			if inputFull {
				select {
				case <-p.closed:
					return
				case <-time.After(replayBackoff):
				}
			}
		}
	}
}

// replayOne 重放单条消息。
//
// delivered 表示消息真正投进了 Input；inputFull 表示 Input 已满、消息已回队。
// 过期消息两者皆 false：它离开了队列但没有被投递，不该计入排空吞吐。
//
// 过期消息不逐条记日志：积压时过期是万级/分钟，逐条写会让排空速度被日志限死。
// 回放速率远低于积压速率——排空队列所需时间超过消息 TTL，于是队列里的消息
// 注定先过期，永远排不空（单夜写出 193MB 日志，99.93% 是这一条）。
// 计量交给 producerDropped 指标，成因交给每 30 秒一次的汇总日志。
func (p *AsyncProducer) replayOne(pm *pendingMsg) (delivered, inputFull bool) {
	if time.Since(pm.enqueuedAt) > fallbackMsgTTL {
		atomic.AddInt64(&p.dropped, 1)
		producerDropped.WithLabelValues("expired").Inc()
		return false, false
	}
	// 直接投 Input（不走 Send，避免 retryCount 被重置为 0）。
	if !p.trySendInput(pm.topic, pm.key, pm.msg) {
		_ = p.enqueueToFallbackWithRetry(pm.topic, pm.key, pm.msg, pm.retryCount+1)
		return false, true
	}
	return true, false
}

// drainFallback 在 Input 尚有空间时成批排空降级队列，返回排空条数与是否遇到 Input 满。
//
// 为什么必须成批：一条一条喂，sarama 攒不出批次，只能按往返延迟发小包，吞吐被钉死在
// "批大小 ÷ RTT"。生产上因此出现过积压与空闲并存的死局——降级队列满着 5 万条、
// Kafka 侧却全空闲，队列里的消息在被重试之前就先到了 TTL。
func (p *AsyncProducer) drainFallback(limit int) (int, bool) {
	drained := 0
	for range limit {
		select {
		case pm := <-p.fallback:
			atomic.AddInt64(&p.fallbackLen, -1)
			delivered, inputFull := p.replayOne(pm)
			if inputFull {
				return drained, true
			}
			if delivered {
				drained++
			}
		default:
			return drained, false // 队列已空
		}
	}
	return drained, false
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
					// 透传原始分区 key，避免重投后同 agent 消息跨分区破坏顺序。
					key := ""
					if err.Msg.Key != nil {
						if kb, ke := err.Msg.Key.Encode(); ke == nil {
							key = string(kb)
						}
					}
					_ = p.enqueueToFallback(err.Msg.Topic, key, &msg)
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
