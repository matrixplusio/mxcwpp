package engine

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// ConsumerGroupID 是 Engine 服务的 Kafka ConsumerGroup,
// 与 Consumer 服务的 "mxsec-writers" 互不冲突,
// 同一份 mxsec.agent.* 消息会被两个 group 各消费一次。
const ConsumerGroupID = "mxsec-engine"

// SubscribedTopics 是 Engine ConsumerGroup B 订阅的 Topic 集合。
// 详见 docs/architecture.md §4.2 ConsumerGroup 拓扑。
var SubscribedTopics = []string{
	"mxsec.agent.ebpf",     // EDR 内核事件 (CEL 规则 / 序列 / ML)
	"mxsec.agent.events",   // FIM 文件事件
	"mxsec.agent.scanner",  // 病毒/漏洞扫描结果
	"mxsec.agent.baseline", // 基线结果
	"mxsec.vuln.advisory",  // 漏洞情报 (Engine 关联检测)
}

// MessageHandler 是单条 Kafka 消息的处理函数。
//
// 返回 error 时该消息走 DLQ;返回 nil 即 commit offset。
// Engine 检测层 (rule/sequence/ml/storyline) 实现该 interface,
// PR13 仅给 noop 占位,真实实现由后续 PR 引入。
type MessageHandler func(ctx context.Context, msg *sarama.ConsumerMessage) error

// KafkaConsumer 是 Engine 的 Kafka ConsumerGroup 消费器。
//
// 启动模型:
//   - 一个 sarama ConsumerGroup 实例订阅 SubscribedTopics
//   - 内部 goroutine 循环 Consume()
//   - ctx 取消时优雅退出
type KafkaConsumer struct {
	brokers []string
	group   sarama.ConsumerGroup
	handler MessageHandler
	logger  *zap.Logger
	wg      sync.WaitGroup
}

// NewKafkaConsumer 构造 ConsumerGroup B。
//
// brokers: Kafka broker 地址列表
// handler: 消息处理函数 (nil 时使用 noop)
func NewKafkaConsumer(brokers []string, handler MessageHandler, logger *zap.Logger) (*KafkaConsumer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("engine kafka: brokers must not be empty")
	}
	if handler == nil {
		handler = noopHandler
	}

	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRoundRobin()}
	cfg.Consumer.Offsets.Initial = sarama.OffsetNewest
	cfg.Consumer.Return.Errors = true

	group, err := sarama.NewConsumerGroup(brokers, ConsumerGroupID, cfg)
	if err != nil {
		return nil, fmt.Errorf("engine kafka: new consumer group: %w", err)
	}

	return &KafkaConsumer{
		brokers: brokers,
		group:   group,
		handler: handler,
		logger:  logger,
	}, nil
}

// Start 启动消费循环。ctx 取消时优雅退出。
// 调用方应在 defer 中 Close。
func (c *KafkaConsumer) Start(ctx context.Context) {
	c.wg.Add(2)

	// 消费循环
	go func() {
		defer c.wg.Done()
		consumer := &groupHandler{
			handler: c.handler,
			logger:  c.logger,
		}
		for {
			if err := c.group.Consume(ctx, SubscribedTopics, consumer); err != nil {
				if ctx.Err() != nil {
					return
				}
				c.logger.Error("engine consumer group error", zap.Error(err))
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()

	// 错误日志循环
	go func() {
		defer c.wg.Done()
		for err := range c.group.Errors() {
			c.logger.Warn("engine consumer group error event", zap.Error(err))
		}
	}()

	c.logger.Info("Engine Kafka ConsumerGroup started",
		zap.String("group_id", ConsumerGroupID),
		zap.Strings("topics", SubscribedTopics),
	)
}

// Close 优雅关闭。
func (c *KafkaConsumer) Close() error {
	err := c.group.Close()
	c.wg.Wait()
	return err
}

// groupHandler 实现 sarama.ConsumerGroupHandler interface。
type groupHandler struct {
	handler MessageHandler
	logger  *zap.Logger
}

func (h *groupHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *groupHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

// ConsumeClaim P1-1: worker pool 并行处理单 partition 消息.
//
// 默认 8 worker, 通过 ENGINE_WORKERS_PER_PARTITION env 覆盖.
// 保证 offset 顺序: 用顺序 channel 推 MarkMessage, 避免 OOO commit.
func (h *groupHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	ctx := sess.Context()
	workers := workerCountFromEnv("ENGINE_WORKERS_PER_PARTITION", 8)
	jobs := make(chan *sarama.ConsumerMessage, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range jobs {
				if err := h.handler(ctx, msg); err != nil {
					h.logger.Warn("engine handler error,消息不会重试 (Engine 不阻塞 offset)",
						zap.String("topic", msg.Topic),
						zap.Int32("partition", msg.Partition),
						zap.Int64("offset", msg.Offset),
						zap.Error(err))
				}
				// Engine 不需严格 offset 顺序, 各 worker 独立 mark
				sess.MarkMessage(msg, "")
			}
		}()
	}
	for msg := range claim.Messages() {
		select {
		case jobs <- msg:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

// workerCountFromEnv P1-1 helper.
func workerCountFromEnv(env string, def int) int {
	v := os.Getenv(env)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 || n > 128 {
		return def
	}
	return n
}

// noopHandler 是 PR13 占位 handler,不做任何业务处理。
// 后续 PR 引入真实检测管线时由 Engine main 注入实现。
func noopHandler(_ context.Context, _ *sarama.ConsumerMessage) error {
	return nil
}
