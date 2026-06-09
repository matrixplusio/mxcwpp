// Package commandsub 是 AC 的 Engine 命令订阅器。
//
// 职责: 订阅 Kafka mxsec.engine.command Topic, 把 Engine 产出的命令
// 解码并通过 transfer.Service 推送到目标 Agent (gRPC stream)。
//
// 实现 engine/scheduler.EngineCommander interface,
// 完成 v2.0 "Engine 决策 / AC 接入" 的 Kafka 解耦闭环。
//
// 数据流:
//
//	Engine.Scheduler → kafka.Produce(mxsec.engine.command)
//	                              │
//	                              v
//	                AC.commandsub.Consumer.ConsumeClaim
//	                              │
//	                              v
//	                AC.transfer.Service.PushToAgent
//	                              │
//	                              v
//	                Agent (gRPC stream)
//
// 设计文档: internal/server/engine/scheduler/README.md §2
package commandsub

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// ConsumerGroupID 是 AC 订阅 Engine 命令使用的 Kafka ConsumerGroup。
// 与 Consumer "mxsec-writers" / Engine "mxsec-engine" 完全隔离,
// 保证 Engine 命令既被 Consumer 持久化,又被 AC 真实推送 Agent。
const ConsumerGroupID = "mxsec-ac-command"

// CommandMessage 是 Engine 产出的命令 (落 Kafka mxsec.engine.command)。
//
// 字段对齐 docs/operating-modes.md §6 告警 schema 的 action 字段格式,
// 这样 Engine 在 protect 模式下产生的处置 action 可直接走该 Topic 路由。
type CommandMessage struct {
	TenantID    string          `json:"tenant_id"`
	AgentIDs    []string        `json:"agent_ids"`    // 批量目标 Agent ID
	CommandType string          `json:"command_type"` // rule_sync / ioc_sync / isolate / kill / ip_block ...
	Payload     json.RawMessage `json:"payload"`      // 命令负载,由 CommandType 决定结构
	IssuedAt    int64           `json:"issued_at"`    // Unix ms
	TraceID     string          `json:"trace_id,omitempty"`
	IdempotKey  string          `json:"idempot_key,omitempty"` // 幂等 key,AC 用作去重
}

// AgentPusher 是 AC 端把命令推到 Agent 的抽象 (由 transfer.Service 实现)。
//
// 解耦 commandsub 与 transfer 内部细节,
// 测试时可注入 mock。
type AgentPusher interface {
	PushToAgent(agentID string, command []byte) (bool, error)
	PushToAgents(agentIDs []string, command []byte) (succeeded, failed int, err error)
}

// Consumer 是 AC 订阅 mxsec.engine.command 的消费器。
type Consumer struct {
	brokers []string
	group   sarama.ConsumerGroup
	pusher  AgentPusher
	logger  *zap.Logger
	wg      sync.WaitGroup
}

// NewConsumer 构造命令订阅消费器。
func NewConsumer(brokers []string, pusher AgentPusher, logger *zap.Logger) (*Consumer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if pusher == nil {
		return nil, fmt.Errorf("commandsub: pusher must not be nil")
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("commandsub: brokers must not be empty")
	}

	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRoundRobin()}
	cfg.Consumer.Offsets.Initial = sarama.OffsetNewest
	cfg.Consumer.Return.Errors = true

	g, err := sarama.NewConsumerGroup(brokers, ConsumerGroupID, cfg)
	if err != nil {
		return nil, fmt.Errorf("commandsub: new consumer group: %w", err)
	}
	return &Consumer{
		brokers: brokers,
		group:   g,
		pusher:  pusher,
		logger:  logger,
	}, nil
}

// Start 启动消费循环。
func (c *Consumer) Start(ctx context.Context) {
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		h := &handler{pusher: c.pusher, logger: c.logger}
		for {
			if err := c.group.Consume(ctx, []string{"mxsec.engine.command"}, h); err != nil {
				if ctx.Err() != nil {
					return
				}
				c.logger.Error("AC commandsub consume error", zap.Error(err))
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		for err := range c.group.Errors() {
			c.logger.Warn("AC commandsub error event", zap.Error(err))
		}
	}()
	c.logger.Info("AC commandsub started",
		zap.String("group_id", ConsumerGroupID),
		zap.String("topic", "mxsec.engine.command"),
	)
}

// Close 优雅关闭。
func (c *Consumer) Close() error {
	err := c.group.Close()
	c.wg.Wait()
	return err
}

type handler struct {
	pusher AgentPusher
	logger *zap.Logger
}

func (h *handler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *handler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *handler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var cmd CommandMessage
		if err := json.Unmarshal(msg.Value, &cmd); err != nil {
			h.logger.Warn("AC commandsub decode failed,丢弃",
				zap.String("topic", msg.Topic),
				zap.Int32("partition", msg.Partition),
				zap.Int64("offset", msg.Offset),
				zap.Error(err),
			)
			sess.MarkMessage(msg, "")
			continue
		}

		if len(cmd.AgentIDs) == 0 {
			h.logger.Warn("AC commandsub: 空 AgentIDs",
				zap.String("command_type", cmd.CommandType))
			sess.MarkMessage(msg, "")
			continue
		}

		// 单条 vs 批量: 一条命令面向一个 Agent → PushToAgent;多个 → PushToAgents
		if len(cmd.AgentIDs) == 1 {
			ok, err := h.pusher.PushToAgent(cmd.AgentIDs[0], cmd.Payload)
			if err != nil {
				h.logger.Warn("AC commandsub push 失败",
					zap.String("agent_id", cmd.AgentIDs[0]),
					zap.String("command_type", cmd.CommandType),
					zap.Error(err))
			} else if !ok {
				h.logger.Debug("Agent 离线,命令未送达",
					zap.String("agent_id", cmd.AgentIDs[0]))
			}
		} else {
			succ, fail, err := h.pusher.PushToAgents(cmd.AgentIDs, cmd.Payload)
			if err != nil {
				h.logger.Warn("AC commandsub batch push 失败",
					zap.Int("total", len(cmd.AgentIDs)),
					zap.Int("succeeded", succ),
					zap.Int("failed", fail),
					zap.String("command_type", cmd.CommandType),
					zap.Error(err))
			} else {
				h.logger.Debug("AC commandsub batch push 完成",
					zap.Int("succeeded", succ),
					zap.Int("failed", fail),
					zap.String("command_type", cmd.CommandType))
			}
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}
