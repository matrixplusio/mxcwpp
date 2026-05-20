// Package consumer 实现 Kafka Consumer 服务
// 从各 Topic 消费 MQMessage，路由到 MySQL / ClickHouse 写入器
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/common/kafka"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/celengine"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/writer"
)

// agentACTTL 是 Redis 中 agent:ac:{agentID} key 的 TTL（3 倍心跳间隔）
const agentACTTL = 180 * time.Second

// Router 订阅所有业务 Topic，根据 DataType 路由到对应写入器
type Router struct {
	saramaConsumerGroupHandler
	group         sarama.ConsumerGroup
	mysql         *writer.MySQLWriter
	ch            *writer.ClickHouseWriter
	dlq           *DLQHandler
	redisClient   *redis.Client             // 可选，用于写 agent:ac: 映射
	celEngine     *celengine.Engine         // CEL 规则引擎（可选）
	alertGen      *celengine.AlertGenerator // CEL 告警生成器（可选）
	autoResponder *celengine.AutoResponder  // 自动响应执行器（可选）
	scanDetector  *celengine.ScanDetector   // 端口扫描检测器（可选）
	topics        []string
	logger        *zap.Logger
}

// NewRouter 创建 Router
// celEng 和 alertGen 可为 nil，此时跳过 CEL 规则评估
// autoResponder 可为 nil，此时跳过自动响应
// scanDetector 可为 nil，此时跳过端口扫描检测
func NewRouter(
	brokers []string,
	groupID string,
	topicPrefix string,
	mysql *writer.MySQLWriter,
	ch *writer.ClickHouseWriter,
	dlq *DLQHandler,
	redisClient *redis.Client, // 可为 nil，Redis 不可用时跳过 agent:ac: 写入
	celEng *celengine.Engine,
	alertGen *celengine.AlertGenerator,
	autoResponder *celengine.AutoResponder, // 可为 nil，跳过自动响应
	scanDetector *celengine.ScanDetector, // 可为 nil，端口扫描检测
	logger *zap.Logger,
) (*Router, error) {
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V2_6_0_0
	cfg.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRoundRobin()}
	cfg.Consumer.Offsets.Initial = sarama.OffsetNewest
	cfg.Consumer.Return.Errors = true

	group, err := sarama.NewConsumerGroup(brokers, groupID, cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 Kafka ConsumerGroup 失败: %w", err)
	}

	prefix := topicPrefix
	topics := []string{
		prefix + kafka.TopicHeartbeat,
		prefix + kafka.TopicEvents,
		prefix + kafka.TopicBaseline,
		prefix + kafka.TopicAsset,
		prefix + kafka.TopicCommandAck,
		prefix + kafka.TopicScanner,
		prefix + kafka.TopicEBPF,
		prefix + kafka.TopicRemediation,
	}

	return &Router{
		group:         group,
		mysql:         mysql,
		ch:            ch,
		dlq:           dlq,
		redisClient:   redisClient,
		celEngine:     celEng,
		alertGen:      alertGen,
		autoResponder: autoResponder,
		scanDetector:  scanDetector,
		topics:        topics,
		logger:        logger,
	}, nil
}

// Run 阻塞式消费，直到 ctx 取消
func (r *Router) Run(ctx context.Context) error {
	// 后台消费 sarama 错误
	go func() {
		for err := range r.group.Errors() {
			r.logger.Error("ConsumerGroup 错误", zap.Error(err))
		}
	}()

	for {
		if err := r.group.Consume(ctx, r.topics, r); err != nil {
			// ErrNotCoordinatorForConsumer / ErrRebalanceInProgress 是瞬态错误，等待后重试
			if err == sarama.ErrNotCoordinatorForConsumer || err == sarama.ErrRebalanceInProgress {
				r.logger.Warn("ConsumerGroup 协调者变更，等待重试", zap.Error(err))
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(3 * time.Second):
				}
				continue
			}
			return fmt.Errorf("消费循环退出: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// Close 关闭 ConsumerGroup
func (r *Router) Close() error {
	return r.group.Close()
}

// ConsumeClaim 实现 sarama.ConsumerGroupHandler，处理每条消息
func (r *Router) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case msg, ok := <-claim.Messages():
			if !ok {
				return nil
			}
			r.handleMessage(session, msg)
		case <-session.Context().Done():
			return nil
		}
	}
}

// handleMessage 解码 MQMessage 并路由到对应写入器
func (r *Router) handleMessage(session sarama.ConsumerGroupSession, raw *sarama.ConsumerMessage) {
	var msg kafka.MQMessage
	if err := json.Unmarshal(raw.Value, &msg); err != nil {
		r.logger.Error("反序列化 MQMessage 失败",
			zap.String("topic", raw.Topic),
			zap.Error(err),
		)
		session.MarkMessage(raw, "")
		return
	}

	var writeErr error
	switch {
	case msg.DataType == 1000:
		// 心跳：upsert hosts 表 + 写 Redis agent:ac: 映射 + 写 ClickHouse 指标
		writeErr = r.mysql.WriteHeartbeat(&msg)
		r.writeAgentACMapping(&msg)
		_ = r.ch.WriteHostMetrics(&msg)
	case msg.DataType == 1001:
		_ = r.ch.WriteHostMetrics(&msg) // 插件心跳，Phase 4 实现

	// 资产数据（5050~5060）
	case msg.DataType >= 5050 && msg.DataType <= 5060:
		writeErr = r.mysql.WriteAsset(&msg, msg.DataType)

	// FIM 事件
	case msg.DataType == 6001:
		writeErr = r.mysql.WriteFIMEvent(&msg)
		if writeErr == nil {
			_ = r.ch.WriteFIMEvent(&msg)
			r.evaluateCEL(&msg)
		}
	// FIM 任务完成
	case msg.DataType == 6002:
		writeErr = r.mysql.WriteFIMTaskComplete(&msg)

	// 基线检查结果
	case msg.DataType == 8000:
		writeErr = r.mysql.WriteBaseline(&msg)
	// 基线扫描任务完成
	case msg.DataType == 8001:
		writeErr = r.mysql.WriteTaskCompletion(&msg)
	// 修复结果
	case msg.DataType == 8003:
		writeErr = r.mysql.WriteFixResult(&msg)
	// 修复任务完成
	case msg.DataType == 8004:
		writeErr = r.mysql.WriteFixTaskComplete(&msg)

	// Scanner 扫描结果
	case msg.DataType == 7001:
		writeErr = r.mysql.WriteScanResult(&msg)
		if writeErr == nil {
			r.evaluateCEL(&msg)
		}
	// Scanner 任务完成
	case msg.DataType == 7002:
		writeErr = r.mysql.WriteScanTaskComplete(&msg)
	// Scanner 隔离/删除结果
	case msg.DataType == 7004:
		writeErr = r.mysql.WriteQuarantineResult(&msg)

	// eBPF 事件（3000-3002）
	case msg.DataType >= 3000 && msg.DataType <= 3002:
		_ = r.ch.WriteEBPFEvent(&msg)
		r.evaluateCEL(&msg)
		// 网络事件额外进行端口扫描检测
		if msg.DataType == 3002 {
			r.checkPortScan(&msg)
		}

	// 漏洞修复结果
	case msg.DataType == 9200:
		writeErr = r.mysql.WriteRemediationResult(&msg)

	// 命令执行回包
	case msg.DataType == 9999:
		writeErr = r.mysql.WriteCommandAck(&msg)

	default:
		r.logger.Debug("Consumer 忽略未路由的 DataType",
			zap.Int32("data_type", msg.DataType),
			zap.String("agent_id", msg.AgentID),
		)
	}

	if writeErr != nil {
		r.logger.Error("写入失败，转入 DLQ",
			zap.String("topic", raw.Topic),
			zap.Int32("data_type", msg.DataType),
			zap.String("agent_id", msg.AgentID),
			zap.Error(writeErr),
		)
		r.dlq.Send(raw.Topic, &msg, writeErr, 1)
	}

	// 不论成功失败，均标记 offset（失败消息已进 DLQ，不阻塞消费进度）
	session.MarkMessage(raw, "")
}

// evaluateCEL 解析消息字段并交给 CEL 引擎评估，命中规则时生成告警
func (r *Router) evaluateCEL(msg *kafka.MQMessage) {
	if r.celEngine == nil || r.alertGen == nil {
		return
	}

	fields, err := writer.ParseRecordFields(msg.Body)
	if err != nil {
		return
	}

	// 补充消息级别字段（Body 中可能没有）
	if fields["agent_id"] == "" {
		fields["agent_id"] = msg.AgentID
	}
	if fields["hostname"] == "" {
		fields["hostname"] = msg.Hostname
	}

	matched := r.celEngine.Evaluate(msg.DataType, fields)
	if len(matched) > 0 {
		r.alertGen.Generate(msg.AgentID, matched, fields)
		// 自动响应：critical 规则命中时下发 kill/隔离/阻断命令
		if r.autoResponder != nil {
			r.autoResponder.Execute(msg.AgentID, matched, fields)
		}
	}
}

// checkPortScan 对入站连接事件进行端口扫描检测
func (r *Router) checkPortScan(msg *kafka.MQMessage) {
	if r.scanDetector == nil {
		return
	}

	fields, err := writer.ParseRecordFields(msg.Body)
	if err != nil {
		return
	}

	// 仅处理入站连接（tcp_accept）
	if fields["event_type"] != "tcp_accept" {
		return
	}

	r.scanDetector.CheckIncomingConnection(
		msg.AgentID,
		fields["remote_addr"],
		fields["local_port"],
		fields,
	)
}

// writeAgentACMapping 将 agent:ac:{agentID}=acID 写入 Redis（TTL=180s）
// 供 Manager 查询 Agent 所在 AC 实例，用于精准任务路由
func (r *Router) writeAgentACMapping(msg *kafka.MQMessage) {
	if r.redisClient == nil || msg.ACID == "" {
		return
	}
	key := "agent:ac:" + msg.AgentID
	if err := r.redisClient.Set(context.Background(), key, msg.ACID, agentACTTL).Err(); err != nil {
		r.logger.Warn("写 agent:ac: Redis 映射失败",
			zap.String("agent_id", msg.AgentID),
			zap.String("ac_id", msg.ACID),
			zap.Error(err),
		)
	}
}
