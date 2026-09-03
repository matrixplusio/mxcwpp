// Package gcppubsub 实现 GCP Pub/Sub 消费者，从 Cloud Logging 接收 GKE 审计日志
package gcppubsub

import (
	"context"
	"encoding/json"
	"time"

	"cloud.google.com/go/pubsub" //nolint:staticcheck // TODO: migrate to cloud.google.com/go/pubsub/v2
	"go.uber.org/zap"
	"google.golang.org/api/option"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ClusterGCPConfig 单个集群的 GCP Pub/Sub 配置（从数据库读取）
type ClusterGCPConfig struct {
	ClusterID       uint
	ClusterName     string
	ProjectID       string
	Subscription    string
	CredentialsJSON string // SA JSON Key 内容；空值使用 ADC
}

// Consumer GCP Pub/Sub 消费者，从 Cloud Logging 接收 GKE 审计日志并转交给审计事件处理器
type Consumer struct {
	cfg       ClusterGCPConfig
	db        *gorm.DB
	logger    *zap.Logger
	processor *kube.KubeAuditProcessor
}

// NewConsumer 创建 Pub/Sub 消费者
func NewConsumer(cfg ClusterGCPConfig, db *gorm.DB, logger *zap.Logger, alarmService *kube.KubeAlarmService) *Consumer {
	return &Consumer{
		cfg:       cfg,
		db:        db,
		logger:    logger,
		processor: kube.NewKubeAuditProcessor(db, logger, alarmService),
	}
}

// Start 启动 Pub/Sub 消费者（阻塞，应在 goroutine 中调用）
func (c *Consumer) Start(ctx context.Context) {
	c.logger.Info("GCP Pub/Sub 消费者启动中",
		zap.String("project_id", c.cfg.ProjectID),
		zap.String("subscription", c.cfg.Subscription),
		zap.Uint("cluster_id", c.cfg.ClusterID),
	)

	// 创建 Pub/Sub 客户端
	var opts []option.ClientOption
	if c.cfg.CredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(c.cfg.CredentialsJSON))) //nolint:staticcheck // TODO: migrate to newer auth approach
	}

	client, err := pubsub.NewClient(ctx, c.cfg.ProjectID, opts...)
	if err != nil {
		c.logger.Error("创建 Pub/Sub 客户端失败", zap.Error(err), zap.Uint("cluster_id", c.cfg.ClusterID))
		return
	}
	defer client.Close()

	sub := client.Subscription(c.cfg.Subscription)
	sub.ReceiveSettings.MaxOutstandingMessages = 100

	c.logger.Info("GCP Pub/Sub 消费者已启动，开始接收消息",
		zap.Uint("cluster_id", c.cfg.ClusterID),
	)

	// Receive 阻塞直到 ctx 取消
	if err := sub.Receive(ctx, c.handleMessage); err != nil {
		if ctx.Err() != nil {
			c.logger.Info("GCP Pub/Sub 消费者已停止（context 取消）", zap.Uint("cluster_id", c.cfg.ClusterID))
			return
		}
		c.logger.Error("Pub/Sub Receive 异常退出", zap.Error(err), zap.Uint("cluster_id", c.cfg.ClusterID))

		// 自动重连：等待后重试
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
			c.logger.Info("Pub/Sub 消费者尝试重连", zap.Uint("cluster_id", c.cfg.ClusterID))
			c.Start(ctx)
		}
	}
}

// handleMessage 处理单条 Pub/Sub 消息。
//
// 可靠性语义：处理成功（或消息本就无需处理）才 Ack；持久化失败则 Nack 触发重投（at-least-once），
// 避免原先 `defer msg.Ack()` 无论写入成败都 Ack 的 at-most-once 缺陷（写失败即丢）。重投上限与
// 死信由 Pub/Sub 订阅侧的 dead-letter policy 承接，与 Kafka 路径的 DLQ 语义对齐。
// 解析失败 / 集群未接入 / 无有效事件属"已正确处理，无需落库"，Ack 避免毒消息无限重投。
func (c *Consumer) handleMessage(_ context.Context, msg *pubsub.Message) {
	// 解析 Cloud Logging LogEntry
	var logEntry LogEntry
	if err := json.Unmarshal(msg.Data, &logEntry); err != nil {
		c.logger.Debug("解析 Pub/Sub 消息失败，跳过", zap.Error(err))
		msg.Ack()
		return
	}

	// 提取集群名称
	clusterName := logEntry.Resource.Labels.ClusterName
	if clusterName == "" {
		msg.Ack()
		return
	}

	// 查找对应集群
	var cluster model.KubeCluster
	if err := c.db.Where("name = ?", clusterName).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.logger.Debug("Pub/Sub 消息对应的集群未接入，跳过",
				zap.String("cluster_name", clusterName))
			msg.Ack()
			return
		}
		// 非 NotFound 的查询错误可能是 DB 抖动，Nack 重投避免丢事件。
		c.logger.Warn("查询集群失败，Nack 重投",
			zap.String("cluster_name", clusterName), zap.Error(err))
		msg.Nack()
		return
	}

	// 转换为 AuditEvent
	events := TransformLogEntry(&logEntry)
	if len(events) == 0 {
		msg.Ack()
		return
	}

	// 交给审计事件处理器；持久化失败则 Nack 重投。
	if err := c.processor.ProcessAuditEvents(cluster, events); err != nil {
		c.logger.Warn("处理审计事件失败，Nack 重投",
			zap.Uint("cluster_id", c.cfg.ClusterID), zap.Error(err))
		msg.Nack()
		return
	}
	msg.Ack()
}
