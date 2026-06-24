package consumer

import (
	"encoding/json"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
)

// DLQHandler 将消费失败的消息写入 Dead Letter Queue Topic
type DLQHandler struct {
	producer kafka.Producer
	logger   *zap.Logger
}

// NewDLQHandler 创建 DLQHandler
func NewDLQHandler(producer kafka.Producer, logger *zap.Logger) *DLQHandler {
	return &DLQHandler{producer: producer, logger: logger}
}

// Send 将原始消息和错误信息发送到对应的 DLQ Topic
func (h *DLQHandler) Send(sourceTopic string, msg *kafka.MQMessage, cause error, retryCount int) {
	dlqMsg := &kafka.DLQMessage{
		Original:    msg,
		Error:       cause.Error(),
		SourceTopic: sourceTopic,
		RetryCount:  retryCount,
		FailedAt:    time.Now(),
	}

	body, err := json.Marshal(dlqMsg)
	if err != nil {
		h.logger.Error("序列化 DLQ 消息失败", zap.Error(err))
		return
	}

	dlqTopic := kafka.DLQTopic(sourceTopic)
	dlqMQMsg := &kafka.MQMessage{
		DataType:  msg.DataType,
		AgentID:   msg.AgentID,
		Body:      body,
		AgentTime: msg.AgentTime,
		SvrTime:   time.Now().Unix(),
		Hostname:  msg.Hostname,
		TraceID:   msg.TraceID,
	}

	if err := h.producer.Send(dlqTopic, msg.AgentID, dlqMQMsg); err != nil {
		h.logger.Error("写入 DLQ 失败",
			zap.String("dlq_topic", dlqTopic),
			zap.String("agent_id", msg.AgentID),
			zap.Error(err),
		)
	}
}

// saramaConsumerGroupHandler 是 sarama.ConsumerGroupHandler 的空实现基类
// 嵌入到 Router 中以减少样板代码
//
//nolint:unused // 接口实现基类，通过嵌入 Router 间接被 sarama 调用
type saramaConsumerGroupHandler struct{}

//nolint:unused
func (saramaConsumerGroupHandler) Setup(_ sarama.ConsumerGroupSession) error { return nil }

//nolint:unused
func (saramaConsumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
