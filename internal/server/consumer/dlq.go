package consumer

import (
	"encoding/json"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
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
		// 数据保全的最后一米失守：处理失败已转 DLQ 保底，连 DLQ 也没写进去，这条消息真的没了。
		// 只打日志无法计量也无法告警，必须计数——该指标非零即代表已发生不可恢复的丢失。
		consumermetrics.RecordDLQWriteFailure(dlqTopic)
		h.logger.Error("写入 DLQ 失败，消息已不可恢复地丢失",
			zap.String("dlq_topic", dlqTopic),
			zap.Int32("data_type", msg.DataType),
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
