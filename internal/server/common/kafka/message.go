package kafka

import "time"

// MQMessage 是写入 Kafka 的消息体（对应设计文档 § 3.2.2）
// 使用 JSON 序列化，兼容 Consumer 侧解析
type MQMessage struct {
	DataType     int32     `json:"data_type"`
	AgentID      string    `json:"agent_id"`
	Body         []byte    `json:"body"`       // 原始 protobuf 编码数据
	AgentTime    int64     `json:"agent_time"` // Agent 端时间戳（Unix 秒）
	SvrTime      int64     `json:"svr_time"`   // AC 接收时间戳（Unix 秒）
	Hostname     string    `json:"hostname"`
	IntranetIPv4 string    `json:"intranet_ipv4,omitempty"`
	ExtranetIPv4 string    `json:"extranet_ipv4,omitempty"`
	Version      string    `json:"version,omitempty"`
	Product      string    `json:"product,omitempty"`
	TraceID      string    `json:"trace_id"` // 端到端追踪 ID
	ReceivedAt   time.Time `json:"received_at"`
	ACID         string    `json:"ac_id,omitempty"` // 接收该消息的 AC 实例 ID（Consumer 用于写 agent:ac: Redis 映射）
}

// DLQMessage 是写入 DLQ 的消息体，包含原始消息 + 错误信息
type DLQMessage struct {
	Original    *MQMessage `json:"original"`
	Error       string     `json:"error"`
	SourceTopic string     `json:"source_topic"`
	RetryCount  int        `json:"retry_count"`
	FailedAt    time.Time  `json:"failed_at"`
}
