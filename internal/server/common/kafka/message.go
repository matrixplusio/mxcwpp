package kafka

import (
	"sync"
	"time"
)

// P2-6: MQMessage sync.Pool 减 hot path alloc.
//
// Consumer router.handleMessage 每条消息 var msg MQMessage 栈分配本身廉价,
// 但 json.Unmarshal 把 Body []byte 拷到堆. Pool 化 MQMessage struct + Body buffer
// 减少 GC 压力. 调用方:
//
//	msg := kafka.GetMQMessage()
//	defer kafka.PutMQMessage(msg)
//	if err := json.Unmarshal(raw, msg); err != nil { ... }
//
// 注意: 调用方不能 keep 引用 msg 跨调用 (Body 切片会被复用).
var mqMessagePool = sync.Pool{
	New: func() any {
		return &MQMessage{}
	},
}

// GetMQMessage 取池化 MQMessage.
func GetMQMessage() *MQMessage {
	return mqMessagePool.Get().(*MQMessage)
}

// PutMQMessage 还池, reset 字段防内存泄漏.
func PutMQMessage(m *MQMessage) {
	if m == nil {
		return
	}
	// 小 Body 还池 (大 Body > 64KB 不还防 oversized 堆积)
	if cap(m.Body) > 64*1024 {
		m.Body = nil
	} else {
		m.Body = m.Body[:0]
	}
	m.DataType = 0
	m.AgentID = ""
	m.AgentTime = 0
	m.SvrTime = 0
	m.Hostname = ""
	m.IntranetIPv4 = ""
	m.ExtranetIPv4 = ""
	m.Version = ""
	m.Product = ""
	m.TraceID = ""
	m.ReceivedAt = time.Time{}
	m.ACID = ""
	mqMessagePool.Put(m)
}

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
