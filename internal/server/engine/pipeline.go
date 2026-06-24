package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/internal/common/jsonx"
	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
)

// Pipeline 把 Kafka 消息按"规则 → 序列 → ML → Storyline"4 层引擎处理,
// 命中告警时通过 AlertProducer 发到 mxcwpp.engine.alert。
//
// 设计文档: docs/engine-detection-design.md
type Pipeline struct {
	producer *AlertProducer
	resolver *mode.MemoryResolver
	stages   []Stage
	logger   *zap.Logger
}

// Stage 是 Pipeline 中的一层检测处理器。
//
// 每个 Stage 接收 PipelineEvent (从 Kafka 消息解码得到),
// 检测命中时返回 Alert(s),不命中返回空 slice。
type Stage interface {
	Name() string
	Process(ctx context.Context, ev PipelineEvent) ([]Alert, error)
}

// PipelineEvent 是 Engine 内部统一事件 schema (解码自 Kafka).
type PipelineEvent struct {
	TenantID   string          `json:"tenant_id"`
	AgentID    string          `json:"agent_id"`
	HostID     string          `json:"host_id"`
	DataType   int32           `json:"data_type"`
	Topic      string          `json:"-"`
	Partition  int32           `json:"-"`
	Offset     int64           `json:"-"`
	ReceivedAt time.Time       `json:"received_at"`
	Payload    json.RawMessage `json:"payload"`
	// P0-5: Pipeline 顶层预解码 fields, 各 stage 共享避免 3+ 次 jsonx.Unmarshal.
	// 用 *fieldsCache 指针, 多个 ev 值拷贝共享同一 cache (struct copy 仅复制 pointer).
	fieldsCache *fieldsCache `json:"-"`
}

// fieldsCache 保存解码后的 fields, 多 stage 共享.
type fieldsCache struct {
	fields map[string]string
	err    error
	done   bool
}

// Fields P0-5: lazy 一次解码, 多 stage 共享.
//
// 调用者 ev.Fields(), 内部第一次访问触发解码 + 写 cache; 后续直接命中.
// 单 goroutine 走完所有 stage 时安全 (Pipeline 串行 stage 走顺序).
func (ev *PipelineEvent) Fields() (map[string]string, error) {
	if ev.fieldsCache == nil {
		ev.fieldsCache = &fieldsCache{}
	}
	c := ev.fieldsCache
	if c.done {
		return c.fields, c.err
	}
	c.fields, c.err = payloadToFields(ev.Payload)
	c.done = true
	return c.fields, c.err
}

// Alert 是 Pipeline 产出的告警 (转换为 AlertEnvelope 后推送)。
type Alert struct {
	AlertID        string
	RuleID         string
	Severity       string
	ATTCKTactic    string
	ATTCKTechnique string
	WouldAction    json.RawMessage
	Action         json.RawMessage
	Payload        json.RawMessage
}

// NewPipeline 构造检测管线。
func NewPipeline(producer *AlertProducer, resolver *mode.MemoryResolver, stages []Stage, logger *zap.Logger) *Pipeline {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolver == nil {
		resolver = mode.NewMemoryResolver(mode.Observe)
	}
	return &Pipeline{
		producer: producer,
		resolver: resolver,
		stages:   stages,
		logger:   logger,
	}
}

// Handler 把 Pipeline 包装成 engine.MessageHandler,
// 供 KafkaConsumer 注入。
func (p *Pipeline) Handler() MessageHandler {
	return func(ctx context.Context, msg *sarama.ConsumerMessage) error {
		ev, err := decodeEvent(msg)
		if err != nil {
			p.logger.Warn("engine pipeline decode failed",
				zap.String("topic", msg.Topic),
				zap.Int32("partition", msg.Partition),
				zap.Int64("offset", msg.Offset),
				zap.Error(err))
			return nil // 不阻塞 offset
		}
		ev.Topic = msg.Topic
		ev.Partition = msg.Partition
		ev.Offset = msg.Offset
		ev.ReceivedAt = time.Now().UTC()
		// P0-5: decodeEvent 若已预填 fieldsCache (protobuf Body 解码) 则保留, 否则 lazy 解.
		if ev.fieldsCache == nil {
			ev.fieldsCache = &fieldsCache{}
		}

		// 逐层处理
		for _, st := range p.stages {
			alerts, err := st.Process(ctx, ev)
			if err != nil {
				p.logger.Warn("stage error",
					zap.String("stage", st.Name()),
					zap.String("topic", ev.Topic),
					zap.Error(err))
				continue
			}
			for _, a := range alerts {
				if err := p.emitAlert(ctx, ev, a); err != nil {
					p.logger.Warn("emit alert failed", zap.Error(err))
				}
			}
		}
		return nil
	}
}

// emitAlert 把 Alert 转 AlertEnvelope 推到 mxcwpp.engine.alert,
// 根据当前 mode 决定 Action vs WouldAction 字段。
func (p *Pipeline) emitAlert(ctx context.Context, ev PipelineEvent, a Alert) error {
	if p.producer == nil {
		return nil
	}
	decision := p.resolver.Resolve(mode.Scope{
		TenantID: ev.TenantID,
		RuleID:   a.RuleID,
	})

	env := AlertEnvelope{
		AlertID:        a.AlertID,
		TenantID:       ev.TenantID,
		HostID:         ev.HostID,
		RuleID:         a.RuleID,
		Severity:       a.Severity,
		Mode:           string(decision.Mode),
		DetectedAt:     time.Now().UTC(),
		ATTCKTactic:    a.ATTCKTactic,
		ATTCKTechnique: a.ATTCKTechnique,
		Payload:        a.Payload,
	}

	// mode 决定 would_action vs action 字段填充
	if mode.ShouldEnforce(decision) {
		env.Action = a.Action
	} else {
		env.WouldAction = a.WouldAction
		// observe 模式下如果没有 WouldAction,用 Action 内容(预期动作描述)
		if len(env.WouldAction) == 0 && len(a.Action) > 0 {
			env.WouldAction = a.Action
		}
	}

	return p.producer.Publish(ctx, env)
}

// decodeEvent 解码 Kafka 消息为 PipelineEvent.
//
// 实际消息格式: Kafka msg.Value = JSON(kafka.MQMessage), MQMessage.Body = protobuf(bridge.Record).
// 流程: JSON 解 MQMessage → 取 AgentID/DataType + 顶层字段 → protobuf 解 Body 拿 fields map.
//
// AgentID 在 mxcwpp 模型里 = HostID (单租户). HostID 字段同时填充供 ev.HostID 用.
func decodeEvent(msg *sarama.ConsumerMessage) (PipelineEvent, error) {
	// 1. 顶层 MQMessage (JSON)
	var mq struct {
		DataType int32  `json:"data_type"`
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Body     []byte `json:"body"`
		TraceID  string `json:"trace_id"`
	}
	if err := jsonx.Unmarshal(msg.Value, &mq); err != nil {
		return PipelineEvent{}, fmt.Errorf("unmarshal MQMessage: %w", err)
	}

	ev := PipelineEvent{
		AgentID:  mq.AgentID,
		HostID:   mq.AgentID, // mxcwpp: AgentID = HostID
		DataType: mq.DataType,
		Payload:  msg.Value,
	}

	// 2. Body (protobuf bridge.Record) → fields map, 直接预填 cache
	if len(mq.Body) > 0 {
		rec := &bridge.Record{}
		if perr := proto.Unmarshal(mq.Body, rec); perr == nil && rec.Data != nil {
			fields := rec.Data.Fields
			if fields == nil {
				fields = make(map[string]string)
			}
			// 顶层 MQMessage 字段回填到 fields (CEL 规则需要)
			if fields["agent_id"] == "" {
				fields["agent_id"] = mq.AgentID
			}
			if fields["hostname"] == "" {
				fields["hostname"] = mq.Hostname
			}
			ev.fieldsCache = &fieldsCache{fields: fields, done: true}
		}
	}
	return ev, nil
}
