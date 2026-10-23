package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/internal/common/jsonx"
	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/risk"
)

// Pipeline 把 Kafka 消息按"规则 → 序列 → ML → Storyline"4 层引擎处理,
// 命中告警时通过 AlertProducer 发到 mxcwpp.engine.alert。
//
// 设计文档: docs/engine-detection-design.md
type Pipeline struct {
	producer    *AlertProducer
	alertWriter *StageAlertWriter
	resolver    *mode.MemoryResolver
	stages      []Stage
	logger      *zap.Logger
	// enrich 在各阶段之前给事件补字段（见 SetEnricher）。为空时不做。
	enrich func(ev PipelineEvent, fields map[string]string)
	// risk 实体风险累积（见 WithRisk）。为空时不做。
	risk *risk.Accumulator
}

// SetEnricher 注入事件补全。须在开始处理事件之前设置。
func (p *Pipeline) SetEnricher(fn func(ev PipelineEvent, fields map[string]string)) {
	p.enrich = fn
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
	TenantID   string    `json:"tenant_id"`
	AgentID    string    `json:"agent_id"`
	HostID     string    `json:"host_id"`
	DataType   int32     `json:"data_type"`
	Topic      string    `json:"-"`
	Partition  int32     `json:"-"`
	Offset     int64     `json:"-"`
	ReceivedAt time.Time `json:"received_at"`
	// EventTime Kafka 消息时间（生产者写入时刻）。积压追赶时它比 ReceivedAt 更接近事件发生时间。
	EventTime time.Time       `json:"-"`
	Payload   json.RawMessage `json:"payload"`
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
	// 以下供风险累积使用，不进 Kafka 消息。
	RuleName string
	Category string
	// Shadow 规则处于影子（或草稿）阶段：命中只用于观察，不参与风险累积。
	Shadow bool
}

// WithStageAlertWriter 注入落库器，让不自带落库能力的 Stage 的告警也能进 alerts 表。
//
// 只对未实现 selfPersistingStage 的 Stage 生效：CEL / Sequence / IOC 已通过
// AlertGenerator 自行落库，再写一遍会在界面上出现两条同源告警。
func (p *Pipeline) WithStageAlertWriter(w *StageAlertWriter) *Pipeline {
	p.alertWriter = w
	return p
}

// selfPersistingStage 由自行把告警写进 alerts 表的 Stage 实现。
// 流水线据此跳过统一落库，避免同一次命中被写两遍。
type selfPersistingStage interface {
	PersistsOwnAlerts() bool
}

// stageSelfPersists 判断 Stage 是否自带落库。
func stageSelfPersists(st Stage) bool {
	sp, ok := st.(selfPersistingStage)
	return ok && sp.PersistsOwnAlerts()
}

// NewPipeline 构造检测管线。
func NewPipeline(producer *AlertProducer, resolver *mode.MemoryResolver, stages []Stage, logger *zap.Logger) *Pipeline {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolver == nil {
		resolver = mode.NewMemoryResolver(mode.Observe)
	}
	// 预热每个已注册 Stage 的告警计数器。
	//
	// CounterVec 的时间序列只在第一次 Inc 时才创建，所以一个从未产出过告警的
	// Stage，它的 stage_alerts_total 根本不存在——不是 0，是查不到。
	// 结果是「这个 Stage 在正常工作但没有威胁」和「这个 Stage 从未真正跑过」
	// 在监控上完全一样：都查不到数据，也都没法写成告警条件。
	//
	// 预置为 0 之后，序列始终存在，「长期零产出」才成为一个可观测、可告警的事实。
	// 零产出本身不代表故障（没有威胁时本就该是 0），但它必须是看得见的零。
	PrewarmStageMetrics(stages)

	return &Pipeline{
		producer: producer,
		resolver: resolver,
		stages:   stages,
		logger:   logger,
	}
}

// PrewarmStageMetrics 为每个 Stage 预置计数器，使其从注册那一刻起就有值。
func PrewarmStageMetrics(stages []Stage) {
	for _, st := range stages {
		if st == nil {
			continue
		}
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			Metrics().StageAlerts.WithLabelValues(st.Name(), sev).Add(0)
		}
		Metrics().StageErrors.WithLabelValues(st.Name()).Add(0)
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
		ev.EventTime = msg.Timestamp
		// P0-5: decodeEvent 若已预填 fieldsCache (protobuf Body 解码) 则保留, 否则 lazy 解.
		if ev.fieldsCache == nil {
			ev.fieldsCache = &fieldsCache{}
		}

		// 文件与网络事件只带进程号。先补上程序信息，后面的自排除与各阶段的规则才看得到 exe。
		if p.enrich != nil {
			if fields, ferr := ev.Fields(); ferr == nil {
				p.enrich(ev, fields)
			}
		}

		// 自排除：EDR 不检测自身安全 agent / 插件进程的行为。
		// collector 等插件做资产采集(读 /etc/passwd /proc、写状态文件、连 AC、DNS 解析)
		// 会触发枚举/隐藏文件/外连/DNS 等 CEL 规则,造成大量自检测误报(单条规则可命中上千次)。
		// 凡 exe 属 agent 自身进程树(/var/lib/mxcwpp-agent/ 下插件 或 agent 主程序)的事件直接跳过检测。
		if isAgentSelfEvent(ev) {
			return nil
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
			selfPersists := stageSelfPersists(st)
			for _, a := range alerts {
				// 自行落库的阶段每次命中都会返回一条用于外发，那是命中次数不是告警数；
				// 它们的计数由落库处的回调在「新开告警」时上报（见 SetAlertObserver），这里不重复计。
				if !selfPersists {
					RecordAlert(st.Name(), a.RuleID, a.Severity)
				}
				// 不自带落库的 Stage 统一在此落库。此前它们只把告警推到
				// mxcwpp.engine.alert，而该 topic 无人消费——检测在跑，界面上永远看不到。
				if !selfPersists && p.alertWriter != nil {
					if err := p.alertWriter.Persist(st.Name(), ev, a); err != nil {
						p.logger.Error("stage 告警落库失败（该告警不会出现在界面上）",
							zap.String("stage", st.Name()), zap.Error(err))
					}
				}
				if p.risk != nil {
					p.observeRisk(st.Name(), ev, a)
				}
				if err := p.emitAlert(ctx, st.Name(), ev, a); err != nil {
					p.logger.Warn("emit alert failed", zap.Error(err))
				}
			}
		}
		return nil
	}
}

// agent 自身及插件的可执行路径。这些进程的行为（资产采集、插件运行、与 AC 通信）不应被自家 EDR 当作攻击检测。
const (
	agentSelfBinary = "/usr/bin/mxcwpp-agent"  // agent 主程序，只认这一个全路径
	agentSelfDir    = "/var/lib/mxcwpp-agent/" // 工作目录：插件及其 bin/clamscan、bin/yr；只有 root 能写

	dataTypeMemory = 3004 // agent 内存威胁扫描（memfd / 已删除可执行文件 / 匿名可执行内存）
)

// isAgentSelfEvent 判断事件是否由 agent 自身进程发起。
//
// eBPF 的 exec 事件里 exe 是调用方传给 execve 的原样路径，任何用户都能执行
// /var/lib/mxcwpp-agent/../../../tmp/x，按字符串前缀判断就会把它整条丢掉、所有检测阶段都看不到。
// 所以只接受已规范化的绝对路径，并且必须能确认是宿主机上的 root：
//   - 容器里的路径是容器自己的文件系统，容器 root 能自建 /var/lib/mxcwpp-agent/x，uid 也是 0；
//     agent 只以宿主机进程部署，容器里的事件一律不算自身。
//   - 不带 uid 的事件（无 eBPF 时的降级采集）确认不了身份，按不是自身处理：
//     多报几条 agent 自己的事件，好过让伪装成 agent 的进程整条消失。
//   - 从 /proc 补的进程事件（启动快照、对账补发）和内存威胁事件不带容器标记，exe 又是 readlink
//     出来的容器内路径，分不清是不是容器 root 自建的同名路径，不参与排除。内存扫描在 agent 侧
//     已经跳过了自身进程，服务端不需要再排除一次。
func isAgentSelfEvent(ev PipelineEvent) bool {
	fields, err := ev.Fields()
	if err != nil {
		return false
	}
	if fields["uid"] != "0" || fields["in_container"] == "true" || ev.DataType == dataTypeMemory {
		return false
	}
	if src := fields["source"]; src == "proc_snapshot" || src == "reconciliation" {
		return false
	}
	exe := fields["exe"]
	// agent 包升级后主程序还没重启时，readlink 得到的路径带这个后缀；插件目录不放宽。
	if exe == agentSelfBinary+" (deleted)" {
		return true
	}
	if exe == "" || !filepath.IsAbs(exe) || filepath.Clean(exe) != exe || strings.HasSuffix(exe, " (deleted)") {
		return false
	}
	return exe == agentSelfBinary || strings.HasPrefix(exe, agentSelfDir)
}

// emitAlert 把 Alert 转 AlertEnvelope 推到 mxcwpp.engine.alert,
// 根据当前 mode 决定 Action vs WouldAction 字段。
func (p *Pipeline) emitAlert(ctx context.Context, stage string, ev PipelineEvent, a Alert) error {
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
		Stage:          stage,
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
