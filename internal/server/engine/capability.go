package engine

// 运行时能力清单（E-WIRE-1）。
//
// 这份清单存在的理由：代码里有 19 个检测 Stage 的构造器，但只有 8 个真的接进了
// 流水线；接进去的里面还有两个把告警发往一个没有任何消费者的 topic。也就是说
// "有代码"和"能力在跑"之间隔着两道口子，而此前没有任何机制能说清一个 Stage
// 落在哪一档——只能靠人工 grep，数出来的数字还互相对不上。
//
// 清单是对外承诺的事实基线：只有 Status 为 StatusActive 的能力才允许在方案、
// 官网或 POC 里宣称。CI（capability_test.go）双向比对本清单与真实代码——
// 新增构造器未登记、登记为已接线但流水线里没有、登记未接线却在流水线里，
// 三种情况都会让测试失败，杜绝"清单说有、代码没有"或反过来。
type CapabilityStatus string

const (
	// StatusActive 已接入流水线，且告警有实际去处（可被查询/通知）。
	StatusActive CapabilityStatus = "active"
	// StatusDeadEnd 已接入流水线，但告警发往无人消费的去处——跑了等于没跑。
	StatusDeadEnd CapabilityStatus = "dead_end"
	// StatusStarved 已接入流水线、告警去处也正常，但它依赖的输入在系统中
	// 不存在（没有任何采集器产生该字段/事件），因此永远不会产出。
	//
	// 与 DeadEnd 的区别在方向：DeadEnd 是输出端没人接，Starved 是输入端没人喂。
	// 单独设一档是因为这类失效最难发现——Stage 注册了、指标导出了、状态表建了、
	// 告警规则配了，一切结构完整，只是管道从头到尾是空的。
	StatusStarved CapabilityStatus = "starved"
	// StatusUnwired 有构造器但从未接入流水线，纯代码。
	StatusUnwired CapabilityStatus = "unwired"
)

// AlertSink 描述一个 Stage 的告警去向。
type AlertSink string

const (
	// SinkAlertsTable 经 AlertGenerator 直落 alerts 表，前端可查、通知可发。
	SinkAlertsTable AlertSink = "alerts_table"
	// SinkStorylineTopic 落攻击故事线专用 topic，有独立消费者。
	SinkStorylineTopic AlertSink = "storyline_topic"
	// SinkEngineAlertTopic 落 mxcwpp.engine.alert。该 topic 至今无任何消费者，
	// 因此不能作为告警的唯一去处。流水线仍会向它发布（供未来外部订阅），
	// 但所有 Stage 的告警落库已改走 alerts 表，不再依赖它。
	SinkEngineAlertTopic AlertSink = "engine_alert_topic"
	// SinkNone 未接线，无从谈及去向。
	SinkNone AlertSink = "none"
)

// Capability 是一项检测能力的声明。
type Capability struct {
	// Name 能力名，与构造器一一对应。
	Name string `json:"name"`
	// Constructor 构造函数名，CI 据此与包内实际定义比对。
	Constructor string `json:"constructor"`
	// Status 见 CapabilityStatus。
	Status CapabilityStatus `json:"status"`
	// Sink 告警去向。
	Sink AlertSink `json:"alert_sink"`
	// Note 补充说明，尤其是不可用的原因。
	Note string `json:"note,omitempty"`
}

// Wired 表示该能力是否已接入引擎流水线（含接了但去处无人消费的情况）。
func (c Capability) Wired() bool { return c.Status != StatusUnwired }

// Usable 表示该能力是否真的能产生用户看得见的结果。
// 只有 Usable 的能力允许对外宣称。
func (c Capability) Usable() bool { return c.Status == StatusActive }

// Capabilities 是运行时能力清单。
//
// 修改本清单必须与代码同步：CI 会双向校验。
var Capabilities = []Capability{
	// --- 已接线且告警可达 ---
	{Name: "cel_rule", Constructor: "NewCelRuleStage", Status: StatusActive, Sink: SinkAlertsTable},
	{Name: "sequence", Constructor: "NewSequenceStage", Status: StatusActive, Sink: SinkAlertsTable},
	{Name: "ioc_match", Constructor: "NewIOCStage", Status: StatusActive, Sink: SinkAlertsTable},
	{Name: "port_scan", Constructor: "NewScanStage", Status: StatusActive, Sink: SinkAlertsTable},

	// 以下三个此前只把告警推到 mxcwpp.engine.alert（无消费者），现由流水线统一落库。
	{Name: "privilege", Constructor: "NewPrivilegeStage", Status: StatusActive, Sink: SinkAlertsTable},
	{Name: "rasp", Constructor: "NewRASPStage", Status: StatusActive, Sink: SinkAlertsTable},
	{Name: "anti_rootkit", Constructor: "NewAntiRootkitStage", Status: StatusActive, Sink: SinkAlertsTable,
		Note: "落库路径已通；检出逻辑本身尚未经端到端验证"},

	{Name: "abnormal_login", Constructor: "NewAbnormalLoginStage", Status: StatusStarved, Sink: SinkAlertsTable,
		Note: "Stage 已接线、去处正常，但输入不存在：它读 fields[\"log_msg\"] 判断 " +
			"\"Accepted\" / \"session opened\"，而全系统没有任何采集器产生该字段——" +
			"agent 侧无日志采集（未读 /var/log/secure、auth.log，未订阅 journald），" +
			"事件面只有 eBPF 的进程/文件/网络/DNS 四类。因此 Ingest 永不执行，" +
			"host_login_profile_states 恒空，三个 hosts_learning/_graduated/_suppressed " +
			"指标恒为 0。恢复此能力需要新增日志采集管道（agent 采集 + DataType + " +
			"consumer 路由），属新增能力而非修复"},
	{Name: "webshell", Constructor: "NewWebshellStage", Status: StatusActive, Sink: SinkAlertsTable,
		Note: "已接线；正常语料零误命中"},
	{Name: "brute_force", Constructor: "NewBruteForceStage", Status: StatusStarved, Sink: SinkAlertsTable,
		Note: "阈值逻辑（5 分钟窗口 5 次失败，成功登录清零）已实现且已接线，" +
			"但与 abnormal_login 依赖同一个不存在的输入 fields[\"log_msg\"]，" +
			"因此从未产出。恢复条件同 abnormal_login"},
	{Name: "reverse_shell", Constructor: "NewReverseShellStage", Status: StatusActive, Sink: SinkAlertsTable,
		Note: "已接线；正常语料零误命中，检出侧尚未做端到端验证"},
	{Name: "priv_escalation", Constructor: "NewPrivEscalationStage", Status: StatusActive, Sink: SinkAlertsTable,
		Note: "已接线；正常语料零误命中（不把日常 sudo 当信号）"},
	{Name: "rootkit", Constructor: "NewRootkitStage", Status: StatusActive, Sink: SinkAlertsTable,
		Note: "已接线；已排除包管理器写 systemd/cron 的常规行为，正常语料零误命中"},

	// --- 有构造器但未接入本进程流水线 ---
	{Name: "storyline", Constructor: "NewStorylineStage", Status: StatusUnwired, Sink: SinkNone,
		Note: "攻击故事线聚合由 consumer 进程独占（cmd/server/consumer/main.go），" +
			"那里才有 SetClickHouse + SetEventsTarget + StartFlush 的完整接线。" +
			"engine 曾装配本 Stage 但从不调 StartFlush：事件只堆在内存里，永不落库。" +
			"重新接线前必须先解决双写与写入目标路由，否则会重现 2026-08 的 storyline_events 撑爆库事故",
	},
}

// CapabilitySummary 是清单的统计摘要。
type CapabilitySummary struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	DeadEnd  int `json:"dead_end"`
	Starved  int `json:"starved"`
	Unwired  int `json:"unwired"`
	Declared int `json:"declarable"` // 允许对外宣称的数量（= Active）
}

// SummarizeCapabilities 汇总清单。
func SummarizeCapabilities() CapabilitySummary {
	s := CapabilitySummary{Total: len(Capabilities)}
	for _, c := range Capabilities {
		switch c.Status {
		case StatusActive:
			s.Active++
		case StatusDeadEnd:
			s.DeadEnd++
		case StatusStarved:
			s.Starved++
		case StatusUnwired:
			s.Unwired++
		}
	}
	s.Declared = s.Active
	return s
}
