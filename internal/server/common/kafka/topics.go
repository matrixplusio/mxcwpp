package kafka

// Topic 常量（对应设计文档 docs/architecture.md §4.1 + docs/datatype-allocation.md）
const (
	// v1.x Agent → Server 数据 Topic
	TopicHeartbeat   = "mxsec.agent.heartbeat"   // DataType 1000/1001, Retention 24h
	TopicEvents      = "mxsec.agent.events"      // DataType 6001 (FIM), Retention 72h
	TopicRASP        = "mxsec.agent.rasp"        // DataType 4000~4099 (RASP), Retention 7d (P5-2)
	TopicBaseline    = "mxsec.agent.baseline"    // DataType 8000~8004, Retention 7d
	TopicAsset       = "mxsec.agent.asset"       // DataType 5050~5060, Retention 7d
	TopicCommandAck  = "mxsec.agent.command-ack" // 命令执行回包, Retention 7d
	TopicScanner     = "mxsec.agent.scanner"     // DataType 7000~7004, Retention 7d
	TopicEBPF        = "mxsec.agent.ebpf"        // DataType 3000~3002, Retention 3d
	TopicRemediation = "mxsec.agent.remediation" // DataType 9100~9299, Retention 7d

	// v2.0 Engine 产出 Topic
	TopicEngineAlert     = "mxsec.engine.alert"     // DataType 11001-11099, Retention 7d
	TopicEngineStoryline = "mxsec.engine.storyline" // DataType 11100-11199, Retention 14d
	TopicEngineFeedback  = "mxsec.engine.feedback"  // DataType 11900-11999, Retention 30d

	// v2.0 Engine → AC 命令 Topic (Sprint 2 PR14 新增)
	// 解耦 Engine 决策与 AC 接入: Engine 产命令 → Kafka → AC 消费 → Agent 下发
	// 详见 docs/architecture.md §3.1 + internal/server/engine/scheduler/README.md
	TopicEngineCommand = "mxsec.engine.command" // DataType 11800-11899, Retention 24h

	// v2.0 VulnSync 产出 Topic
	TopicVulnAdvisory = "mxsec.vuln.advisory" // DataType 12001-12099, Retention 30d

	// v2.0 LLMProxy 审计 Topic
	TopicLLMAudit = "mxsec.llm.audit" // DataType 13001-13099, Retention 90d

	// v2.0 多租户计量 Topic
	TopicMeteringUsage = "mxsec.metering.usage" // DataType 14001-14099, Retention 365d

	// DLQ 后缀约定：{topic}.dlq
	DLQSuffix = ".dlq"
)

// DataType 范围常量 (v2.0 新增,便于 Engine/AC 路由)
const (
	DataTypeEngineCommandMin int32 = 11800
	DataTypeEngineCommandMax int32 = 11899

	DataTypeEngineAlertMin int32 = 11001
	DataTypeEngineAlertMax int32 = 11099

	DataTypeEngineStorylineMin int32 = 11100
	DataTypeEngineStorylineMax int32 = 11199

	DataTypeEngineFeedbackMin int32 = 11900
	DataTypeEngineFeedbackMax int32 = 11999

	DataTypeVulnAdvisoryMin int32 = 12001
	DataTypeVulnAdvisoryMax int32 = 12099

	DataTypeLLMAuditMin int32 = 13001
	DataTypeLLMAuditMax int32 = 13099

	DataTypeMeteringUsageMin int32 = 14001
	DataTypeMeteringUsageMax int32 = 14099
)

// DLQTopic 返回对应 Topic 的 Dead Letter Queue Topic 名称
func DLQTopic(topic string) string {
	return topic + DLQSuffix
}

// RouteDataType 根据 DataType 返回对应的 Kafka Topic
func RouteDataType(dataType int32, topicPrefix string) string {
	var topic string
	switch {
	case dataType == 1000 || dataType == 1001:
		topic = TopicHeartbeat
	case dataType == 6001 || dataType == 6002:
		topic = TopicEvents
	case dataType >= 8000 && dataType <= 8004:
		topic = TopicBaseline
	case dataType >= 5050 && dataType <= 5060:
		topic = TopicAsset
	case dataType >= 7000 && dataType <= 7099:
		topic = TopicScanner
	case dataType >= 3000 && dataType <= 3099:
		topic = TopicEBPF
	case dataType >= 9100 && dataType <= 9299:
		topic = TopicRemediation
	case dataType == 9999:
		topic = TopicCommandAck
	case dataType >= DataTypeEngineAlertMin && dataType <= DataTypeEngineAlertMax:
		topic = TopicEngineAlert
	case dataType >= DataTypeEngineStorylineMin && dataType <= DataTypeEngineStorylineMax:
		topic = TopicEngineStoryline
	case dataType >= DataTypeEngineCommandMin && dataType <= DataTypeEngineCommandMax:
		topic = TopicEngineCommand
	case dataType >= DataTypeEngineFeedbackMin && dataType <= DataTypeEngineFeedbackMax:
		topic = TopicEngineFeedback
	case dataType >= DataTypeVulnAdvisoryMin && dataType <= DataTypeVulnAdvisoryMax:
		topic = TopicVulnAdvisory
	case dataType >= DataTypeLLMAuditMin && dataType <= DataTypeLLMAuditMax:
		topic = TopicLLMAudit
	case dataType >= DataTypeMeteringUsageMin && dataType <= DataTypeMeteringUsageMax:
		topic = TopicMeteringUsage
	default:
		topic = TopicHeartbeat // 兜底：未知类型归入心跳 Topic
	}
	if topicPrefix != "" {
		return topicPrefix + topic
	}
	return topic
}

// IsEngineCommand 判断 DataType 是否落在 Engine→AC 命令段。
func IsEngineCommand(dataType int32) bool {
	return dataType >= DataTypeEngineCommandMin && dataType <= DataTypeEngineCommandMax
}

// IsEngineAlert 判断 DataType 是否落在 Engine 告警段。
func IsEngineAlert(dataType int32) bool {
	return dataType >= DataTypeEngineAlertMin && dataType <= DataTypeEngineAlertMax
}
