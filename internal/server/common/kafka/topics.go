package kafka

// Topic 常量（对应设计文档 § 3.2.1）
const (
	TopicHeartbeat   = "mxsec.agent.heartbeat"   // DataType 1000/1001, Retention 24h
	TopicEvents      = "mxsec.agent.events"      // DataType 6001 (FIM), Retention 72h
	TopicBaseline    = "mxsec.agent.baseline"    // DataType 8000~8004, Retention 7d
	TopicAsset       = "mxsec.agent.asset"       // DataType 5050~5060, Retention 7d
	TopicCommandAck  = "mxsec.agent.command-ack" // 命令执行回包, Retention 7d
	TopicScanner     = "mxsec.agent.scanner"     // DataType 7000~7004, Retention 7d
	TopicEBPF        = "mxsec.agent.ebpf"        // DataType 3000~3002, Retention 3d
	TopicRemediation = "mxsec.agent.remediation" // DataType 9100~9299, Retention 7d

	// DLQ 后缀约定：{topic}.dlq
	DLQSuffix = ".dlq"
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
	default:
		topic = TopicHeartbeat // 兜底：未知类型归入心跳 Topic
	}
	if topicPrefix != "" {
		return topicPrefix + topic
	}
	return topic
}
