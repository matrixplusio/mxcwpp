package advisory

import (
	"encoding/json"
	"fmt"
)

// AdvisoryMessage 是 Kafka topic mxcwpp.vuln.advisory 的 wire 契约。
//
// VulnSync 服务拉源后生产该消息，Manager consumer 消费后用 Matcher 比对主机软件
// 清单写 host_vulnerabilities。承载完整的 Advisory（含 AffectedPkgs NEVRA/fixed_version
// + OS gate），保证匹配保真——任何匹配字段丢失都会导致主机漏洞漏报。
//
// 生产者与消费者共享本 struct（均 import advisory 包），故 JSON 默认字段名即契约，
// 无需显式 tag；如需跨语言/版本演进再补 tag。
type AdvisoryMessage struct {
	Source     string     `json:"source"`     // source.Name(): rhsa / rocky-apollo / usn / debian-tracker / alpine
	Confidence Confidence `json:"confidence"` // source.Confidence()，consumer 端 mergeByConfidence 排序用
	Advisory   *Advisory  `json:"advisory"`   // 富 payload，含 AffectedPkgs + OS/ecosystem gate
}

// PartitionKey 返回 Kafka 分区键 source:advisory_id，
// 保证同源同 advisory 的更新落同一分区、消费顺序一致。
func (m AdvisoryMessage) PartitionKey() string {
	id := ""
	if m.Advisory != nil {
		id = m.Advisory.AdvisoryID
	}
	return m.Source + ":" + id
}

// Marshal 序列化为 Kafka 消息体。
func (m AdvisoryMessage) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// UnmarshalAdvisoryMessage 从 Kafka 消息体反序列化。
func UnmarshalAdvisoryMessage(b []byte) (*AdvisoryMessage, error) {
	var m AdvisoryMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshal advisory message: %w", err)
	}
	if m.Advisory == nil {
		return nil, fmt.Errorf("advisory message: nil advisory payload")
	}
	return &m, nil
}
