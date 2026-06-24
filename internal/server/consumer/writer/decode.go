package writer

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
)

// ParseRecordFields 从 MQMessage.Body 解析 bridge.Record，返回 Fields map
// MQMessage.Body = AC 的 EncodedRecord.Data = protobuf 编码的 bridge.Record
// 同时供 Router 层 CEL 引擎评估使用
func ParseRecordFields(body []byte) (map[string]string, error) {
	record := &bridge.Record{}
	if err := proto.Unmarshal(body, record); err != nil {
		return nil, fmt.Errorf("proto.Unmarshal bridge.Record 失败: %w", err)
	}
	if record.Data == nil {
		return nil, fmt.Errorf("Record.Data 为空")
	}
	if record.Data.Fields == nil {
		return make(map[string]string), nil
	}
	return record.Data.Fields, nil
}
