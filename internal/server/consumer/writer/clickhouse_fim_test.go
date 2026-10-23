package writer

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
)

// fimPluginMsg 按 fim 插件真实的上报格式构造消息（字段名照抄 plugins/fim/main.go）。
func fimPluginMsg(t *testing.T, fields map[string]string) *kafka.MQMessage {
	t.Helper()
	body, err := proto.Marshal(&bridge.Record{
		DataType: 6001,
		Data:     &bridge.Payload{Fields: fields},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &kafka.MQMessage{AgentID: "host-1", Body: body}
}

// 插件上报的明细必须进 ClickHouse。字段名曾在两端不一致，明细恒为空，
// 而编译、运行、日志全都正常——只有按真实上报格式断言才拦得住。
func TestParseFIMEventKeepsPluginChangeDetail(t *testing.T) {
	detail := `{"hash_before":"aa","hash_after":"bb","hash_changed":true}`
	row := (&ClickHouseWriter{}).parseFIMEvent(fimPluginMsg(t, map[string]string{
		"file_path":     "/usr/bin/ssh",
		"change_type":   "changed",
		"severity":      "critical",
		"category":      "binary",
		"change_detail": detail,
	}))
	if row.Detail != detail {
		t.Fatalf("ClickHouse 行的明细应为插件上报的 change_detail，实际 %q", row.Detail)
	}
	if row.FilePath != "/usr/bin/ssh" || row.ChangeType != "changed" {
		t.Fatalf("其余字段解析异常: %+v", row)
	}
}

// 旧格式只带 detail 的消息仍要能写进去。
func TestParseFIMEventFallsBackToDetail(t *testing.T) {
	row := (&ClickHouseWriter{}).parseFIMEvent(fimPluginMsg(t, map[string]string{
		"file_path": "/etc/passwd",
		"detail":    "legacy",
	}))
	if row.Detail != "legacy" {
		t.Fatalf("没有 change_detail 时应回落到 detail，实际 %q", row.Detail)
	}
}
