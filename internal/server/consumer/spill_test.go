package consumer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/consumer/writer"
)

// 写入方按字节装好的记录，经真实的编码路径后仍远小于 Kafka 的 4MB 上限：
// 不能在最后一步把 < > & 重新转义放大 6 倍。
func TestEncodeSpillRecordDoesNotEscapeHTML(t *testing.T) {
	row := `{"HostID":"h","Detail":"` + strings.Repeat("<", 900<<10) + `"}`
	rec := writer.SpillRecord{Table: "fim_events", Reason: writer.SpillReasonRejected, FailedAt: time.Now(),
		Rows: json.RawMessage("[" + row + "]")}
	b, err := encodeSpillRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 1<<20 {
		t.Fatalf("编码后 %d 字节，被转义放大了", len(b))
	}
	var back writer.SpillRecord
	if err := json.Unmarshal(b, &back); err != nil || back.Table != "fim_events" {
		t.Fatalf("编码结果应能原样解析: %v", err)
	}
}
