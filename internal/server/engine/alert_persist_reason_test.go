package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// 告警描述取检测阶段给的一句话说明；内容里有主机上报的字段，过长要截断，取不到就为空。
func TestPayloadReason(t *testing.T) {
	p, _ := json.Marshal(map[string]any{"would_action": map[string]any{"reason": "  来源 203.0.113.9 登录失败 5 次  "}})
	if got := payloadReason(p); got != "来源 203.0.113.9 登录失败 5 次" {
		t.Errorf("正常取值：%q", got)
	}
	long, _ := json.Marshal(map[string]any{"would_action": map[string]any{"reason": strings.Repeat("长", 1000)}})
	if got := []rune(payloadReason(long)); len(got) != 300 {
		t.Errorf("应截到 300 个字，得 %d", len(got))
	}
	for _, bad := range []string{"", "not json", `{"would_action":"x"}`, `{"other":1}`} {
		if got := payloadReason(json.RawMessage(bad)); got != "" {
			t.Errorf("%q 应取不到说明，得 %q", bad, got)
		}
	}
}
