package gcppubsub

import (
	"encoding/json"
	"testing"
)

// GKE 审计日志的成败只在 protoPayload.status 里，转换时要换算成 HTTP 状态码，
// 规则才分得清「匿名访问成功」和「被拒的探测」。
func TestTransformCarriesResponseStatus(t *testing.T) {
	mk := func(status string) *LogEntry {
		p := `{"methodName":"io.k8s.core.v1.pods.list","resourceName":"core/v1/namespaces/default/pods",` +
			`"authenticationInfo":{"principalEmail":"system:anonymous"},"requestMetadata":{"callerIp":"203.0.113.9"}` + status + `}`
		return &LogEntry{Resource: LogResource{Type: "k8s_cluster"}, ProtoPayload: json.RawMessage(p)}
	}
	cases := map[string]int{
		``:             200, // 没有 status 表示成功
		`,"status":{}`: 200,
		`,"status":{"code":7,"message":"forbidden"}`: 403,
		`,"status":{"code":16}`:                      401,
		`,"status":{"code":13}`:                      500,
	}
	for status, want := range cases {
		evs := TransformLogEntry(mk(status))
		if len(evs) != 1 || evs[0].ResponseStatus == nil || evs[0].ResponseStatus.Code != want {
			t.Errorf("status %q：期望 %d，得 %+v", status, want, evs)
		}
	}
	// 授权没通过：authorizationInfo 里那一项不带 granted。按 GKE 审计日志格式构造。
	denied := `,"status":{"code":7},"authorizationInfo":[{"permission":"io.k8s.post","resource":"/"}]`
	if evs := TransformLogEntry(mk(denied)); len(evs) != 1 || !evs[0].Denied() {
		t.Error("授权没通过的 403 应判为被拒")
	}
	// 授权通过、被准入控制器挡下：同样是 code 7，但 granted 为 true。
	admission := `,"status":{"code":7},"authorizationInfo":[{"permission":"io.k8s.core.v1.pods.create","granted":true}]`
	if evs := TransformLogEntry(mk(admission)); len(evs) != 1 || evs[0].Denied() {
		t.Error("授权已通过、被准入挡下的不该判为被拒")
	}
	// 没有 authorizationInfo：拿不准，不判为被拒。
	if evs := TransformLogEntry(mk(`,"status":{"code":7}`)); len(evs) != 1 || evs[0].Denied() {
		t.Error("没有授权结论时不该判为被拒")
	}
}
