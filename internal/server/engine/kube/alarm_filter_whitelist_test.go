package kube

import (
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 白名单要能精确到「谁、哪条规则」。只能按命名空间与告警类型放行时，
// 为了放行一个控制器的例行操作，就得把同类的所有操作一起放掉。
func TestWhitelistMatchesUserAndRule(t *testing.T) {
	s := &KubeAlarmService{logger: zap.NewNop()}
	alarm := func(rule, user, ns, pod string) *model.KubeAlarm {
		raw := `{"user":{"username":"` + user + `"}}`
		if user == "" {
			raw = ""
		}
		return &model.KubeAlarm{ClusterID: 1, RuleID: rule, AlarmType: "privilege_escalation",
			Namespace: ns, PodName: pod, RawData: model.RawJSON(raw)}
	}
	cluster := uint(1)
	wl := &model.KubeWhitelist{ClusterID: &cluster, AlarmTypes: model.StringArray{"privilege_escalation"},
		Users:   model.StringArray{"system:serviceaccount:cert-manager:cert-manager-cainjector"},
		RuleIDs: model.StringArray{"K8S-014"}}

	if !s.ruleMatches(wl, alarm("K8S-014", "system:serviceaccount:cert-manager:cert-manager-cainjector", "", "")) {
		t.Error("指定的操作者做指定规则的事，应放行")
	}
	if s.ruleMatches(wl, alarm("K8S-014", "alice@example.com", "", "")) {
		t.Error("换一个人做同样的事，不该放行")
	}
	if s.ruleMatches(wl, alarm("K8S-010", "system:serviceaccount:cert-manager:cert-manager-cainjector", "", "")) {
		t.Error("同一个操作者触发别的规则，不该放行")
	}
	if s.ruleMatches(wl, alarm("K8S-014", "", "", "")) {
		t.Error("不知道操作者是谁时，限定了操作者的白名单不该放行")
	}
}

// 写了 Pod 名模式、告警却没有 Pod 名时不算匹配。原先这种情况直接跳过，白名单比写的宽。
func TestWhitelistPodPatternRequiresPod(t *testing.T) {
	s := &KubeAlarmService{logger: zap.NewNop()}
	wl := &model.KubeWhitelist{Namespace: "istio-system", PodPattern: "kiali-*"}
	if !s.ruleMatches(wl, &model.KubeAlarm{Namespace: "istio-system", PodName: "kiali-7d9f"}) {
		t.Error("Pod 名匹配时应放行")
	}
	if s.ruleMatches(wl, &model.KubeAlarm{Namespace: "istio-system", PodName: ""}) {
		t.Error("没有 Pod 名时不该放行")
	}
	if s.ruleMatches(wl, &model.KubeAlarm{Namespace: "istio-system", PodName: "istiod-1"}) {
		t.Error("Pod 名不匹配时不该放行")
	}
}
