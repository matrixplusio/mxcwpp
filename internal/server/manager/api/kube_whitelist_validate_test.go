package api

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestValidateWhitelistRule(t *testing.T) {
	cluster := uint(1)
	cases := []struct {
		name string
		rule model.KubeWhitelist
		ok   bool
	}{
		{"什么都不限定", model.KubeWhitelist{Name: "x"}, false},
		{"只限定操作者", model.KubeWhitelist{Users: model.StringArray{"system:serviceaccount:a:b"}}, false},
		{"操作者加规则", model.KubeWhitelist{Users: model.StringArray{"system:serviceaccount:a:b"}, RuleIDs: model.StringArray{"K8S-014"}}, true},
		{"只限定命名空间", model.KubeWhitelist{Namespace: "istio-system"}, true},
		{"只限定集群", model.KubeWhitelist{ClusterID: &cluster}, true},
	}
	for _, c := range cases {
		if got := validateWhitelistRule(&c.rule) == ""; got != c.ok {
			t.Errorf("%s：期望通过=%v，实际=%v", c.name, c.ok, got)
		}
	}
}
