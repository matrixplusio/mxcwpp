package service

import (
	"reflect"
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Oracle Linux 上报 "ol"，内置策略写 "oracle"：逐字比较时这类主机被静默跳过。
func TestMatchPolicyOSAlias(t *testing.T) {
	s := &TaskService{logger: zap.NewNop()}
	p := &model.Policy{OSFamily: model.StringArray{"rocky", "centos", "oracle"}, OSVersion: ">=7"}
	if !s.matchPolicyOS(p, &model.Host{OSFamily: "ol", OSVersion: "8.10"}) {
		t.Fatal("ol 主机应匹配写 oracle 的策略")
	}
	if s.matchPolicyOS(p, &model.Host{OSFamily: "ubuntu", OSVersion: "22.04"}) {
		t.Fatal("ubuntu 不应匹配")
	}
}

func TestFamiliesForHost(t *testing.T) {
	policy := []string{"rocky", "oracle"}
	// 靠别名匹配上：补上主机原名，老插件逐字比较才认
	if got := familiesForHost(policy, "ol"); !reflect.DeepEqual(got, []string{"rocky", "oracle", "ol"}) {
		t.Errorf("ol: got %v", got)
	}
	// 本来就逐字匹配、或根本不匹配：原样返回
	if got := familiesForHost(policy, "Rocky"); !reflect.DeepEqual(got, policy) {
		t.Errorf("rocky: got %v", got)
	}
	if got := familiesForHost(policy, "ubuntu"); !reflect.DeepEqual(got, policy) {
		t.Errorf("ubuntu: got %v", got)
	}
	if len(policy) != 2 {
		t.Error("不能改动原切片")
	}
}
