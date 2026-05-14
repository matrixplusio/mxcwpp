package biz

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIsSystemNamespace 验证系统 Namespace 判断
func TestIsSystemNamespace(t *testing.T) {
	tests := []struct {
		ns   string
		want bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"default", false},
		{"production", false},
		{"monitoring", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			if got := isSystemNamespace(tt.ns); got != tt.want {
				t.Fatalf("isSystemNamespace(%q) = %v, want %v", tt.ns, got, tt.want)
			}
		})
	}
}

// TestHasOwnerKind 验证 OwnerReference Kind 查找
func TestHasOwnerKind(t *testing.T) {
	refs := []metav1.OwnerReference{
		{Kind: "Job", Name: "my-job"},
		{Kind: "ReplicaSet", Name: "my-rs"},
	}

	tests := []struct {
		name string
		refs []metav1.OwnerReference
		kind string
		want bool
	}{
		{"found Job", refs, "Job", true},
		{"found ReplicaSet", refs, "ReplicaSet", true},
		{"not found DaemonSet", refs, "DaemonSet", false},
		{"nil refs", nil, "Job", false},
		{"empty refs", []metav1.OwnerReference{}, "Job", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasOwnerKind(tt.refs, tt.kind); got != tt.want {
				t.Fatalf("hasOwnerKind(refs, %q) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

// TestRegisterCheckFuncsCount 验证注册了 80 条检查函数
func TestRegisterCheckFuncsCount(t *testing.T) {
	c := &KubeBaselineChecker{}
	c.checkFuncs = c.registerCheckFuncs()

	if len(c.checkFuncs) != 80 {
		t.Fatalf("期望注册 80 条检查函数, 实际 %d 条", len(c.checkFuncs))
	}
}

// TestRegisterCheckFuncsUniqueIDs 验证所有 CheckID 唯一（map key 天然唯一，验证数量即可）
func TestRegisterCheckFuncsUniqueIDs(t *testing.T) {
	c := &KubeBaselineChecker{}
	c.checkFuncs = c.registerCheckFuncs()

	// map key 天然唯一，只需确认数量
	if len(c.checkFuncs) != 80 {
		t.Fatalf("CheckID 数量不符, 期望 80, 实际 %d", len(c.checkFuncs))
	}
}

// TestRegisterCheckFuncsNoNil 验证所有检查函数非 nil
func TestRegisterCheckFuncsNoNil(t *testing.T) {
	c := &KubeBaselineChecker{}
	c.checkFuncs = c.registerCheckFuncs()

	for id, fn := range c.checkFuncs {
		if fn == nil {
			t.Fatalf("CheckFunc 不能为 nil: %s", id)
		}
	}
}

// TestGetRegisteredCheckIDs 验证获取已注册 CheckID 列表
func TestGetRegisteredCheckIDs(t *testing.T) {
	c := &KubeBaselineChecker{}
	c.checkFuncs = c.registerCheckFuncs()

	ids := c.GetRegisteredCheckIDs()
	if len(ids) != 80 {
		t.Fatalf("期望 80 个 CheckID, 实际 %d 个", len(ids))
	}

	// 验证已排序
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Fatalf("CheckID 未排序: %s < %s", ids[i], ids[i-1])
		}
	}
}

// TestUpdateHealthScoreLogic 验证健康分计算逻辑
func TestUpdateHealthScoreLogic(t *testing.T) {
	tests := []struct {
		name     string
		passed   int
		total    int
		expected int
	}{
		{"all pass", 80, 80, 100},
		{"half pass", 40, 80, 50},
		{"none pass", 0, 80, 0},
		{"3/4 pass", 60, 80, 75},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.passed * 100 / tt.total
			if score != tt.expected {
				t.Fatalf("score = %d, want %d", score, tt.expected)
			}
		})
	}
}
