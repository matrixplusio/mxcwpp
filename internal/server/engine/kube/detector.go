package kube

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// DetectionRule 检测规则定义
type DetectionRule struct {
	ID          string
	Name        string
	Severity    string
	AlarmType   model.KubeAlarmType
	Description string
	Remediation string // 处置建议
	Match       func(event *model.AuditEvent) bool
}

// KubeDetector Audit Event 规则检测引擎
type KubeDetector struct {
	db           *gorm.DB
	logger       *zap.Logger
	alarmService *KubeAlarmService
	rules        []DetectionRule
}

// NewKubeDetector 创建检测引擎
func NewKubeDetector(db *gorm.DB, logger *zap.Logger, alarmService *KubeAlarmService) *KubeDetector {
	d := &KubeDetector{
		db:           db,
		logger:       logger,
		alarmService: alarmService,
	}
	d.registerRules()
	return d
}

// ---- 全局上下文排除配置 ----
//
// 以下命名空间、用户、UserAgent 对应的事件全部跳过规则检测。
// 这些是 K8s 内核组件的正常行为，监控它们会产生大量误报。
// 用户自定义排除通过白名单机制实现（matchWhitelist）。

var excludedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

var excludedUserPrefixes = []string{
	"system:node:",                       // kubelet
	"system:kube-controller-manager",     // controller-manager
	"system:kube-scheduler",              // scheduler
	"system:apiserver",                   // apiserver 内部
	"system:serviceaccount:kube-system:", // kube-system 内的 SA
}

var excludedAgentPrefixes = []string{
	"kubelet/",
	"kube-apiserver/",
	"kube-controller-manager/",
	"kube-scheduler/",
}

// shouldExcludeEvent 判断 audit 事件是否需要跳过检测。
// 命中命名空间 / 用户 / UserAgent 任一排除条件则返回 true。
func shouldExcludeEvent(e *model.AuditEvent) bool {
	if e == nil {
		return false
	}
	if e.ObjectRef != nil && excludedNamespaces[e.ObjectRef.Namespace] {
		return true
	}
	for _, p := range excludedUserPrefixes {
		if strings.HasPrefix(e.User.Username, p) {
			return true
		}
	}
	for _, p := range excludedAgentPrefixes {
		if strings.HasPrefix(e.UserAgent, p) {
			return true
		}
	}
	return false
}

// isSystemUser 判断用户名是否属于 K8s 内核 / 系统组件。
// 全局排除已覆盖大部分情况，此函数作为规则级别的二次兜底。
func isSystemUser(username string) bool {
	return strings.HasPrefix(username, "system:")
}

// containsHighPrivilegeRole 检查 ClusterRoleBinding 的 requestObj 是否绑定高权限角色。
// 仅在绑定 cluster-admin、admin 或 system:*-admin 时返回 true。
func containsHighPrivilegeRole(requestObj json.RawMessage) bool {
	var crb struct {
		RoleRef struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"roleRef"`
	}
	if err := json.Unmarshal(requestObj, &crb); err != nil {
		return false
	}
	name := crb.RoleRef.Name
	if name == "" {
		return false
	}
	// 显式高权限角色
	highPriv := map[string]bool{
		"cluster-admin": true,
		"admin":         true,
		"edit":          true,
	}
	if highPriv[name] {
		return true
	}
	// 形如 system:*-admin 的系统高权限角色
	if strings.HasPrefix(name, "system:") && strings.HasSuffix(name, "-admin") {
		return true
	}
	return false
}

func (d *KubeDetector) registerRules() {
	d.rules = []DetectionRule{
		{
			ID: "K8S-001", Name: "kubectl exec 进入容器",
			Severity: "high", AlarmType: model.KubeAlarmTypeAbnormalProcess,
			Description: "检测到通过 kubectl exec 进入运行中的容器。攻击者可能通过 exec 在容器内执行恶意命令、窃取数据或进行横向移动。",
			Remediation: "1. 确认执行者身份和操作目的是否合法\n2. 检查容器内是否有异常进程或文件变更\n3. 对非运维人员限制 pods/exec 权限（RBAC）\n4. 启用 PodSecurity 策略限制交互式 Shell",
			Match: func(e *model.AuditEvent) bool {
				return e.ObjectRef != nil && e.Verb == "create" && e.ObjectRef.Subresource == "exec"
			},
		},
		{
			ID: "K8S-002", Name: "创建 hostNetwork/hostPID Pod",
			Severity: "critical", AlarmType: model.KubeAlarmTypeContainerEscape,
			Description: "检测到创建使用 hostNetwork 或 hostPID 的 Pod。这类 Pod 可以直接访问宿主机网络栈或进程空间，是容器逃逸的常见手段。",
			Remediation: "1. 确认是否为合法的系统组件（如 CNI、监控 DaemonSet）\n2. 非系统组件应禁止使用 hostNetwork/hostPID\n3. 通过 PodSecurity Admission 或 OPA/Kyverno 策略限制\n4. 审查创建者的 RBAC 权限范围",
			Match: func(e *model.AuditEvent) bool {
				if e.ObjectRef == nil || e.Verb != "create" || e.ObjectRef.Resource != "pods" {
					return false
				}
				return containsHostAccess(e.RequestObj)
			},
		},
		{
			ID: "K8S-003", Name: "ClusterRole 绑定高权限",
			Severity: "critical", AlarmType: model.KubeAlarmTypePrivilegeEscalation,
			Description: "检测到创建 ClusterRoleBinding 绑定高权限角色。攻击者可能通过绑定 cluster-admin 等角色实现权限提升，获取集群完全控制权。",
			Remediation: "1. 检查绑定的 ClusterRole 是否为 cluster-admin 或等效高权限角色\n2. 确认操作者是否有合法的提权需求\n3. 遵循最小权限原则，使用 Role 而非 ClusterRole\n4. 定期审计 ClusterRoleBinding 列表",
			Match: func(e *model.AuditEvent) bool {
				if e.ObjectRef == nil || e.Verb != "create" || e.ObjectRef.Resource != "clusterrolebindings" {
					return false
				}
				// 只告警绑定高权限角色的 CRB，避免业务组件的普通 binding 触发误报
				return containsHighPrivilegeRole(e.RequestObj)
			},
		},
		{
			ID: "K8S-004", Name: "访问 Secret 资源",
			Severity: "medium", AlarmType: model.KubeAlarmTypeAbnormalProcess,
			Description: "检测到读取 Secret 资源。Secret 中可能包含数据库密码、API Key、TLS 证书等敏感凭据，未授权访问可导致凭据泄露。",
			Remediation: "1. 确认访问者是否有合法的业务需求\n2. 检查 Secret 内容是否包含高敏感凭据\n3. 通过 RBAC 限制 Secret 的 get/list 权限\n4. 考虑使用外部密钥管理（Vault、KMS）替代 K8s Secret",
			Match: func(e *model.AuditEvent) bool {
				if e.ObjectRef == nil || e.ObjectRef.Resource != "secrets" ||
					(e.Verb != "get" && e.Verb != "list") {
					return false
				}
				// 排除系统组件访问（全局排除已过滤大部分，此处兜底非 kube-system 的系统身份）
				if isSystemUser(e.User.Username) {
					return false
				}
				return true
			},
		},
		{
			ID: "K8S-005", Name: "创建特权容器",
			Severity: "critical", AlarmType: model.KubeAlarmTypeContainerEscape,
			Description: "检测到创建特权容器（privileged: true）。特权容器拥有宿主机全部 Linux Capabilities，可直接访问宿主机设备和文件系统，是最高风险的容器逃逸路径。",
			Remediation: "1. 确认是否为必须特权运行的系统组件\n2. 非必要场景应使用最小 Capabilities 替代特权模式\n3. 通过 PodSecurity Admission 在 namespace 级别禁止特权容器\n4. 审查 Pod 的 SecurityContext 配置",
			Match: func(e *model.AuditEvent) bool {
				if e.ObjectRef == nil || e.Verb != "create" || e.ObjectRef.Resource != "pods" {
					return false
				}
				return containsPrivileged(e.RequestObj)
			},
		},
		{
			ID: "K8S-006", Name: "ServiceAccount Token 异常使用",
			Severity: "high", AlarmType: model.KubeAlarmTypeAbnormalProcess,
			Description: "检测到非标准工具使用 ServiceAccount Token 调用 K8s API。可能是攻击者窃取了 Pod 内的 SA Token 后从外部发起 API 请求，也可能是恶意程序在容器内横向探测。",
			Remediation: "1. 检查 UserAgent 是否为已知的合法组件\n2. 确认对应的 ServiceAccount 是否需要 API 访问权限\n3. 对无需访问 API 的 Pod 设置 automountServiceAccountToken: false\n4. 限制 ServiceAccount 的 RBAC 权限范围",
			Match: func(e *model.AuditEvent) bool {
				if e.UserAgent == "" {
					return false
				}
				knownAgents := []string{
					"kubectl/", "kube-", "kubelet/",
					"Go-http-client/",
					"argo", "helm", "flux", // GitOps 工具
					"prometheus/", "grafana/", // 监控组件
					"cert-manager/", "coredns", // 集群组件
					"rancher/", "velero/", // 集群管理
					"calico/", "cilium", // CNI
					"operator/", // 通用 Operator 前缀
				}
				for _, agent := range knownAgents {
					if strings.HasPrefix(e.UserAgent, agent) {
						return false
					}
				}
				// 非标准 UserAgent + ServiceAccount 用户
				return strings.HasPrefix(e.User.Username, "system:serviceaccount:")
			},
		},
		{
			ID: "K8S-007", Name: "容器内反弹 Shell 迹象",
			Severity: "critical", AlarmType: model.KubeAlarmTypeReverseShell,
			Description: "检测到通过 kubectl exec 在容器内执行 Shell 命令（bash/sh/nc/ncat）。这是反弹 Shell 或交互式入侵的典型行为模式。",
			Remediation: "1. 立即检查容器内是否存在异常进程或网络连接\n2. 确认是否为合法的运维调试操作\n3. 检查容器是否已被植入后门或 WebShell\n4. 对生产环境禁止 exec 权限，使用 ephemeral containers 调试",
			Match: func(e *model.AuditEvent) bool {
				if e.ObjectRef == nil || e.Verb != "create" || e.ObjectRef.Subresource != "exec" {
					return false
				}
				reqStr := string(e.RequestObj)
				return strings.Contains(reqStr, "/bin/bash") || strings.Contains(reqStr, "/bin/sh") ||
					strings.Contains(reqStr, "nc ") || strings.Contains(reqStr, "ncat")
			},
		},
		{
			ID: "K8S-008", Name: "挂载宿主机路径（容器逃逸迹象）",
			Severity: "critical", AlarmType: model.KubeAlarmTypeContainerEscape,
			Description: "检测到 Pod 挂载宿主机敏感路径（/、/etc、/proc、/var/run/docker.sock 等）。攻击者可通过 hostPath 挂载读写宿主机文件系统，实现容器逃逸。",
			Remediation: "1. 确认挂载路径是否为业务必需\n2. 尽量使用 PV/PVC 替代 hostPath\n3. 如必须挂载，设置 readOnly: true 限制为只读\n4. 通过 PodSecurity Admission 或 OPA 策略限制 hostPath 使用",
			Match: func(e *model.AuditEvent) bool {
				if e.ObjectRef == nil || e.Verb != "create" || e.ObjectRef.Resource != "pods" {
					return false
				}
				return containsHostPathMount(e.RequestObj)
			},
		},
	}
}

// DetectAuditEvent 对单个 audit event 执行所有规则检测
func (d *KubeDetector) DetectAuditEvent(clusterID uint, clusterName string, event *model.AuditEvent) {
	// 全局上下文排除：kube-system 命名空间、kubelet 等系统身份不检测
	if shouldExcludeEvent(event) {
		return
	}

	for _, rule := range d.rules {
		if !rule.Match(event) {
			continue
		}

		rawData, _ := json.Marshal(event)
		alarm := model.KubeAlarm{
			ClusterID:   clusterID,
			ClusterName: clusterName,
			Severity:    rule.Severity,
			AlarmType:   rule.AlarmType,
			RuleID:      rule.ID,
			Title:       "[" + rule.ID + "] " + rule.Name,
			Description: rule.Description,
			Remediation: rule.Remediation,
			Message:     buildAlarmMessage(rule.ID, event),
			RawData:     model.RawJSON(rawData),
			Status:      model.KubeAlarmStatusPending,
		}

		if event.ObjectRef != nil {
			alarm.Namespace = event.ObjectRef.Namespace
			alarm.PodName = event.ObjectRef.Name
			// 构建 Target: resource/name
			if event.ObjectRef.Name != "" {
				alarm.Target = event.ObjectRef.Resource + "/" + event.ObjectRef.Name
			} else {
				alarm.Target = event.ObjectRef.Resource
			}
		}

		created, err := d.alarmService.CreateAlarmWithFilter(&alarm)
		if err != nil {
			d.logger.Error("规则引擎创建告警失败",
				zap.String("rule", rule.ID), zap.Error(err))
		}
		if created {
			d.logger.Info("规则引擎触发告警",
				zap.String("rule", rule.ID),
				zap.String("cluster", clusterName),
			)
		}
	}
}

// buildAlarmMessage 根据规则和事件构建可读的告警消息
func buildAlarmMessage(ruleID string, e *model.AuditEvent) string {
	user := e.User.Username
	ns := ""
	resource := ""
	name := ""
	if e.ObjectRef != nil {
		ns = e.ObjectRef.Namespace
		resource = e.ObjectRef.Resource
		name = e.ObjectRef.Name
	}

	// 构建命名空间前缀
	nsPart := ""
	if ns != "" {
		nsPart = "命名空间 " + ns + " 中"
	}

	switch ruleID {
	case "K8S-001":
		return fmt.Sprintf("用户 %s 通过 kubectl exec 进入了%s容器 %s", user, nsPart, name)
	case "K8S-002":
		return fmt.Sprintf("用户 %s 在%s创建了使用 hostNetwork/hostPID 的 Pod %s，该 Pod 可直接访问宿主机网络或进程空间", user, nsPart, name)
	case "K8S-003":
		return fmt.Sprintf("用户 %s 创建了 ClusterRoleBinding %s，可能绑定了 cluster-admin 等高权限角色", user, name)
	case "K8S-004":
		verb := e.Verb
		return fmt.Sprintf("用户 %s 在%s %s 了 Secret 资源 %s", user, nsPart, verb, name)
	case "K8S-005":
		return fmt.Sprintf("用户 %s 在%s创建了特权容器 Pod %s（privileged: true），拥有宿主机全部权限", user, nsPart, name)
	case "K8S-006":
		return fmt.Sprintf("ServiceAccount %s 通过非标准客户端（%s）访问了 %s/%s，可能存在 Token 被盗用", user, e.UserAgent, resource, name)
	case "K8S-007":
		return fmt.Sprintf("用户 %s 在%s容器 %s 内执行了 Shell 命令，疑似反弹 Shell 或交互式入侵", user, nsPart, name)
	case "K8S-008":
		return fmt.Sprintf("用户 %s 在%s创建了挂载宿主机敏感路径的 Pod %s，存在容器逃逸风险", user, nsPart, name)
	default:
		return fmt.Sprintf("用户 %s 触发规则 %s，资源: %s/%s", user, ruleID, resource, name)
	}
}

// 辅助函数：检查 Pod spec 中是否包含 hostNetwork/hostPID
func containsHostAccess(requestObj json.RawMessage) bool {
	var pod struct {
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
			HostPID     bool `json:"hostPID"`
			HostIPC     bool `json:"hostIPC"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(requestObj, &pod); err != nil {
		return false
	}
	return pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC
}

// 辅助函数：检查 Pod spec 中是否包含特权容器
func containsPrivileged(requestObj json.RawMessage) bool {
	var pod struct {
		Spec struct {
			Containers []struct {
				SecurityContext *struct {
					Privileged *bool `json:"privileged"`
				} `json:"securityContext"`
			} `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(requestObj, &pod); err != nil {
		return false
	}
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

// 辅助函数：检查 Pod spec 中是否挂载宿主机敏感路径
func containsHostPathMount(requestObj json.RawMessage) bool {
	var pod struct {
		Spec struct {
			Volumes []struct {
				HostPath *struct {
					Path string `json:"path"`
				} `json:"hostPath"`
			} `json:"volumes"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(requestObj, &pod); err != nil {
		return false
	}
	sensitivePaths := []string{"/", "/etc", "/proc", "/sys", "/var/run/docker.sock", "/run/containerd"}
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath == nil {
			continue
		}
		for _, sp := range sensitivePaths {
			if vol.HostPath.Path == sp || strings.HasPrefix(vol.HostPath.Path, sp+"/") {
				return true
			}
		}
	}
	return false
}
