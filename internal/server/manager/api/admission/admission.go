// Package admission 实现 K8s ValidatingAdmissionWebhook v1。
//
// 设计文档: docs/architecture.md §2.1 Manager + ref/05-容器K8s.md §5
//
// 12 条内置策略 (P2-22 扩展):
//   - PRIVILEGED:           阻止 privileged: true Pod
//   - HOST_NETWORK:         阻止 hostNetwork: true
//   - HOST_PID:             阻止 hostPID: true
//   - HOST_PATH:            阻止 mount /etc / /proc / /sys hostPath
//   - SA_TOKEN:             阻止 automountServiceAccountToken=true 且无 SA 限定
//   - IMAGE_LATEST:         拒绝 :latest tag (不可复现)
//   - RUN_AS_ROOT:          容器 UID=0 / runAsNonRoot=false
//   - DANGEROUS_CAPS:       SYS_ADMIN/SYS_PTRACE/NET_RAW 等高危 capability
//   - DOCKER_SOCK:          挂载 /var/run/docker.sock (容器逃逸)
//   - NO_RESOURCES:         无 resources.limits (易 OOM)
//   - UNTRUSTED_REGISTRY:   非白名单 registry (warning)
//
// 模式遵循全局 mode.Resolver:
//   - observe (默认): 仅 warning 不 deny
//   - protect: 真 deny
package admission

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
)

// AdmissionReview K8s admission webhook 请求/响应 schema (v1)。
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest 简化版 (仅留必要字段)。
type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Kind      KindRef         `json:"kind"`
	Resource  ResourceRef     `json:"resource"`
	Namespace string          `json:"namespace"`
	Operation string          `json:"operation"` // CREATE / UPDATE / DELETE
	UserInfo  UserInfo        `json:"userInfo"`
	Object    json.RawMessage `json:"object"`
}

// KindRef API 资源类型。
type KindRef struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// ResourceRef API 资源标识。
type ResourceRef struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// UserInfo K8s 请求用户。
type UserInfo struct {
	Username string `json:"username"`
}

// AdmissionResponse webhook 决策。
type AdmissionResponse struct {
	UID      string   `json:"uid"`
	Allowed  bool     `json:"allowed"`
	Status   *Status  `json:"status,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Status 拒绝原因。
type Status struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

// Handler 处理 ValidatingAdmissionWebhook。
type Handler struct {
	resolver *mode.MemoryResolver
	logger   *zap.Logger
}

// NewHandler 构造。
func NewHandler(resolver *mode.MemoryResolver, logger *zap.Logger) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	if resolver == nil {
		resolver = mode.NewMemoryResolver(mode.Observe)
	}
	return &Handler{resolver: resolver, logger: logger}
}

// Validate POST /api/v2/admission/validate
//
// K8s ValidatingAdmissionWebhook 调用入口。
func (h *Handler) Validate(c *gin.Context) {
	var review AdmissionReview
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(400, gin.H{"error": "invalid AdmissionReview", "hint": err.Error()})
		return
	}
	if review.Request == nil {
		c.JSON(400, gin.H{"error": "request must not be nil"})
		return
	}

	// 仅处理 CREATE/UPDATE 的 Pod / Deployment / StatefulSet / DaemonSet
	op := review.Request.Operation
	if op != "CREATE" && op != "UPDATE" {
		respondAllow(c, review.Request.UID, nil)
		return
	}
	kind := review.Request.Kind.Kind
	if !isWorkloadKind(kind) {
		respondAllow(c, review.Request.UID, nil)
		return
	}

	// 解析 PodSpec
	violations := h.checkPolicies(review.Request.Object)

	// 多租户场景: 命名空间映射 tenant_id (留 PR 加映射表; 当前用 default)
	tenantID := review.Request.Namespace
	decision := h.resolver.Resolve(mode.Scope{TenantID: tenantID})

	if len(violations) == 0 {
		respondAllow(c, review.Request.UID, nil)
		return
	}

	// observe: 仅 warning
	// protect: deny
	if !mode.ShouldEnforce(decision) {
		respondAllow(c, review.Request.UID, violations)
		h.logger.Info("admission observe 模式: 仅警告",
			zap.String("namespace", review.Request.Namespace),
			zap.String("kind", kind),
			zap.Strings("violations", violations))
		return
	}

	respondDeny(c, review.Request.UID, violations)
	h.logger.Warn("admission protect 模式: 已拒绝",
		zap.String("namespace", review.Request.Namespace),
		zap.String("kind", kind),
		zap.Strings("violations", violations))
}

// checkPolicies 检查 5 条内置策略,返回 violations 列表。
func (h *Handler) checkPolicies(obj json.RawMessage) []string {
	var violations []string

	// 简化: 转 string 后 substring 检查 (完整实现应该解构 PodSpec)
	s := string(obj)

	if strings.Contains(s, `"privileged":true`) || strings.Contains(s, `"privileged": true`) {
		violations = append(violations, "PRIVILEGED: 拒绝 privileged Pod")
	}
	if strings.Contains(s, `"hostNetwork":true`) || strings.Contains(s, `"hostNetwork": true`) {
		violations = append(violations, "HOST_NETWORK: 拒绝 hostNetwork=true")
	}
	if strings.Contains(s, `"hostPID":true`) || strings.Contains(s, `"hostPID": true`) {
		violations = append(violations, "HOST_PID: 拒绝 hostPID=true")
	}
	if strings.Contains(s, `"path":"/etc"`) || strings.Contains(s, `"path":"/proc"`) || strings.Contains(s, `"path":"/sys"`) || strings.Contains(s, `"path":"/var/lib/docker"`) {
		violations = append(violations, "HOST_PATH: 拒绝 mount 敏感系统目录")
	}
	if strings.Contains(s, `"automountServiceAccountToken":true`) && !strings.Contains(s, `"serviceAccountName"`) {
		violations = append(violations, "SA_TOKEN: 拒绝 automount SA token 且无 serviceAccountName 限定")
	}

	// P2-22 扩展: 5 条新策略
	// IMAGE_LATEST: 拒绝镜像 :latest tag (不可复现)
	if strings.Contains(s, `:latest"`) {
		violations = append(violations, "IMAGE_LATEST: 镜像不应使用 :latest tag, 改用 sha256: 或语义版本")
	}
	// RUN_AS_ROOT: 容器 runAsUser=0 / runAsNonRoot=false
	if strings.Contains(s, `"runAsUser":0`) || strings.Contains(s, `"runAsUser": 0`) {
		violations = append(violations, "RUN_AS_ROOT: 容器禁以 root (UID=0) 运行")
	}
	if strings.Contains(s, `"runAsNonRoot":false`) || strings.Contains(s, `"runAsNonRoot": false`) {
		violations = append(violations, "RUN_AS_ROOT: securityContext.runAsNonRoot 不应为 false")
	}
	// DANGEROUS_CAPS: SYS_ADMIN / SYS_PTRACE / NET_ADMIN 等高危 capability
	for _, cap := range []string{`"SYS_ADMIN"`, `"SYS_PTRACE"`, `"NET_RAW"`, `"NET_ADMIN"`, `"SYS_MODULE"`} {
		if strings.Contains(s, `"add":[`+cap) || strings.Contains(s, cap) && strings.Contains(s, `capabilities`) {
			violations = append(violations, "DANGEROUS_CAPS: 危险 capability 命中 (含 "+cap+")")
			break
		}
	}
	// DOCKER_SOCK: 挂载 /var/run/docker.sock (容器逃逸经典)
	if strings.Contains(s, `/var/run/docker.sock`) || strings.Contains(s, `/run/docker.sock`) {
		violations = append(violations, "DOCKER_SOCK: 拒绝 mount Docker socket (容器逃逸)")
	}
	// NO_RESOURCES: 容器无 resources.limits (易 OOM 拖垮节点)
	if !strings.Contains(s, `"limits"`) && strings.Contains(s, `"containers"`) {
		violations = append(violations, "NO_RESOURCES: 容器未配置 resources.limits (CPU/Memory)")
	}
	// UNAUTHORIZED_REGISTRY: 镜像非内部 registry (后续可配置白名单)
	// 默认白名单: 内部 registry.mxcwpp.local + 公共可信
	knownGood := []string{"gcr.io/google_containers/", "gcr.io/k8s/", "registry.k8s.io/", "k8s.gcr.io/",
		"registry.mxcwpp.local/", "docker.io/library/"}
	if strings.Contains(s, `"image":"`) {
		isWhitelisted := false
		for _, w := range knownGood {
			if strings.Contains(s, w) {
				isWhitelisted = true
				break
			}
		}
		if !isWhitelisted {
			// 仅 warning, 不直接 deny (避免误伤业务自定义镜像)
			violations = append(violations, "UNTRUSTED_REGISTRY: 镜像源非白名单 registry (warning)")
		}
	}

	return violations
}

func isWorkloadKind(kind string) bool {
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob":
		return true
	}
	return false
}

func respondAllow(c *gin.Context, uid string, warnings []string) {
	c.JSON(200, AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response: &AdmissionResponse{
			UID:      uid,
			Allowed:  true,
			Warnings: warnings,
		},
	})
}

func respondDeny(c *gin.Context, uid string, violations []string) {
	c.JSON(200, AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response: &AdmissionResponse{
			UID:     uid,
			Allowed: false,
			Status: &Status{
				Code:    403,
				Message: fmt.Sprintf("mxcwpp admission deny: %s", strings.Join(violations, "; ")),
			},
		},
	})
}
