package gcppubsub

import (
	"encoding/json"
	"strings"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// LogEntry Cloud Logging 日志条目结构（简化版，仅提取审计日志所需字段）
type LogEntry struct {
	InsertID     string          `json:"insertId"`
	LogName      string          `json:"logName"`
	Timestamp    string          `json:"timestamp"`
	Resource     LogResource     `json:"resource"`
	ProtoPayload json.RawMessage `json:"protoPayload"`
	JSONPayload  json.RawMessage `json:"jsonPayload"`
}

// LogResource Cloud Logging 资源信息
type LogResource struct {
	Type   string            `json:"type"`
	Labels LogResourceLabels `json:"labels"`
}

// LogResourceLabels Cloud Logging 资源标签
type LogResourceLabels struct {
	ClusterName string `json:"cluster_name"`
	Location    string `json:"location"`
	ProjectID   string `json:"project_id"`
}

// AuditLogProtoPayload GKE Admin Activity 审计日志的 protoPayload 结构
type AuditLogProtoPayload struct {
	Type               string                 `json:"@type"`
	MethodName         string                 `json:"methodName"`
	ResourceName       string                 `json:"resourceName"`
	AuthenticationInfo AuthenticationInfo     `json:"authenticationInfo"`
	AuthorizationInfo  []AuthorizationInfo    `json:"authorizationInfo"`
	RequestMetadata    RequestMetadata        `json:"requestMetadata"`
	Request            json.RawMessage        `json:"request"`
	Response           json.RawMessage        `json:"response"`
	Status             map[string]interface{} `json:"status"`
}

// AuthenticationInfo 认证信息
type AuthenticationInfo struct {
	PrincipalEmail string `json:"principalEmail"`
}

// AuthorizationInfo 授权信息
type AuthorizationInfo struct {
	Permission string `json:"permission"`
	Resource   string `json:"resource"`
	Granted    bool   `json:"granted"`
}

// RequestMetadata 请求元数据
type RequestMetadata struct {
	CallerIP        string `json:"callerIp"`
	CallerUserAgent string `json:"callerSuppliedUserAgent"`
}

// TransformLogEntry 将 Cloud Logging LogEntry 转换为 K8s AuditEvent 列表
func TransformLogEntry(entry *LogEntry) []model.AuditEvent {
	// 只处理 k8s_cluster 类型
	if entry.Resource.Type != "k8s_cluster" {
		return nil
	}

	// 优先处理 protoPayload（Admin Activity 审计日志）
	if len(entry.ProtoPayload) > 0 {
		return transformProtoPayload(entry)
	}

	// 尝试 jsonPayload（Data Access 审计日志）
	if len(entry.JSONPayload) > 0 {
		return transformJSONPayload(entry)
	}

	return nil
}

// transformProtoPayload 转换 Admin Activity 审计日志
func transformProtoPayload(entry *LogEntry) []model.AuditEvent {
	var payload AuditLogProtoPayload
	if err := json.Unmarshal(entry.ProtoPayload, &payload); err != nil {
		return nil
	}

	verb, resource, subresource, name, namespace := parseMethodName(payload.MethodName, payload.ResourceName)
	if verb == "" || resource == "" {
		return nil
	}

	event := model.AuditEvent{
		Verb:       verb,
		User:       model.AuditUser{Username: payload.AuthenticationInfo.PrincipalEmail},
		UserAgent:  payload.RequestMetadata.CallerUserAgent,
		RequestURI: payload.ResourceName,
		Stage:      "ResponseComplete",
		ObjectRef: &model.AuditObjectRef{
			Resource:    resource,
			Subresource: subresource,
			Namespace:   namespace,
			Name:        name,
		},
		RequestObj: payload.Request,
	}

	if payload.RequestMetadata.CallerIP != "" {
		event.SourceIPs = []string{payload.RequestMetadata.CallerIP}
	}

	return []model.AuditEvent{event}
}

// transformJSONPayload 转换 Data Access 审计日志（结构类似，但在 jsonPayload 中）
func transformJSONPayload(entry *LogEntry) []model.AuditEvent {
	// Data Access 日志也可能包含一个嵌套的审计事件
	var payload AuditLogProtoPayload
	if err := json.Unmarshal(entry.JSONPayload, &payload); err != nil {
		return nil
	}

	if payload.MethodName == "" {
		return nil
	}

	return transformProtoPayload(&LogEntry{
		InsertID:     entry.InsertID,
		LogName:      entry.LogName,
		Timestamp:    entry.Timestamp,
		Resource:     entry.Resource,
		ProtoPayload: entry.JSONPayload,
	})
}

// parseMethodName 解析 GKE 审计日志的 methodName 和 resourceName
//
// GKE methodName 格式示例：
//   - io.k8s.core.v1.pods.create
//   - io.k8s.core.v1.pods.exec.create
//   - io.k8s.core.v1.secrets.get
//   - io.k8s.rbac.authorization.v1.clusterrolebindings.create
//
// resourceName 格式示例：
//   - core/v1/namespaces/default/pods/my-pod
//   - core/v1/namespaces/kube-system/secrets/my-secret
//   - rbac.authorization.k8s.io/v1/clusterrolebindings/my-binding
func parseMethodName(methodName, resourceName string) (verb, resource, subresource, name, namespace string) {
	// 解析 methodName 提取 verb 和 resource
	parts := strings.Split(methodName, ".")
	if len(parts) < 2 {
		return
	}

	// verb 是最后一个部分
	verb = parts[len(parts)-1]

	// 判断是否有 subresource（如 pods.exec.create → resource=pods, subresource=exec）
	// 在 io.k8s.core.v1.pods.exec.create 中，倒数第二个是 subresource，倒数第三个是 resource
	if len(parts) >= 3 {
		candidate := parts[len(parts)-2]
		// 常见的 subresource：exec, attach, log, portforward, proxy, binding, status
		knownSubresources := map[string]bool{
			"exec": true, "attach": true, "log": true,
			"portforward": true, "proxy": true, "binding": true, "status": true,
		}
		if knownSubresources[candidate] {
			subresource = candidate
			if len(parts) >= 4 {
				resource = parts[len(parts)-3]
			}
		} else {
			resource = candidate
		}
	}

	// 从 resourceName 解析 namespace 和 name
	if resourceName != "" {
		rParts := strings.Split(resourceName, "/")
		// 查找 namespaces/<ns> 和最后的资源名
		for i, p := range rParts {
			if p == "namespaces" && i+1 < len(rParts) {
				namespace = rParts[i+1]
			}
		}
		if len(rParts) > 0 {
			name = rParts[len(rParts)-1]
		}
	}

	return
}
