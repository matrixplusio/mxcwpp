// Package rasp 实现 RASP (Runtime Application Self-Protection) 服务端事件接收与检测。
//
// 严格 read-only 哲学 (Sprint 4 PR63 起):
//
//	mxsec RASP 仅做观察 + 告警,不阻断业务,不抛异常,不修改进程行为。
//	Agent 端 JVMTI Agent / php-fpm extension / Python pep667 hook
//	仅采集事件,不参与控制流。
//
// 选择 read-only 原因:
//   - 业务侧零风险 (RASP 阻断历史上多次造成应用宕机)
//   - 符合 v2.0 observe-first 哲学 (docs/operating-modes.md)
//   - 后续 Sprint 5+ 在客户特定授权下才上 enforce 模式
//
// 设计文档: ref/04-运行时.md §5 RASP / docs/edr-agent-design.md
package rasp

import (
	"encoding/json"
	"time"
)

// EventKind 是 RASP 事件类型。
type EventKind string

const (
	// Java
	KindJavaClassLoad   EventKind = "java.class_load"  // 类加载 (内存马典型)
	KindJavaReflection  EventKind = "java.reflection"  // 反射调用 (Runtime.exec/ProcessBuilder)
	KindJavaDeserialize EventKind = "java.deserialize" // 反序列化
	KindJavaJDBC        EventKind = "java.jdbc"        // JDBC SQL
	KindJavaFile        EventKind = "java.file"        // 文件操作
	KindJavaHTTPClient  EventKind = "java.http_client" // HTTP 出站调用
	KindJavaMemshell    EventKind = "java.memshell"    // 内存马 (Filter/Listener/Servlet 动态注册)

	// PHP
	KindPHPEval       EventKind = "php.eval"
	KindPHPInclude    EventKind = "php.include"
	KindPHPSystemCall EventKind = "php.system_call"

	// Python
	KindPyExec       EventKind = "py.exec"
	KindPyImport     EventKind = "py.dynamic_import"
	KindPySubprocess EventKind = "py.subprocess"

	// Node.js
	KindNodeChildProcess EventKind = "node.child_process"
	KindNodeRequire      EventKind = "node.dynamic_require"
)

// Event 是 RASP Agent 上报的运行时事件。
//
// 所有字段 read-only;Engine 不会通过事件反向影响 Agent 进程行为。
type Event struct {
	HostID      string            `json:"host_id"`
	TenantID    string            `json:"tenant_id"`
	AgentID     string            `json:"agent_id"`
	PID         int32             `json:"pid"`
	Language    string            `json:"language"` // java / php / python / node / go
	Kind        EventKind         `json:"kind"`
	ClassName   string            `json:"class_name,omitempty"` // Java/Node 类名
	MethodName  string            `json:"method_name,omitempty"`
	Arguments   []string          `json:"arguments,omitempty"`    // 关键参数 (前 256 字符截断)
	StackTrace  []string          `json:"stack_trace,omitempty"`  // 调用栈 (最多 50 帧)
	HTTPContext *HTTPContext      `json:"http_context,omitempty"` // 当前 HTTP 请求上下文
	Metadata    map[string]string `json:"metadata,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	// 严格 read-only 标记
	Mode string `json:"mode"` // 永远为 "observe", protect 模式留客户授权后启用
}

// HTTPContext 是 RASP 事件附带的 HTTP 请求上下文。
type HTTPContext struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	RemoteIP string            `json:"remote_ip"`
	Headers  map[string]string `json:"headers,omitempty"` // 过滤敏感 header (Cookie/Authorization 仅 hash)
}

// EnsureObserveMode 强制 mode=observe (read-only 哲学硬约束)。
//
// Agent 端无论上报什么,服务端都强制改写为 observe。
// 后续 Sprint 启用 protect 时移除此函数。
func (e *Event) EnsureObserveMode() {
	e.Mode = "observe"
}

// Marshal 序列化 (落 Kafka mxsec.engine.alert 用)。
func (e *Event) Marshal() ([]byte, error) {
	e.EnsureObserveMode()
	return json.Marshal(e)
}

// ParseFromFields 从 PipelineEvent.fields 解析 RASP Event。
//
// Agent 上报字段映射:
//
//	language / kind / class_name / method_name / arguments_json /
//	stack_trace_json / http_method / http_url / http_remote_ip / pid
func ParseFromFields(hostID, tenantID, agentID string, fields map[string]string) *Event {
	if hostID == "" || fields["kind"] == "" {
		return nil
	}
	ev := &Event{
		HostID:     hostID,
		TenantID:   tenantID,
		AgentID:    agentID,
		PID:        parseInt32(fields["pid"]),
		Language:   fields["language"],
		Kind:       EventKind(fields["kind"]),
		ClassName:  fields["class_name"],
		MethodName: fields["method_name"],
		Mode:       "observe",
		Timestamp:  time.Now(),
	}
	if v := fields["arguments_json"]; v != "" {
		_ = json.Unmarshal([]byte(v), &ev.Arguments)
	}
	if v := fields["stack_trace_json"]; v != "" {
		_ = json.Unmarshal([]byte(v), &ev.StackTrace)
	}
	if fields["http_method"] != "" {
		ev.HTTPContext = &HTTPContext{
			Method:   fields["http_method"],
			URL:      fields["http_url"],
			RemoteIP: fields["http_remote_ip"],
		}
	}
	return ev
}

// MemshellIndicators 是内存马命中规则集 (类加载时检查)。
//
// 返回非空 → 命中内存马;返回空 → 正常类加载。
func MemshellIndicators(ev Event) []string {
	if ev.Kind != KindJavaClassLoad {
		return nil
	}
	var hits []string
	// 类名含可疑前缀
	for _, suspect := range []string{
		"AntCommandHandler", "Behinder", "Godzilla", "ChinaShell",
		"AntSwordShell", "MemShell", "FreeMarkerRMI", "Cknife",
	} {
		if containsCaseInsensitive(ev.ClassName, suspect) {
			hits = append(hits, "class_name_match:"+suspect)
		}
	}
	// stack_trace 含可疑特征 (命中一次即可,不重复加 hit)
stackLoop:
	for _, frame := range ev.StackTrace {
		switch {
		case containsCaseInsensitive(frame, "javax.servlet.Filter.doFilter"),
			containsCaseInsensitive(frame, "javax.servlet.Servlet.service"),
			containsCaseInsensitive(frame, "org.apache.catalina.core.StandardContext.addFilterDef"):
			// 运行时动态注册 Filter/Servlet 是经典内存马指标
			hits = append(hits, "dynamic_filter_servlet_register")
			break stackLoop
		}
	}
	return hits
}

func containsCaseInsensitive(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	ls, lsub := toLower(s), toLower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func parseInt32(s string) int32 {
	var n int32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int32(c-'0')
	}
	return n
}
