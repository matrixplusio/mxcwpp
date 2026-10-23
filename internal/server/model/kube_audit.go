package model

import (
	"encoding/json"
	"time"
)

// AuditEvent K8s Audit Event 简化结构
type AuditEvent struct {
	Level      string          `json:"level"`
	AuditID    string          `json:"auditID"`
	Stage      string          `json:"stage"`
	RequestURI string          `json:"requestURI"`
	Verb       string          `json:"verb"`
	User       AuditUser       `json:"user"`
	SourceIPs  []string        `json:"sourceIPs"`
	UserAgent  string          `json:"userAgent"`
	ObjectRef  *AuditObjectRef `json:"objectRef"`
	RequestObj json.RawMessage `json:"requestObject"`
	Timestamp  time.Time       `json:"requestReceivedTimestamp"`
	// ResponseStatus 请求的结果。原生审计日志自带；GKE 的日志在转换时由 status 换算成 HTTP 状态码。
	// 为空表示不知道结果。
	ResponseStatus *AuditResponseStatus `json:"responseStatus,omitempty"`
	// Annotations 原生审计日志的注解，其中 authorization.k8s.io/decision 是授权结论（allow / forbid）。
	// GKE 的日志在转换时由 authorizationInfo 推出这一项。
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AuditAuthzDecisionKey 审计注解里授权结论的键。
const AuditAuthzDecisionKey = "authorization.k8s.io/decision"

// AuditResponseStatus 审计事件里请求的结果，Code 为 HTTP 状态码。
type AuditResponseStatus struct {
	Code int `json:"code"`
}

// Denied 请求在认证或授权这一步就被拒了：401，或者 403 且授权结论是 forbid。
//
// 只看 403 不够：准入控制器（admission webhook、Pod 安全标准）挡下的请求同样返回 403，
// 那时请求已经通过了授权——匿名用户能走到准入这一步，本身就是严重的授权配置错误。
// 拿不到授权结论、或结论不是 forbid 时返回 false：用它来降级时，拿不准就按「成功了」处理。
func (e *AuditEvent) Denied() bool {
	if e.ResponseStatus == nil {
		return false
	}
	switch e.ResponseStatus.Code {
	case 401:
		return true
	case 403:
		return e.Annotations[AuditAuthzDecisionKey] == "forbid"
	}
	return false
}

// DirectSourceIP 直接连到 API Server 的那一端。sourceIPs 依次是 X-Forwarded-For、X-Real-Ip、
// 对端地址，前面几项由请求方随意填写，只有最后一项是 API Server 自己看到的。
func (e *AuditEvent) DirectSourceIP() string {
	if len(e.SourceIPs) == 0 {
		return ""
	}
	return e.SourceIPs[len(e.SourceIPs)-1]
}

// AuditUser Audit 事件中的用户信息
type AuditUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

// AuditObjectRef Audit 事件中的对象引用
type AuditObjectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	APIGroup    string `json:"apiGroup"`
	APIVersion  string `json:"apiVersion"`
	Subresource string `json:"subresource"`
}

// AuditEventList K8s Audit EventList
type AuditEventList struct {
	Kind  string       `json:"kind"`
	Items []AuditEvent `json:"items"`
}
