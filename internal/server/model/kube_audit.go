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
