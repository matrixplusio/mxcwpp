// Package httptrans — RASP ingest endpoint (P5-2).
//
// 数据流:
//
//	业务进程 → 本地 UDS (rasp-java.sock / rasp-py.sock / rasp-php.sock / rasp-node.sock / rasp-go.sock)
//	  → Agent rasp_uds.Listener 收 4 byte BE length + JSON 帧
//	  → Agent 批量 POST 到本 endpoint
//	  → AC 校验 + 落 Kafka topic mxsec.agent.rasp
//	  → Consumer/Engine RASPStage 消费 → Alert
//
// 严格 read-only RASP 哲学: 这里强制改 mode=observe, 不接受业务进程上报的 protect.
package httptrans

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/common/kafka"
)

// RaspEvent Agent 转发上来的 RASP 事件 (与 plugins/rasp-* 反序列化一致).
type RaspEvent struct {
	Kind        string   `json:"kind"`
	ClassName   string   `json:"class_name"`
	MethodName  string   `json:"method_name"`
	Arguments   []string `json:"arguments,omitempty"`
	StackTrace  string   `json:"stack_trace,omitempty"`
	HTTPMethod  string   `json:"http_method,omitempty"`
	HTTPURL     string   `json:"http_url,omitempty"`
	HTTPClient  string   `json:"http_client,omitempty"`
	PID         int      `json:"pid"`
	TenantID    string   `json:"tenant_id"`
	TimestampMS int64    `json:"timestamp"`
	Mode        string   `json:"mode"`
	Language    string   `json:"language"`
}

// raspIngestRequest 一次批量上报.
type raspIngestRequest struct {
	AgentID string      `json:"agent_id"`
	HostID  string      `json:"host_id"`
	Batch   []RaspEvent `json:"batch"`
}

// raspIngestResponse 应答.
type raspIngestResponse struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors,omitempty"`
}

// KafkaProducer 抽象 sarama.AsyncProducer / 测试 mock.
type KafkaProducer interface {
	SendMessage(ctx context.Context, topic string, key, payload []byte) error
}

// RaspIngestHandler 处理 RASP ingest.
type RaspIngestHandler struct {
	producer KafkaProducer
	logger   *zap.Logger
	maxBatch int
}

// NewRaspIngestHandler 构造.
func NewRaspIngestHandler(producer KafkaProducer, logger *zap.Logger) *RaspIngestHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &RaspIngestHandler{producer: producer, logger: logger, maxBatch: 500}
}

// Register 注册 POST /internal/rasp/ingest.
func (h *RaspIngestHandler) Register(rg *gin.RouterGroup) {
	rg.POST("/rasp/ingest", h.Ingest)
}

// Ingest 接收 Agent 转发的 RASP 批量事件.
func (h *RaspIngestHandler) Ingest(c *gin.Context) {
	var req raspIngestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json: " + err.Error()})
		return
	}
	if req.AgentID == "" || req.HostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id and host_id required"})
		return
	}
	if len(req.Batch) == 0 {
		c.JSON(http.StatusOK, raspIngestResponse{})
		return
	}
	if len(req.Batch) > h.maxBatch {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("batch too large: %d > %d", len(req.Batch), h.maxBatch),
		})
		return
	}

	resp := raspIngestResponse{}
	ctx := c.Request.Context()
	for i := range req.Batch {
		ev := &req.Batch[i]
		// 哲学硬约束: RASP 永远 observe, Agent 无权报 protect
		ev.Mode = "observe"
		if ev.TenantID == "" {
			ev.TenantID = "t-default"
		}
		if !isValidLanguage(ev.Language) {
			resp.Rejected++
			resp.Errors = append(resp.Errors, "invalid language: "+ev.Language)
			continue
		}
		if !isValidKind(ev.Kind) {
			resp.Rejected++
			continue
		}
		if ev.TimestampMS == 0 {
			ev.TimestampMS = time.Now().UnixMilli()
		}
		// 构造 Pipeline payload
		payload := map[string]any{
			"data_type": dataTypeForLanguage(ev.Language),
			"agent_id":  req.AgentID,
			"host_id":   req.HostID,
			"tenant_id": ev.TenantID,
			"timestamp": ev.TimestampMS,
			"rasp": map[string]any{
				"kind":        ev.Kind,
				"class_name":  ev.ClassName,
				"method_name": ev.MethodName,
				"arguments":   ev.Arguments,
				"stack_trace": ev.StackTrace,
				"http_method": ev.HTTPMethod,
				"http_url":    ev.HTTPURL,
				"pid":         ev.PID,
				"mode":        "observe",
				"language":    ev.Language,
			},
		}
		buf, err := json.Marshal(payload)
		if err != nil {
			resp.Rejected++
			continue
		}
		key := []byte(req.HostID + ":" + strconv.Itoa(ev.PID))
		if err := h.producer.SendMessage(ctx, kafka.TopicRASP, key, buf); err != nil {
			resp.Rejected++
			resp.Errors = append(resp.Errors, "kafka: "+err.Error())
			continue
		}
		resp.Accepted++
	}

	if resp.Accepted > 0 {
		h.logger.Debug("rasp ingest",
			zap.String("agent_id", req.AgentID),
			zap.String("host_id", req.HostID),
			zap.Int("accepted", resp.Accepted),
			zap.Int("rejected", resp.Rejected))
	}
	c.JSON(http.StatusOK, resp)
}

// dataTypeForLanguage 把语言映射到 DataType 段 (4000-4099).
//
//	4001: java
//	4002: python
//	4003: php
//	4004: node
//	4005: go
//	4099: 未知 (兜底)
func dataTypeForLanguage(lang string) int {
	switch strings.ToLower(lang) {
	case "java":
		return 4001
	case "python":
		return 4002
	case "php":
		return 4003
	case "nodejs", "node":
		return 4004
	case "go":
		return 4005
	}
	return 4099
}

func isValidLanguage(lang string) bool {
	switch strings.ToLower(lang) {
	case "java", "python", "php", "node", "nodejs", "go":
		return true
	}
	return false
}

// isValidKind 白名单, 防恶意 Agent 上报任意 kind.
func isValidKind(k string) bool {
	if k == "" {
		return false
	}
	allowed := []string{
		// Java
		"runtime_exec", "process_builder", "jndi_lookup", "deserialize", "define_class", "filter_registered",
		// Python
		"compile", "exec", "subprocess_popen", "os_system", "os_exec", "os_spawn",
		"socket_connect", "socket_bind", "pickle_find_class", "marshal_loads",
		"importlib_find_spec", "urllib_request", "open",
		// PHP
		"php_dangerous_fn", "php_eval",
		// Node
		"cmd_exec", "cmd_spawn", "cmd_exec_sync", "fs_unlink", "fs_unlink_sync", "fs_write",
		"http_request", "https_request", "vm_eval", "native_load",
		// Go
		"sql_query", "http_out", "file_write", "plugin_load",
	}
	for _, a := range allowed {
		if k == a {
			return true
		}
	}
	return false
}
