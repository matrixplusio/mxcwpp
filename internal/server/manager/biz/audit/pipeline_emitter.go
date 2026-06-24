// Package audit — 把后端 ConfigChange / Quarantine 事件推到 Engine Pipeline (P5-5).
//
// 设计目的: 用一个统一抽象把后端 worker 写出来的"治理事件"丢到 Engine Pipeline,
// 让所有事件 (含审计、隔离箱、CR) 都走告警生命周期 + Storyline 关联, 不绕过 Engine.
//
// Topic 复用: 仍用 mxcwpp.engine.alert 的输入侧 mxcwpp.engine.audit (新增).
// DataType:
//
//	14501: 配置变更审计
//	14502: 隔离箱审计
//
// Worker 调用入口:
//
//	emitter.EmitConfigChange(ctx, cr)
//	emitter.EmitQuarantine(ctx, qf)
package audit

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"go.uber.org/zap"
)

// PipelineEmitter Worker → Pipeline 桥接.
type PipelineEmitter struct {
	producer KafkaProducer
	logger   *zap.Logger
	topic    string
}

// KafkaProducer 与 agentcenter/httptrans 同抽象, 避免循环 import.
type KafkaProducer interface {
	SendMessage(ctx context.Context, topic string, key, payload []byte) error
}

// NewPipelineEmitter 构造.
func NewPipelineEmitter(producer KafkaProducer, topic string, logger *zap.Logger) *PipelineEmitter {
	if logger == nil {
		logger = zap.NewNop()
	}
	if topic == "" {
		topic = "mxcwpp.engine.audit"
	}
	return &PipelineEmitter{producer: producer, topic: topic, logger: logger}
}

// ConfigChangeFact ConfigChangeWorker apply 完成后调.
type ConfigChangeFact struct {
	RequestID     uint
	TenantID      string
	TargetTable   string
	TargetKey     string
	OldValue      string
	ProposedValue string
	RequestedBy   string
	Approvers     string
	AppliedAt     time.Time
}

// EmitConfigChange 落 Pipeline.
func (e *PipelineEmitter) EmitConfigChange(ctx context.Context, f ConfigChangeFact) {
	payload := map[string]any{
		"tenant_id":   f.TenantID,
		"data_type":   14501,
		"received_at": time.Now().Format(time.RFC3339Nano),
		"payload": map[string]any{
			"request_id":     f.RequestID,
			"target_table":   f.TargetTable,
			"target_key":     f.TargetKey,
			"old_value":      f.OldValue,
			"proposed_value": f.ProposedValue,
			"requested_by":   f.RequestedBy,
			"approvers":      f.Approvers,
			"applied_at_ms":  f.AppliedAt.UnixMilli(),
		},
	}
	e.emit(ctx, payload, "cr-"+strconv.FormatUint(uint64(f.RequestID), 10))
}

// QuarantineFact 隔离/还原后调.
type QuarantineFact struct {
	QID       string
	TenantID  string
	HostID    string
	OrigPath  string
	Hash      string
	Reason    string
	Operation string // quarantine | restore
	RuleID    string
}

// EmitQuarantine 落 Pipeline.
func (e *PipelineEmitter) EmitQuarantine(ctx context.Context, f QuarantineFact) {
	payload := map[string]any{
		"tenant_id":   f.TenantID,
		"host_id":     f.HostID,
		"data_type":   14502,
		"received_at": time.Now().Format(time.RFC3339Nano),
		"payload": map[string]any{
			"qid":       f.QID,
			"host_id":   f.HostID,
			"orig_path": f.OrigPath,
			"hash":      f.Hash,
			"reason":    f.Reason,
			"operation": f.Operation,
			"rule_id":   f.RuleID,
		},
	}
	e.emit(ctx, payload, "q-"+f.QID)
}

func (e *PipelineEmitter) emit(ctx context.Context, p map[string]any, key string) {
	if e.producer == nil {
		return
	}
	buf, err := json.Marshal(p)
	if err != nil {
		e.logger.Warn("audit emit marshal", zap.Error(err))
		return
	}
	if err := e.producer.SendMessage(ctx, e.topic, []byte(key), buf); err != nil {
		e.logger.Warn("audit emit kafka", zap.Error(err), zap.String("key", key))
	}
}
