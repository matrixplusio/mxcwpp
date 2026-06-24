package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
)

// SequenceStage 接入 celengine.SequenceDetector,
// 检测 N 次内多事件触发的序列模式 (暴力破解 / 多次失败登录 / 反弹shell 多步)。
type SequenceStage struct {
	detector *celengine.SequenceDetector
	logger   *zap.Logger
}

// NewSequenceStage 构造 sequence stage。
func NewSequenceStage(d *celengine.SequenceDetector, logger *zap.Logger) *SequenceStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SequenceStage{detector: d, logger: logger}
}

// Name 返回 stage 名。
func (s *SequenceStage) Name() string { return "sequence" }

// Process 把 ev 喂给 detector,返回命中的 SequenceRule -> Alert。
func (s *SequenceStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil || ev.HostID == "" {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		s.logger.Debug("sequence decode payload failed", zap.Error(err))
		return nil, nil
	}
	if ev.TenantID != "" {
		fields["tenant_id"] = ev.TenantID
	}

	hits := s.detector.Evaluate(ev.HostID, ev.DataType, fields)
	if len(hits) == 0 {
		return nil, nil
	}

	alerts := make([]Alert, 0, len(hits))
	for _, rule := range hits {
		payload, _ := json.Marshal(map[string]any{
			"matched_fields": fields,
			"rule_name":      rule.Name,
		})
		alerts = append(alerts, Alert{
			AlertID:        fmt.Sprintf("alrt-seq-%d-%d-%d", rule.ID, ev.Partition, ev.Offset),
			RuleID:         fmt.Sprint(rule.ID),
			Severity:       rule.Severity,
			ATTCKTactic:    rule.MitreID,
			ATTCKTechnique: rule.MitreID,
			Payload:        payload,
		})
	}
	return alerts, nil
}

var _ Stage = (*SequenceStage)(nil)
