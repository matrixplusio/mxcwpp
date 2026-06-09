package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/engine/ml"
)

// MLStage 用 ml.Registry 中的所有模型对事件做推理。
//
// 每个 Model 独立产 Alert (一个事件可触发多个 model 命中)。
// 分数阈值 (默认 0.7) 以上才产 Alert。
type MLStage struct {
	registry  *ml.Registry
	threshold float64
	logger    *zap.Logger
}

// NewMLStage 构造 ML stage。
func NewMLStage(reg *ml.Registry, threshold float64, logger *zap.Logger) *MLStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if threshold <= 0 {
		threshold = 0.7
	}
	return &MLStage{registry: reg, threshold: threshold, logger: logger}
}

// Name 满足 Stage interface。
func (s *MLStage) Name() string { return "ml" }

// Process 把 ev.fields 转 features 后依次跑所有 model.
//
// P1-5: 加 DataType 段过滤短路, 仅对 ML 段 (3000-3099) 跑模型, 其它 DataType 直接 return.
// 避免每事件都遍历全部 model.
func (s *MLStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.registry == nil {
		return nil, nil
	}
	// P1-5: DataType 段过滤 — ML 仅处理 EDR 内核事件 (3000-3099) + RASP (4000-4099)
	if !(ev.DataType >= 3000 && ev.DataType < 3100) && !(ev.DataType >= 4000 && ev.DataType < 4100) {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}

	var alerts []Alert
	for _, name := range s.registry.Names() {
		model, ok := s.registry.Get(name)
		if !ok {
			continue
		}
		// 按模型的 FeatureNames 提取 features
		featNames := model.FeatureNames()
		features := make([]float64, len(featNames))
		for i, k := range featNames {
			v, _ := strconv.ParseFloat(fields[k], 64)
			features[i] = v
		}

		score, label, err := model.Predict(features)
		if err != nil {
			s.logger.Debug("ml predict error",
				zap.String("model", name),
				zap.Error(err))
			continue
		}
		if score < s.threshold {
			continue
		}

		payload, _ := json.Marshal(map[string]any{
			"model":    name,
			"version":  model.Version(),
			"score":    score,
			"label":    label,
			"features": fields,
		})
		alerts = append(alerts, Alert{
			AlertID:        fmt.Sprintf("alrt-ml-%s-%d-%d", name, ev.Partition, ev.Offset),
			RuleID:         "ML_" + name,
			Severity:       severityFromScore(score),
			ATTCKTactic:    "",
			ATTCKTechnique: "",
			Payload:        payload,
		})
	}
	return alerts, nil
}

// severityFromScore 把分数映射成 severity。
func severityFromScore(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.8:
		return "high"
	case score >= 0.7:
		return "medium"
	default:
		return "low"
	}
}

var _ Stage = (*MLStage)(nil)
