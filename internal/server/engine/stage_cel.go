package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
)

// CelRuleStage 把 PipelineEvent 喂给 celengine.Engine,
// 返回命中的 DetectionRule 对应的 Alert(s)。
//
// v2 拆分: Engine 服务独立 deploy 时, alertGen 直接 upsert alerts 表 (取代旧
// 架构 Consumer 内嵌 cel 写 DB 的路径). Kafka mxcwpp.engine.alert 仍推送, 供后续
// ML / SOAR / 通知 异步消费.
type CelRuleStage struct {
	celEngine *celengine.Engine
	alertGen  *celengine.AlertGenerator // 可选: 非 nil 时 stage 内直接落 DB
	logger    *zap.Logger
}

// NewCelRuleStage 构造 CEL 规则 stage。
func NewCelRuleStage(cel *celengine.Engine, logger *zap.Logger) *CelRuleStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &CelRuleStage{celEngine: cel, logger: logger}
}

// WithAlertGenerator 注入 AlertGenerator, 让 stage 在命中时直接 upsert alerts 表.
// 不调时 stage 仅返 Alert slice (pipeline 推 Kafka), 不写 DB.
func (s *CelRuleStage) WithAlertGenerator(g *celengine.AlertGenerator) *CelRuleStage {
	s.alertGen = g
	return s
}

// Name 满足 Stage interface。
func (s *CelRuleStage) Name() string { return "cel_rule" }

// Process 把 ev.Payload 解码为 fields map,调用 celEngine.Evaluate。
func (s *CelRuleStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.celEngine == nil {
		return nil, nil
	}

	// 把 ev.Payload 解码成 fields map (celengine.Engine 接受 map[string]string)
	fields, err := ev.Fields()
	if err != nil {
		s.logger.Debug("cel stage decode payload failed", zap.Error(err))
		return nil, nil
	}

	// 注入 ev 顶层字段 (host_id/tenant_id/agent_id) 供 CEL 表达式引用
	if ev.HostID != "" {
		fields["host_id"] = ev.HostID
	}
	if ev.TenantID != "" {
		fields["tenant_id"] = ev.TenantID
	}
	if ev.AgentID != "" {
		fields["agent_id"] = ev.AgentID
	}

	hits := s.celEngine.Evaluate(ev.DataType, fields)
	if len(hits) == 0 {
		return nil, nil
	}

	// 直接 upsert alerts 表 (拆分架构核心: engine 接管检测落 DB).
	if s.alertGen != nil && ev.HostID != "" {
		s.alertGen.Generate(ev.HostID, hits, fields)
	}

	alerts := make([]Alert, 0, len(hits))
	for _, rule := range hits {
		payload, _ := json.Marshal(map[string]any{
			"matched_fields": fields,
			"rule_name":      rule.Name,
		})
		alerts = append(alerts, Alert{
			AlertID:        fmt.Sprintf("alrt-%d-%d-%d", rule.ID, ev.Partition, ev.Offset),
			RuleID:         fmt.Sprint(rule.ID),
			Severity:       rule.Severity,
			ATTCKTactic:    rule.MitreID,
			ATTCKTechnique: rule.MitreID,
			Payload:        payload,
			Action:         actionFromRule(rule),
		})
	}
	return alerts, nil
}

// payloadToFields 把任意 JSON payload 解码成 string->string map。
//
// celengine 历史接口接受 map[string]string,这里做适配:
//   - string 字段直接拿
//   - 其他类型 (number/bool/object) 用 fmt.Sprint 转字符串
func payloadToFields(payload json.RawMessage) (map[string]string, error) {
	if len(payload) == 0 {
		return map[string]string{}, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch s := v.(type) {
		case string:
			out[k] = s
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprint(s)
		}
	}
	return out, nil
}

// actionFromRule 把 DetectionRule.Action 转 AlertEnvelope.Action JSON。
//
// model.DetectionRule.Action 是结构化的处置动作描述,
// AlertEnvelope.Action 是 JSON, observe 时填 WouldAction, protect 时填 Action。
func actionFromRule(rule any) json.RawMessage {
	b, err := json.Marshal(rule)
	if err != nil {
		return nil
	}
	return b
}

// 编译期断言
var _ Stage = (*CelRuleStage)(nil)
