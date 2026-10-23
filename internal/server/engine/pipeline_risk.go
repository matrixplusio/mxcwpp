package engine

import (
	"strings"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/risk"
)

// WithRisk 接入实体风险累积。每个阶段的每次命中都会喂给它。
//
// 不按白名单过滤：白名单是为单条告警降噪写的，按程序名、命令行子串、整台主机豁免都合法；
// 原样搬进组合判断，一条为降噪加的豁免会让依赖组合才能发现的攻击也一起看不见。
// 风险层的降噪靠普遍性系数与有效战术门槛。
func (p *Pipeline) WithRisk(acc *risk.Accumulator) *Pipeline {
	p.risk = acc
	return p
}

// observeRisk 把一次命中转成风险累积的输入。
func (p *Pipeline) observeRisk(stage string, ev PipelineEvent, a Alert) {
	fields, _ := ev.Fields()
	h := risk.Hit{
		HostID:    ev.HostID,
		RuleKey:   riskRuleKey(stage, a.RuleID),
		RuleName:  a.RuleName,
		Severity:  a.Severity,
		Tactic:    riskTactic(a),
		Technique: a.ATTCKTechnique,
		Shadow:    a.Shadow,
		At:        ev.EventTime,
	}
	if fields != nil {
		h.PID, h.Exe, h.Cmdline = fields["pid"], fields["exe"], fields["cmdline"]
	}
	p.risk.Observe(h)
}

// riskTactic 阶段自己声明了战术（TA####）时以它为准；否则由技术号推主战术。
// 技术号的主战术映射是一对一的，会把横跨多个战术的技术归到一个桶里，所以只作后备。
func riskTactic(a Alert) string {
	if strings.HasPrefix(a.ATTCKTactic, "TA") {
		return a.ATTCKTactic
	}
	return celengine.TacticFromTechnique(a.ATTCKTechnique)
}

// riskRuleKey 换成告警表里的规则写法：CEL 与攻击链的规则号是纯数字，区分不了。
func riskRuleKey(stage, id string) string {
	switch stage {
	case "cel_rule":
		return "cel-" + id
	case "sequence":
		return "seq-" + id
	}
	return id
}
