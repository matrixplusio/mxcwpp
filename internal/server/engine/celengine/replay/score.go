package replay

import (
	"fmt"
	"sort"
)

// Matcher 对一条事件返回命中的规则 ID 列表。
//
// 用接口而不是直接依赖 *celengine.Engine：回放只关心"这条事件有没有被检出"，
// 引擎的构造依赖（DB、进程树、CEL 环境）不该被拖进语料测试里。
type Matcher interface {
	MatchIDs(dataType int32, fields map[string]string) []string
}

// Outcome 是一条样本的回放结果。
type Outcome struct {
	Sample  Sample
	Matched []string
	// Detected 是否被任一规则命中。
	Detected bool
}

// Report 是一次回放的总体结果。
type Report struct {
	// Recall 攻击样本被检出的比例。
	Recall float64
	// FalsePositiveRate 正常样本被误命中的比例。
	FalsePositiveRate float64

	AttackTotal   int
	AttackCaught  int
	BenignTotal   int
	BenignFlagged int

	// Missed 漏掉的攻击样本。
	//
	// 单给一个召回率数字没有用——要修的是具体漏了哪条。
	Missed []Outcome
	// FalsePositives 误命中的正常样本。
	FalsePositives []Outcome

	// ByTechnique 按 ATT&CK 技术拆分的召回率。
	//
	// 总召回率会掩盖结构性缺口：某个技术一条都没检出，在总分里可能只掉几个点，
	// 但它意味着这类攻击可以完全无声地通过。
	ByTechnique map[string]TechniqueScore
}

// TechniqueScore 是单个技术的召回情况。
type TechniqueScore struct {
	Total  int
	Caught int
	Recall float64
}

// Run 用语料回放规则并给出报告。
func Run(c *Corpus, m Matcher) (*Report, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	r := &Report{ByTechnique: make(map[string]TechniqueScore)}

	for _, s := range c.Samples {
		ids := m.MatchIDs(s.DataType, s.Fields)
		out := Outcome{Sample: s, Matched: ids, Detected: len(ids) > 0}

		switch s.Label {
		case LabelAttack:
			r.AttackTotal++
			ts := r.ByTechnique[s.Technique]
			ts.Total++
			if out.Detected {
				r.AttackCaught++
				ts.Caught++
			} else {
				r.Missed = append(r.Missed, out)
			}
			r.ByTechnique[s.Technique] = ts
		case LabelBenign:
			r.BenignTotal++
			if out.Detected {
				r.BenignFlagged++
				r.FalsePositives = append(r.FalsePositives, out)
			}
		}
	}

	if r.AttackTotal > 0 {
		r.Recall = float64(r.AttackCaught) / float64(r.AttackTotal)
	}
	if r.BenignTotal > 0 {
		r.FalsePositiveRate = float64(r.BenignFlagged) / float64(r.BenignTotal)
	}
	for k, ts := range r.ByTechnique {
		if ts.Total > 0 {
			ts.Recall = float64(ts.Caught) / float64(ts.Total)
		}
		r.ByTechnique[k] = ts
	}
	return r, nil
}

// UncoveredTechniques 返回语料里完全没有覆盖到的技术。
//
// 这些技术的召回率是未知，不是 100%。把"没测过"读成"没问题"，
// 正是覆盖率报告最常见的骗法。
func (r *Report) UncoveredTechniques(want []string) []string {
	var missing []string
	for _, tech := range want {
		if _, ok := r.ByTechnique[tech]; !ok {
			missing = append(missing, tech)
		}
	}
	sort.Strings(missing)
	return missing
}

// ZeroRecallTechniques 返回一条都没检出的技术。
//
// 这类缺口比低召回更严重：该技术的攻击可以完全无声地通过。
func (r *Report) ZeroRecallTechniques() []string {
	var out []string
	for tech, ts := range r.ByTechnique {
		if ts.Caught == 0 {
			out = append(out, tech)
		}
	}
	sort.Strings(out)
	return out
}

// Summary 返回可读摘要。
func (r *Report) Summary() string {
	return fmt.Sprintf(
		"召回 %.1f%% (%d/%d)，正常语料误命中 %.1f%% (%d/%d)，覆盖 %d 个技术",
		r.Recall*100, r.AttackCaught, r.AttackTotal,
		r.FalsePositiveRate*100, r.BenignFlagged, r.BenignTotal,
		len(r.ByTechnique))
}
