package replay_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	builtinrules "github.com/matrixplusio/mxcwpp/configs/rules"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine/replay"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// corpusDir 标注语料目录。
const corpusDir = "testdata/corpus"

// loadBuiltinRules 从内置规则 YAML 载入规则。
//
// 直接读发布用的那份 YAML，而不是测试里另写一套：另写一套只能证明
// 那套自制规则有效，与真正部署出去的东西无关。
func loadBuiltinRules(t *testing.T) []model.DetectionRule {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(string(builtinrules.BuiltinRulesYAML))); err != nil {
		t.Fatalf("解析内置规则 YAML 失败: %v", err)
	}
	var file struct {
		Rules []struct {
			Name       string   `mapstructure:"name"`
			Expression string   `mapstructure:"expression"`
			Severity   string   `mapstructure:"severity"`
			Category   string   `mapstructure:"category"`
			MitreID    string   `mapstructure:"mitre_id"`
			DataTypes  []string `mapstructure:"data_types"`
			Fidelity   string   `mapstructure:"fidelity"`
		} `mapstructure:"rules"`
	}
	if err := v.Unmarshal(&file); err != nil {
		t.Fatalf("反序列化内置规则失败: %v", err)
	}
	rules := make([]model.DetectionRule, 0, len(file.Rules))
	for i, r := range file.Rules {
		rules = append(rules, model.DetectionRule{
			ID:         uint(i + 1),
			Name:       r.Name,
			Expression: r.Expression,
			Severity:   r.Severity,
			Category:   r.Category,
			MitreID:    r.MitreID,
			DataTypes:  model.StringArray(r.DataTypes),
			Enabled:    true,
			Builtin:    true,
			// 跟随 YAML 而不是一律 high：写死 high 会让标成 indicator 的规则
			// 在回放里被当成告警规则，量出来的误报率与线上对不上。
			Fidelity: fidelityOrHigh(r.Fidelity),
			Stage:    model.RuleStageAlert,
		})
	}
	return rules
}

// fidelityOrHigh 与导入逻辑保持一致：未写保真度按 high。
func fidelityOrHigh(v string) string {
	if v == model.RuleFidelityLow {
		return model.RuleFidelityLow
	}
	return model.RuleFidelityHigh
}

// engineMatcher 把 celengine 适配成 replay.Matcher。
type engineMatcher struct{ e *celengine.Engine }

// MatchIDs 只返回会独立产生告警的规则。
//
// 低保真(indicator)与未到 alert 阶段的规则命中后不会告警，只作为关联信号。
// 把它们算成误报是在量错东西：这里要回答的是"正常流量会不会把人叫醒"，
// 而不是"有没有任何表达式为真"。反过来，若把 indicator 命中也算作检出，
// 召回率同样会虚高——两边都得用同一把尺子，也就是 Generate 实际的告警条件。
func (m engineMatcher) MatchIDs(dataType int32, fields map[string]string) []string {
	matched := m.e.Evaluate(dataType, fields)
	ids := make([]string, 0, len(matched))
	for i := range matched {
		if matched[i].IsLowFidelity() || !matched[i].AlertsIndependently() {
			continue
		}
		ids = append(ids, matched[i].Name)
	}
	return ids
}

func newMatcher(t *testing.T) replay.Matcher {
	t.Helper()
	e, err := celengine.NewInMemory(zap.NewNop(), loadBuiltinRules(t))
	if err != nil {
		t.Fatalf("构造引擎失败: %v", err)
	}
	return engineMatcher{e: e}
}

// 语料本身必须先是可用的：标注混乱的语料会给出一个看起来很高的分数，
// 然后所有人都会拿它当依据。
func TestCorpusIsValid(t *testing.T) {
	c, err := replay.Load(corpusDir)
	if err != nil {
		t.Fatalf("加载语料失败: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("语料不可用: %v", err)
	}
}

// 回放语料，记录当前召回率与误报率。
//
// 这个测试不断言一个具体的召回门槛：现在钉死一个数字，只会逼着后来的人
// 去改数字而不是改规则。它要做的是把真实水平打印出来，让缺口可见。
// 真正会挡住合并的是下面两个断言：正常语料零误命中，以及不能有整类技术零检出。
func TestReplayBuiltinRules(t *testing.T) {
	c, err := replay.Load(corpusDir)
	if err != nil {
		t.Fatalf("加载语料失败: %v", err)
	}
	rep, err := replay.Run(c, newMatcher(t))
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}

	t.Log(rep.Summary())
	for _, m := range rep.Missed {
		t.Logf("漏报: %s (%s) — %s", m.Sample.Name, m.Sample.Technique, m.Sample.Note)
	}
	for _, fp := range rep.FalsePositives {
		t.Logf("误报: %s 命中 %v — %s", fp.Sample.Name, fp.Matched, fp.Sample.Note)
	}
	for tech, ts := range rep.ByTechnique {
		t.Logf("技术 %s: 召回 %.0f%% (%d/%d)", tech, ts.Recall*100, ts.Caught, ts.Total)
	}
}

// 正常语料一条都不该被命中。
//
// 这些样本是刻意挑的「长得像攻击的日常运维」：配置管理派生 shell、
// 包管理器投放 systemd 单元、日志轮转批量删日志。规则若靠关键字粗暴匹配，
// 就会在这里翻车——而在生产上翻车的代价是值班从此不再看告警。
func TestBenignCorpusProducesNoAlerts(t *testing.T) {
	c, err := replay.Load(corpusDir)
	if err != nil {
		t.Fatalf("加载语料失败: %v", err)
	}
	rep, err := replay.Run(c, newMatcher(t))
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	if rep.BenignFlagged > 0 {
		for _, fp := range rep.FalsePositives {
			t.Errorf("正常样本被误命中: %s\n  命中规则: %v\n  为什么它是正常的: %s",
				fp.Sample.Name, fp.Matched, fp.Sample.Note)
		}
		t.Fatalf("正常语料误命中 %d/%d", rep.BenignFlagged, rep.BenignTotal)
	}
}

// 不允许出现整类技术零检出。
//
// 总召回率会掩盖结构性缺口：某个技术一条都没检出，在总分里可能只掉几个点，
// 但它意味着这类攻击可以完全无声地通过——那不是「差一点」，是根本没覆盖。
func TestNoTechniqueIsCompletelyUndetected(t *testing.T) {
	c, err := replay.Load(corpusDir)
	if err != nil {
		t.Fatalf("加载语料失败: %v", err)
	}
	rep, err := replay.Run(c, newMatcher(t))
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	if zero := rep.ZeroRecallTechniques(); len(zero) > 0 {
		for _, tech := range zero {
			for _, m := range rep.Missed {
				if m.Sample.Technique == tech {
					t.Errorf("技术 %s 完全未检出，样本: %s — %s", tech, m.Sample.Name, m.Sample.Note)
				}
			}
		}
		t.Fatalf("以下技术一条都没检出: %v", zero)
	}
}

// requiredTechniquesFile 是「必须被语料覆盖」的技术清单。
const requiredTechniquesFile = "testdata/required_techniques.json"

// loadRequiredTechniques 读清单里的技术 ID。
func loadRequiredTechniques(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(requiredTechniquesFile)
	if err != nil {
		t.Fatalf("读取技术清单失败: %v", err)
	}
	var doc struct {
		Techniques []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("解析技术清单失败: %v", err)
	}
	if len(doc.Techniques) == 0 {
		t.Fatal("技术清单为空：清空它等于删掉这道门禁")
	}
	ids := make([]string, 0, len(doc.Techniques))
	for _, tech := range doc.Techniques {
		if tech.ID == "" {
			t.Fatalf("技术清单里有条目缺 id: %+v", tech)
		}
		ids = append(ids, tech.ID)
	}
	return ids
}

// 清单里的技术必须仍被语料覆盖。
//
// UncoveredTechniques 此前已实现却没有输入，等于没接。缺了输入，
// 「某个技术已经没有样本在测了」这件事不会有任何人发现——
// 总召回率反而会因为少测一类而变好看。
//
// 这道门禁挡的是倒退：删语料、改标注、或规则改到某类技术不再被覆盖，都会红。
// 它不给覆盖率定目标，还没覆盖的技术记在 roadmap，不放进清单。
func TestRequiredTechniquesRemainCovered(t *testing.T) {
	c, err := replay.Load(corpusDir)
	if err != nil {
		t.Fatalf("加载语料失败: %v", err)
	}
	rep, err := replay.Run(c, newMatcher(t))
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}

	want := loadRequiredTechniques(t)
	if missing := rep.UncoveredTechniques(want); len(missing) > 0 {
		t.Fatalf("以下技术已无语料覆盖: %v\n"+
			"  它们的召回率现在是「未知」，不是 100%%。\n"+
			"  要么补回样本，要么把这几行从 %s 删掉并在 docs/roadmap.md §5.1 记下缺口——\n"+
			"  但不要让清单和语料悄悄脱节。", missing, requiredTechniquesFile)
	}
}

// 清单不许写没覆盖的技术：那样门禁会长期红着，然后被所有人忽略。
func TestRequiredTechniquesListHasNoAspirationalEntries(t *testing.T) {
	c, err := replay.Load(corpusDir)
	if err != nil {
		t.Fatalf("加载语料失败: %v", err)
	}
	rep, err := replay.Run(c, newMatcher(t))
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}

	for _, tech := range loadRequiredTechniques(t) {
		ts, ok := rep.ByTechnique[tech]
		if !ok {
			continue // 由上面那个用例负责报
		}
		if ts.Caught == 0 {
			t.Errorf("清单里的 %s 有样本但一条都没检出——清单是覆盖现状，不是愿望清单", tech)
		}
	}
}
