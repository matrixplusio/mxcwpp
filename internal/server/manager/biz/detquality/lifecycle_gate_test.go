package detquality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// repoRoot 返回仓库根目录。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("未找到仓库根目录")
	return ""
}

// 存量规则的回填目标必须是 alert，不能是任何更低的阶段。
//
// 这是本次改动风险最高的一处：新加的 stage 字段若让存量规则落到 shadow，
// 整个已部署的规则集会在一次升级后集体停止告警——平台看起来一切正常，
// 实际已经不再报警，而且没有任何东西会提示这件事。
// 用测试钉死方向，避免以后有人"顺手"把默认值调低。
func TestBackfillCannotSilenceExistingRules(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal/server/migration/migrate.go"))
	if err != nil {
		t.Fatalf("read migrate.go: %v", err)
	}
	body := string(src)

	idx := strings.Index(body, "func migrateBackfillRuleStage")
	if idx < 0 {
		t.Fatal("找不到 migrateBackfillRuleStage：存量规则回填不能被删掉")
	}
	fn := body[idx:]
	if end := strings.Index(fn, "\nfunc "); end > 0 {
		fn = fn[:end]
	}
	if !strings.Contains(fn, "model.RuleStageAlert") {
		t.Fatal("存量规则必须回填为 alert，否则升级后整个规则集会静默停止告警")
	}
	for _, lower := range []string{"RuleStageShadow", "RuleStageDraft", "RuleStageContext"} {
		if strings.Contains(fn, lower) {
			t.Fatalf("存量规则回填不得使用 %s：会让已部署的检测能力在升级后归零", lower)
		}
	}
}

// 模型的默认阶段同样必须是 alert。
//
// 迁移只处理存量行，列默认值决定的是迁移之后新写入的行；两处方向必须一致，
// 否则会出现"迁移修好了、新建的又是哑的"这种只在一段时间后才暴露的偏差。
func TestColumnDefaultIsAlert(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal/server/model/detection_rule.go"))
	if err != nil {
		t.Fatalf("read detection_rule.go: %v", err)
	}
	body := string(src)
	line := ""
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, "column:stage") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("找不到 stage 列定义")
	}
	if !strings.Contains(line, "default:'alert'") {
		t.Fatalf("stage 列默认值必须是 alert，实际: %s", strings.TrimSpace(line))
	}
}

// 晋级只能逐级进行，不能跳级。
//
// 跳级等于绕过中间阶段的证据要求：从 shadow 直接到 alert，就没有任何一步
// 检验过它的精确率。
func TestPromotionCannotSkipStages(t *testing.T) {
	cases := map[string]string{
		model.RuleStageDraft:   model.RuleStageShadow,
		model.RuleStageShadow:  model.RuleStageContext,
		model.RuleStageContext: model.RuleStageAlert,
		model.RuleStageAlert:   "",
	}
	for from, want := range cases {
		if got := model.NextRuleStage(from); got != want {
			t.Fatalf("%s 的下一阶段应为 %q，实际 %q", from, want, got)
		}
	}
}

// 达到 alert 的唯一路径必须经过 context——即必须有过人工研判结论。
//
// 逐级走一遍，确认没有任何一条捷径能让未经研判的规则开始打扰值班。
func TestReachingAlertRequiresPassingThroughContext(t *testing.T) {
	stage := model.RuleStageDraft
	path := []string{stage}
	for stage != model.RuleStageAlert {
		next := model.NextRuleStage(stage)
		if next == "" {
			t.Fatalf("从 %s 无法到达 alert", stage)
		}
		stage = next
		path = append(path, stage)
	}
	joined := strings.Join(path, "→")
	if joined != "draft→shadow→context→alert" {
		t.Fatalf("到达 alert 的路径不符合预期: %s", joined)
	}
}
