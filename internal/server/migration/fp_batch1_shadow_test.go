package migration

import (
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 点名日常进程的规则退回影子阶段，只做一次；用户改过的不动。
func TestShadowFPBatch1Rules(t *testing.T) {
	db := setupRuleDB(t)
	createSystemConfigs(t, db)
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	// 模拟老库：这几条规则当初以告警阶段入库。
	if err := db.Model(&model.DetectionRule{}).Where("name IN ?", fpBatch1ShadowRules).Update("stage", model.RuleStageAlert).Error; err != nil {
		t.Fatal(err)
	}
	const touched = "信息收集 - 进程枚举"
	db.Model(&model.DetectionRule{}).Where("name = ?", touched).Update("user_modified", true)

	if err := shadowFPBatch1Rules(db, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	for _, name := range fpBatch1ShadowRules {
		var r model.DetectionRule
		if err := db.Where("name = ?", name).First(&r).Error; err != nil {
			t.Fatalf("内置规则里找不到 %q：改了规则名要同步 fpBatch1ShadowRules（%v）", name, err)
		}
		want := model.RuleStageShadow
		if name == touched {
			want = model.RuleStageAlert
		}
		if r.Stage != want {
			t.Errorf("%s 应为 %s，实际 %s", name, want, r.Stage)
		}
	}

	// 只做一次：人工晋级回告警阶段后，再跑不会被按回去。
	db.Model(&model.DetectionRule{}).Where("name = ?", fpBatch1ShadowRules[0]).Update("stage", model.RuleStageAlert)
	if err := shadowFPBatch1Rules(db, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	var r model.DetectionRule
	db.Where("name = ?", fpBatch1ShadowRules[0]).First(&r)
	if r.Stage != model.RuleStageAlert {
		t.Fatalf("第二次执行不应改动人工晋级的规则，实际 %s", r.Stage)
	}
}
