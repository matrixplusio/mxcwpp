package migration

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 这次才开始工作的规则退回影子阶段，且只做一次：之后人工晋级的不能再被按回去。
func TestShadowReactivatedRules(t *testing.T) {
	db := setupRuleDB(t)
	createSystemConfigs(t, db)
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatalf("init builtin rules: %v", err)
	}
	// 一条被用户改过的不该动。
	const userTouched = "持久化 - crontab 新增"
	if err := db.Model(&model.DetectionRule{}).Where("name = ?", userTouched).Update("user_modified", true).Error; err != nil {
		t.Fatalf("mark user modified: %v", err)
	}

	stage := func(name string) string {
		var r model.DetectionRule
		if err := db.Where("name = ?", name).First(&r).Error; err != nil {
			t.Fatalf("内置规则里找不到 %q：改了规则名要同步 reactivatedRules（%v）", name, err)
		}
		return r.Stage
	}

	if err := shadowReactivatedRules(db, zap.NewNop()); err != nil {
		t.Fatalf("shadow: %v", err)
	}
	for _, name := range reactivatedRules {
		want := model.RuleStageShadow
		if name == userTouched {
			want = model.RuleStageAlert
		}
		if got := stage(name); got != want {
			t.Errorf("%q 阶段 = %q，期望 %q", name, got, want)
		}
	}
	if got := stage("动态链接劫持 - ld.so.preload"); got != model.RuleStageAlert {
		t.Errorf("不在名单里的规则被改成了 %q", got)
	}

	// 人工晋级之后再次启动，不能被按回影子。
	const promoted = "持久化 - /etc/passwd 直接写"
	if err := db.Model(&model.DetectionRule{}).Where("name = ?", promoted).Update("stage", model.RuleStageAlert).Error; err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := shadowReactivatedRules(db, zap.NewNop()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := stage(promoted); got != model.RuleStageAlert {
		t.Fatalf("再次启动把已晋级的规则按回了 %q", got)
	}
}

// 规则文件里写了 stage 的新规则，入库时就在那个阶段；已有规则的阶段不随版本更新改变。
func TestBuiltinRuleInitialStage(t *testing.T) {
	db := setupRuleDB(t)
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatalf("init builtin rules: %v", err)
	}
	var r model.DetectionRule
	if err := db.Where("name = ?", "认证 - root 密码登录").First(&r).Error; err != nil {
		t.Fatalf("load rule: %v", err)
	}
	if r.Stage != model.RuleStageShadow {
		t.Fatalf("写了 stage: shadow 的新规则应以影子阶段入库，得 %q", r.Stage)
	}
	// 人工晋级后再次同步，不能被改回影子。
	if err := db.Model(&r).Update("stage", model.RuleStageAlert).Error; err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if err := db.Where("name = ?", "认证 - root 密码登录").First(&r).Error; err != nil || r.Stage != model.RuleStageAlert {
		t.Fatalf("再次同步把已晋级的规则改回了 %q", r.Stage)
	}
	// 没写 stage 的照旧是 alert。
	var plain model.DetectionRule
	if err := db.Where("name = ?", "动态链接劫持 - ld.so.preload").First(&plain).Error; err != nil || plain.Stage != model.RuleStageAlert {
		t.Fatalf("未写 stage 的规则应为 alert，得 %q", plain.Stage)
	}
}

// createSystemConfigs 手工建 system_configs：它的 updated_at 带 MySQL 专有的 ON UPDATE，sqlite 不能 AutoMigrate。
func createSystemConfigs(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec("CREATE TABLE system_configs (tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"`key` TEXT NOT NULL, value TEXT, category TEXT NOT NULL DEFAULT 'general', description TEXT, " +
		"created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(`key`, category))").Error; err != nil {
		t.Fatalf("create system_configs: %v", err)
	}
}
