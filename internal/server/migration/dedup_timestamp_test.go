package migration

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestMigrateDedupTimestampRules 校验 M1：三条重复 T1070.006 touch 时间戳规则去重
// —— 保留"防御规避 - 时间戳伪造"并补全 -d/--date，禁用另两条；user_modified 不动。
func TestMigrateDedupTimestampRules(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.DetectionRule{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	seed := []model.DetectionRule{
		{Name: "防御规避 - 时间戳伪造", Category: "defense_evasion", Severity: "medium", Expression: "old", Enabled: true},
		{Name: "防御绕过 - timestamp tamper", Category: "defense_evasion", Severity: "medium", Enabled: true},
		{Name: "防御逃避 - timestomp 篡改文件时间", Category: "defense_evasion", Severity: "medium", Enabled: true},
	}
	if err := db.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := migrateDedupTimestampRules(db, zap.NewNop()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	get := func(name string) model.DetectionRule {
		var r model.DetectionRule
		if err := db.Where("name = ?", name).First(&r).Error; err != nil {
			t.Fatalf("load %q: %v", name, err)
		}
		return r
	}
	// 两条冗余被禁用。
	for _, n := range []string{"防御绕过 - timestamp tamper", "防御逃避 - timestomp 篡改文件时间"} {
		if get(n).Enabled {
			t.Errorf("冗余规则 %q 应被禁用", n)
		}
	}
	// 保留规则仍启用且表达式补全 -d/--date。
	kept := get("防御规避 - 时间戳伪造")
	if !kept.Enabled {
		t.Error("保留规则应仍启用")
	}
	if !strings.Contains(kept.Expression, "--date") || !strings.Contains(kept.Expression, `"-d"`) {
		t.Errorf("保留规则表达式未补全 -d/--date: %s", kept.Expression)
	}

	// 幂等。
	if err := migrateDedupTimestampRules(db, zap.NewNop()); err != nil {
		t.Fatalf("migrate 二次: %v", err)
	}
}
