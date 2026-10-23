package migration

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/plugins/baseline/engine"
)

func builtinPolicyFile() *engine.Policy {
	return &engine.Policy{
		ID: "P1", Name: "内置名", Version: "2.0.0",
		OSFamily: []string{"rocky", "oracle"}, OSVersion: ">=7", Enabled: true,
		Rules: []*engine.Rule{{
			RuleID: "P1_001", Title: "内置规则", Severity: "high",
			Check: &engine.Check{Condition: "all"}, Fix: &engine.Fix{},
		}},
	}
}

// 用户在控制台改过的内置策略，重启同步不能把它改回去。
func TestSavePolicyToDBSkipsUserModified(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DisableForeignKeyConstraintWhenMigrating: true})
	if err != nil {
		t.Fatal(err)
	}
	// sqlite 不认 MySQL 的 ON UPDATE，手工建表
	for _, ddl := range []string{
		`CREATE TABLE policies (tenant_id TEXT NOT NULL DEFAULT 't-default', id TEXT PRIMARY KEY, name TEXT NOT NULL,
			version TEXT DEFAULT '', description TEXT DEFAULT '', os_family TEXT DEFAULT '[]', os_version TEXT DEFAULT '',
			os_requirements TEXT DEFAULT '[]', target_type TEXT DEFAULT 'all', runtime_types TEXT DEFAULT '[]',
			enabled INTEGER DEFAULT 1, builtin INTEGER DEFAULT 0, group_id TEXT DEFAULT '', user_modified INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE rules (tenant_id TEXT NOT NULL DEFAULT 't-default', rule_id TEXT PRIMARY KEY, policy_id TEXT NOT NULL,
			category TEXT DEFAULT '', title TEXT DEFAULT '', description TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
			enabled INTEGER DEFAULT 1, builtin INTEGER DEFAULT 0, target_type TEXT DEFAULT 'all', runtime_types TEXT DEFAULT '[]',
			check_config TEXT DEFAULT '{}', fix_config TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	logger := zap.NewNop()

	if _, err := savePolicyToDB(db, builtinPolicyFile(), "g", logger); err != nil {
		t.Fatal(err)
	}

	// 未自定义：同步照常覆盖
	db.Model(&model.Policy{}).Where("id = ?", "P1").Update("name", "改过")
	if _, err := savePolicyToDB(db, builtinPolicyFile(), "g", logger); err != nil {
		t.Fatal(err)
	}
	var p model.Policy
	db.First(&p, "id = ?", "P1")
	if p.Name != "内置名" {
		t.Fatalf("未自定义的策略应被同步覆盖, got %q", p.Name)
	}

	// 已自定义：元数据与规则都保留
	db.Model(&model.Policy{}).Where("id = ?", "P1").Updates(map[string]any{
		"name": "用户名", "os_family": model.StringArray{"rocky", "oracle", "ol"}, "user_modified": true,
	})
	db.Model(&model.Rule{}).Where("rule_id = ?", "P1_001").Update("title", "用户规则")
	if _, err := savePolicyToDB(db, builtinPolicyFile(), "g", logger); err != nil {
		t.Fatal(err)
	}
	db.First(&p, "id = ?", "P1")
	if p.Name != "用户名" || len(p.OSFamily) != 3 {
		t.Fatalf("已自定义的策略被覆盖: name=%q os_family=%v", p.Name, p.OSFamily)
	}
	var r model.Rule
	db.First(&r, "rule_id = ?", "P1_001")
	if r.Title != "用户规则" {
		t.Fatalf("已自定义策略的规则被覆盖: %q", r.Title)
	}
}
