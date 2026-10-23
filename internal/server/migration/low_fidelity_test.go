package migration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	builtinrules "github.com/matrixplusio/mxcwpp/configs/rules"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupRuleDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.DetectionRule{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

// 内置规则的保真度与规则文件一致：同步之后逐条核对。
func TestBuiltinFidelityFollowsRulesFile(t *testing.T) {
	db := setupRuleDB(t)
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	// 模拟库里的规则被别处改过保真度：再次同步要改回规则文件写的值。
	db.Model(&model.DetectionRule{}).Where("builtin = ?", true).Update("fidelity", model.RuleFidelityLow)
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(string(builtinrules.BuiltinRulesYAML))); err != nil {
		t.Fatal(err)
	}
	var file builtinRuleYAML
	if err := v.Unmarshal(&file); err != nil {
		t.Fatal(err)
	}
	for _, r := range file.Rules {
		var got model.DetectionRule
		if err := db.Where("name = ?", r.Name).First(&got).Error; err != nil {
			t.Fatalf("找不到规则 %q: %v", r.Name, err)
		}
		if want := ruleFidelity(r.Fidelity); got.Fidelity != want {
			t.Errorf("%s 的保真度应为规则文件里的 %s，得 %s", r.Name, want, got.Fidelity)
		}
	}
}

// 全仓库只有内置规则同步可以改已有规则的保真度。别处一改，各服务启动时就会和同步打架，
// 规则在「告警」与「静默」之间随重启顺序来回翻。新建规则时在结构体里写 Fidelity 不算「改」，不在此列。
func TestOnlyBuiltinSyncWritesFidelity(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join("internal", "server", "migration", "init_data.go")
	bad := []string{`Update("fidelity"`, `UpdateColumn("fidelity"`, `"fidelity":`, `Select("fidelity"`}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if rel == allowed {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, b := range bad {
				if strings.Contains(string(src), b) {
					t.Errorf("%s 里出现了 %s：已有规则的保真度只能由内置规则同步改", rel, b)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
