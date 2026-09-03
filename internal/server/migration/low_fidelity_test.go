package migration

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

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

func fidelityOf(t *testing.T, db *gorm.DB, name string) string {
	t.Helper()
	var r model.DetectionRule
	if err := db.Where("name = ?", name).First(&r).Error; err != nil {
		t.Fatalf("load rule %q: %v", name, err)
	}
	return r.Fidelity
}

// TestMigrateMarkLowFidelityRules 校验降噪治理(1a)：
//   - 噪声类目(network_scan/discovery)整类降级为 low
//   - 名模式命中的跨类目噪声规则降级为 low
//   - 高保真类目(reverse_shell 等)保持 high
//   - user_modified=true 的规则不被覆盖
//   - 幂等：重复运行结果不变
func TestMigrateMarkLowFidelityRules(t *testing.T) {
	db := setupRuleDB(t)
	logger := zap.NewNop()

	seed := []model.DetectionRule{
		{Name: "数据库端口入站访问", Category: "network_scan", Severity: "high", Fidelity: model.RuleFidelityHigh},
		{Name: "SSH 暴力尝试 - 入站连接", Category: "network_scan", Severity: "high", Fidelity: model.RuleFidelityHigh},
		{Name: "信息收集 - 网络枚举", Category: "discovery", Severity: "low", Fidelity: model.RuleFidelityHigh},
		{Name: "发现 - 云元数据接口访问", Category: "discovery", Severity: "medium", Fidelity: model.RuleFidelityHigh},
		{Name: "/tmp 目录可执行文件创建", Category: "execution", Severity: "medium", Fidelity: model.RuleFidelityHigh},
		{Name: "反弹 Shell - nc/ncat", Category: "reverse_shell", Severity: "critical", Fidelity: model.RuleFidelityHigh},
		{Name: "执行 - memfd_create 文件落地", Category: "defense_evasion", Severity: "critical", Fidelity: model.RuleFidelityHigh},
		{Name: "信息收集 - 用户枚举(用户已调)", Category: "discovery", Severity: "low", Fidelity: model.RuleFidelityHigh, UserModified: true},
	}
	if err := db.Create(&seed).Error; err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	run := func() {
		if err := migrateMarkLowFidelityRules(db, logger); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	run()

	// 噪声类目整类降级
	for _, n := range []string{"数据库端口入站访问", "SSH 暴力尝试 - 入站连接", "信息收集 - 网络枚举", "发现 - 云元数据接口访问"} {
		if got := fidelityOf(t, db, n); got != model.RuleFidelityLow {
			t.Errorf("噪声类目规则 %q fidelity = %q, 期望 low", n, got)
		}
	}
	// 名模式跨类目噪声降级
	if got := fidelityOf(t, db, "/tmp 目录可执行文件创建"); got != model.RuleFidelityLow {
		t.Errorf("名模式噪声规则 fidelity = %q, 期望 low", got)
	}
	// 高保真规则保持 high
	for _, n := range []string{"反弹 Shell - nc/ncat", "执行 - memfd_create 文件落地"} {
		if got := fidelityOf(t, db, n); got != model.RuleFidelityHigh {
			t.Errorf("高保真规则 %q fidelity = %q, 期望 high", n, got)
		}
	}
	// user_modified 不被覆盖
	if got := fidelityOf(t, db, "信息收集 - 用户枚举(用户已调)"); got != model.RuleFidelityHigh {
		t.Errorf("user_modified 规则被覆盖为 %q, 期望保持 high", got)
	}

	// 幂等：再跑一次结果不变
	run()
	if got := fidelityOf(t, db, "数据库端口入站访问"); got != model.RuleFidelityLow {
		t.Errorf("幂等后 fidelity = %q, 期望 low", got)
	}
}
