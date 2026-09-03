package api

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestRoleExists 验证 P1: 建/改用户时角色校验放开到「内置 admin/user + 任意已在
// role_permissions 中定义的自定义角色」，而非写死 admin/user。
func TestRoleExists(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.RolePermission{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 定义一个自定义角色 auditor（任意一条权限即代表该角色存在）
	if err := db.Create(&model.RolePermission{RoleCode: "auditor", PermCode: "dashboard"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := NewUsersHandler(db, zap.NewNop())
	cases := map[string]bool{
		"admin":    true,  // 内置
		"user":     true,  // 内置
		"auditor":  true,  // 自定义，已在 role_permissions
		"nonexist": false, // 未定义
		"":         false,
	}
	for role, want := range cases {
		if got := h.roleExists(role); got != want {
			t.Errorf("roleExists(%q) = %v, want %v", role, got, want)
		}
	}
}
