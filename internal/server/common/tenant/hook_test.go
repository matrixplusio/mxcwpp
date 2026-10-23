package tenant

import (
	"context"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type hookHost struct {
	HostID   string `gorm:"primaryKey"`
	TenantID string
	Name     string
}

func (hookHost) TableName() string { return "hook_hosts" }

type hookGlobal struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

func (hookGlobal) TableName() string { return "hook_globals" }

func newHookTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&hookHost{}, &hookGlobal{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := RegisterAutoInjectHook(db); err != nil {
		t.Fatalf("register hook: %v", err)
	}
	return db
}

func TestAutoInjectHook_FillsEmptyTenantID(t *testing.T) {
	t.Parallel()
	db := newHookTestDB(t)

	ctx := WithContext(context.Background(), Identity{ID: "t-bank-a"})
	host := hookHost{HostID: "h-1", Name: "Alpha"}
	if err := db.WithContext(ctx).Create(&host).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var got hookHost
	if err := db.First(&got, "host_id = ?", "h-1").Error; err != nil {
		t.Fatalf("first: %v", err)
	}
	if got.TenantID != "t-bank-a" {
		t.Fatalf("expected tenant_id=t-bank-a, got %q", got.TenantID)
	}
}

func TestAutoInjectHook_DoesNotOverrideExplicit(t *testing.T) {
	t.Parallel()
	db := newHookTestDB(t)

	ctx := WithContext(context.Background(), Identity{ID: "t-from-ctx"})
	host := hookHost{HostID: "h-2", TenantID: "t-explicit", Name: "Beta"}
	if err := db.WithContext(ctx).Create(&host).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var got hookHost
	if err := db.First(&got, "host_id = ?", "h-2").Error; err != nil {
		t.Fatalf("first: %v", err)
	}
	if got.TenantID != "t-explicit" {
		t.Fatalf("explicit TenantID was overridden! got %q", got.TenantID)
	}
}

func TestAutoInjectHook_BatchInsert(t *testing.T) {
	t.Parallel()
	db := newHookTestDB(t)

	ctx := WithContext(context.Background(), Identity{ID: "t-batch"})
	hosts := []hookHost{
		{HostID: "h-b1", Name: "B1"},
		{HostID: "h-b2", Name: "B2"},
		{HostID: "h-b3", TenantID: "t-other", Name: "B3"},
	}
	if err := db.WithContext(ctx).Create(&hosts).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var got []hookHost
	if err := db.Order("host_id ASC").Find(&got).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if got[0].TenantID != "t-batch" || got[1].TenantID != "t-batch" || got[2].TenantID != "t-other" {
		t.Fatalf("unexpected tenant_ids: %v %v %v",
			got[0].TenantID, got[1].TenantID, got[2].TenantID)
	}
}

func TestAutoInjectHook_NoIdentityNoMutation(t *testing.T) {
	t.Parallel()
	db := newHookTestDB(t)

	host := hookHost{HostID: "h-anon", Name: "Anon"}
	if err := db.Create(&host).Error; err != nil { // 不带 ctx Identity
		t.Fatalf("create: %v", err)
	}

	var got hookHost
	if err := db.First(&got, "host_id = ?", "h-anon").Error; err != nil {
		t.Fatalf("first: %v", err)
	}
	if got.TenantID != "" {
		t.Fatalf("expected empty (no auto inject), got %q", got.TenantID)
	}
}

func TestAutoInjectHook_SkipsGlobalModels(t *testing.T) {
	t.Parallel()
	db := newHookTestDB(t)

	ctx := WithContext(context.Background(), Identity{ID: "t-x"})
	g := hookGlobal{Name: "Permission"}
	if err := db.WithContext(ctx).Create(&g).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	if g.ID == 0 {
		t.Fatalf("global model insert failed")
	}
}
