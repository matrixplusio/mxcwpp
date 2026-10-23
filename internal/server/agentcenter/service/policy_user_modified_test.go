package service

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// 只标记内置策略；用户自建策略本来就不参与启动同步。
func TestMarkUserModified(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE policies (id TEXT PRIMARY KEY, builtin INTEGER DEFAULT 0, user_modified INTEGER DEFAULT 0, updated_at DATETIME)`)
	db.Exec(`INSERT INTO policies (id, builtin) VALUES ('B', 1), ('U', 0)`)

	s := NewPolicyService(db, zap.NewNop())
	for _, id := range []string{"B", "U"} {
		if err := s.MarkUserModified(id); err != nil {
			t.Fatalf("MarkUserModified(%s): %v", id, err)
		}
	}
	var b, u int
	db.Raw(`SELECT user_modified FROM policies WHERE id = 'B'`).Scan(&b)
	db.Raw(`SELECT user_modified FROM policies WHERE id = 'U'`).Scan(&u)
	if b != 1 || u != 0 {
		t.Fatalf("builtin=%d custom=%d, want 1/0", b, u)
	}
}
