package service

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func pruneTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec(`CREATE TABLE processes (
		tenant_id TEXT DEFAULT 't-default', id TEXT PRIMARY KEY, host_id TEXT,
		pid TEXT, ppid TEXT, cmdline TEXT, exe TEXT, exe_hash TEXT,
		container_id TEXT, uid INTEGER, gid INTEGER, username TEXT,
		groupname TEXT, collected_at TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func seedProcesses(t *testing.T, db *gorm.DB, hostID string, n int, prefix string) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-%s-%d", hostID, prefix, i)
		if err := db.Create(&model.Process{ID: id, HostID: hostID, PID: fmt.Sprint(i)}).Error; err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func countProcesses(t *testing.T, db *gorm.DB, hostID string) int64 {
	t.Helper()
	var n int64
	db.Model(&model.Process{}).Where("host_id = ?", hostID).Count(&n)
	return n
}

// TestPruneStaleAssetsRemovesVanishedRows 快照里没有的行必须删掉。
//
// 不删就是此前的行为：行 ID 是 hash(host, pid)，PID 会回绕，退出的进程
// 永远留在表里。单机会因此堆出上万条，而一台机器不可能有上万个进程——
// 这不只是占空间，是「当前进程」这个答案本身错了。
func TestPruneStaleAssetsRemovesVanishedRows(t *testing.T) {
	db := pruneTestDB(t)
	s := NewAssetService(db, zap.NewNop())

	seedProcesses(t, db, "host-1", 50, "old")
	live := seedProcesses(t, db, "host-1", 30, "live")

	s.pruneStaleAssets("host-1", live, &model.Process{}, "进程")

	if got := countProcesses(t, db, "host-1"); got != 30 {
		t.Fatalf("剩余 %d 行，应当只留本轮快照的 30 行", got)
	}
}

// TestPruneStaleAssetsSpareOtherHosts 只清本主机，别人的资产不许动。
func TestPruneStaleAssetsSpareOtherHosts(t *testing.T) {
	db := pruneTestDB(t)
	s := NewAssetService(db, zap.NewNop())

	seedProcesses(t, db, "host-2", 40, "keep")
	live := seedProcesses(t, db, "host-1", 25, "live")

	s.pruneStaleAssets("host-1", live, &model.Process{}, "进程")

	if got := countProcesses(t, db, "host-2"); got != 40 {
		t.Fatalf("另一台主机剩 %d 行，本不该被触及", got)
	}
}

// TestPruneStaleAssetsSkipsSmallSnapshot 快照过小时不删。
//
// 采集器偶发只报回几条时若照删不误，一次异常上报就会把整台主机的资产清空。
// 宁可留着陈旧行，也不能凭一次可疑的上报销毁库存。
func TestPruneStaleAssetsSkipsSmallSnapshot(t *testing.T) {
	db := pruneTestDB(t)
	s := NewAssetService(db, zap.NewNop())

	seedProcesses(t, db, "host-1", 100, "old")
	live := seedProcesses(t, db, "host-1", 3, "live")

	s.pruneStaleAssets("host-1", live, &model.Process{}, "进程")

	if got := countProcesses(t, db, "host-1"); got != 103 {
		t.Fatalf("剩余 %d 行；快照只有 3 条，属于可疑上报，不应触发删除", got)
	}
}

// TestPruneStaleAssetsEmptySnapshotKeepsAll 空快照绝不清库。
func TestPruneStaleAssetsEmptySnapshotKeepsAll(t *testing.T) {
	db := pruneTestDB(t)
	s := NewAssetService(db, zap.NewNop())

	seedProcesses(t, db, "host-1", 60, "old")
	s.pruneStaleAssets("host-1", nil, &model.Process{}, "进程")

	if got := countProcesses(t, db, "host-1"); got != 60 {
		t.Fatalf("剩余 %d 行；采集失败上报空快照时必须原样保留", got)
	}
}
