package scheduler

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupHeartbeatTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	// 手动建表，避免 MySQL 特有语法（ON UPDATE CURRENT_TIMESTAMP）
	db.Exec(`CREATE TABLE IF NOT EXISTS hosts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		host_id TEXT PRIMARY KEY,
		hostname TEXT,
		ipv4 TEXT,
		status TEXT DEFAULT 'offline',
		last_heartbeat TIMESTAMP,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS alerts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mode TEXT DEFAULT '',
		would_action TEXT DEFAULT '',
		action TEXT DEFAULT '',
		action_result TEXT DEFAULT '',
		attck_tactic TEXT DEFAULT '',
		attck_technique TEXT DEFAULT '',
		result_id TEXT UNIQUE,
		host_id TEXT,
		rule_id TEXT,
		policy_id TEXT,
		source TEXT DEFAULT '',
		severity TEXT,
		category TEXT,
		title TEXT,
		description TEXT,
		actual TEXT,
		expected TEXT,
		fix_suggestion TEXT,
		status TEXT DEFAULT 'active',
		hit_count INTEGER DEFAULT 1,
		first_seen_at TIMESTAMP,
		last_seen_at TIMESTAMP,
		last_notified_at TIMESTAMP,
		notify_count INTEGER DEFAULT 0,
		resolved_at TIMESTAMP,
		resolved_by TEXT,
		resolve_reason TEXT,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	)`)

	return db
}

func newTestLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.InfoLevel)
	return zap.New(core), logs
}

// TestCheckHeartbeatTimeout_NoStaleHosts 没有超时主机时不应产生任何操作
func TestCheckHeartbeatTimeout_NoStaleHosts(t *testing.T) {
	db := setupHeartbeatTestDB(t)
	logger, logs := newTestLogger()

	recentHB := model.LocalTime(time.Now().Add(-1 * time.Minute))
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-fresh", "server-1", model.HostStatusOnline, time.Time(recentHB))

	checkHeartbeatTimeout(db, logger)

	// 不应有 "检测到心跳超时主机" 日志
	for _, entry := range logs.All() {
		if entry.Message == "检测到心跳超时主机" {
			t.Fatal("不应检测到心跳超时主机")
		}
	}

	// 主机状态仍为 online
	var host model.Host
	db.Where("host_id = ?", "host-fresh").First(&host)
	if host.Status != model.HostStatusOnline {
		t.Fatalf("期望主机状态 online, 实际 %s", host.Status)
	}
}

// TestCheckHeartbeatTimeout_StaleHost 心跳超时的主机应被标记为离线并产生告警
func TestCheckHeartbeatTimeout_StaleHost(t *testing.T) {
	db := setupHeartbeatTestDB(t)
	logger, logs := newTestLogger()

	staleHB := model.LocalTime(time.Now().Add(-10 * time.Minute))
	db.Exec("INSERT INTO hosts (host_id, hostname, ipv4, status, last_heartbeat) VALUES (?, ?, ?, ?, ?)",
		"host-stale", "server-2", `["10.0.0.1"]`, model.HostStatusOnline, time.Time(staleHB))

	checkHeartbeatTimeout(db, logger)

	// 验证主机状态变为 offline
	var host model.Host
	db.Where("host_id = ?", "host-stale").First(&host)
	if host.Status != model.HostStatusOffline {
		t.Fatalf("期望主机状态 offline, 实际 %s", host.Status)
	}

	// 验证生成了告警
	var alert model.Alert
	err := db.Where("result_id = ?", "offline-host-stale").First(&alert).Error
	if err != nil {
		t.Fatalf("期望找到离线告警: %v", err)
	}
	if alert.Status != model.AlertStatusActive {
		t.Fatalf("期望告警状态 active, 实际 %s", alert.Status)
	}
	if alert.HostID != "host-stale" {
		t.Fatalf("期望 host_id=host-stale, 实际 %s", alert.HostID)
	}
	if alert.Severity != "high" {
		t.Fatalf("期望级别 high, 实际 %s", alert.Severity)
	}

	// 验证日志
	found := false
	for _, entry := range logs.All() {
		if entry.Message == "检测到心跳超时主机" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("期望看到 '检测到心跳超时主机' 日志")
	}
}

// TestCheckHeartbeatTimeout_OfflineHostIgnored 已离线主机不应被重复处理
func TestCheckHeartbeatTimeout_OfflineHostIgnored(t *testing.T) {
	db := setupHeartbeatTestDB(t)
	logger, _ := newTestLogger()

	staleHB := time.Now().Add(-10 * time.Minute)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-already-offline", "server-3", model.HostStatusOffline, staleHB)

	checkHeartbeatTimeout(db, logger)

	var count int64
	db.Model(&model.Alert{}).Where("host_id = ?", "host-already-offline").Count(&count)
	if count != 0 {
		t.Fatalf("已离线主机不应产生新告警, 但找到 %d 条", count)
	}
}

// TestCheckHeartbeatTimeout_DuplicateAlertPrevention 已有活跃告警时不应重复创建
func TestCheckHeartbeatTimeout_DuplicateAlertPrevention(t *testing.T) {
	db := setupHeartbeatTestDB(t)
	logger, _ := newTestLogger()

	staleHB := time.Now().Add(-10 * time.Minute)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-dup", "server-4", model.HostStatusOnline, staleHB)

	// 第一次检查
	checkHeartbeatTimeout(db, logger)

	// 恢复在线状态但心跳仍超时（模拟下一轮检查）
	db.Exec("UPDATE hosts SET status = ? WHERE host_id = ?", model.HostStatusOnline, "host-dup")

	// 第二次检查
	checkHeartbeatTimeout(db, logger)

	// 应只有 1 条告警记录
	var count int64
	db.Model(&model.Alert{}).Where("result_id = ?", "offline-host-dup").Count(&count)
	if count != 1 {
		t.Fatalf("期望 1 条告警记录, 实际 %d 条", count)
	}
}

// TestCheckHeartbeatTimeout_ReactivateResolvedAlert 已解决的告警应被重新激活
func TestCheckHeartbeatTimeout_ReactivateResolvedAlert(t *testing.T) {
	db := setupHeartbeatTestDB(t)
	logger, _ := newTestLogger()

	staleHB := time.Now().Add(-10 * time.Minute)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-react", "server-5", model.HostStatusOnline, staleHB)

	// 预先创建已解决的告警
	now := time.Now()
	db.Exec(`INSERT INTO alerts (result_id, host_id, rule_id, severity, category, title, status, first_seen_at, last_seen_at, resolved_at, resolved_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"offline-host-react", "host-react", "agent_offline", "high", "agent_offline", "old", model.AlertStatusResolved, now, now, now, "auto")

	checkHeartbeatTimeout(db, logger)

	var alert model.Alert
	db.Where("result_id = ?", "offline-host-react").First(&alert)
	if alert.Status != model.AlertStatusActive {
		t.Fatalf("期望告警重新激活为 active, 实际 %s", alert.Status)
	}
}

// TestCheckHeartbeatTimeout_MixedHosts 混合场景
func TestCheckHeartbeatTimeout_MixedHosts(t *testing.T) {
	db := setupHeartbeatTestDB(t)
	logger, _ := newTestLogger()

	recentHB := time.Now().Add(-1 * time.Minute)
	staleHB := time.Now().Add(-10 * time.Minute)

	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-ok-1", "ok-1", model.HostStatusOnline, recentHB)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-ok-2", "ok-2", model.HostStatusOnline, recentHB)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-stale-1", "stale-1", model.HostStatusOnline, staleHB)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-stale-2", "stale-2", model.HostStatusOnline, staleHB)
	db.Exec("INSERT INTO hosts (host_id, hostname, status, last_heartbeat) VALUES (?, ?, ?, ?)",
		"host-offline", "off-1", model.HostStatusOffline, staleHB)

	checkHeartbeatTimeout(db, logger)

	// 正常主机仍在线
	for _, id := range []string{"host-ok-1", "host-ok-2"} {
		var h model.Host
		db.Where("host_id = ?", id).First(&h)
		if h.Status != model.HostStatusOnline {
			t.Fatalf("主机 %s 应保持 online, 实际 %s", id, h.Status)
		}
	}

	// 超时主机已离线
	for _, id := range []string{"host-stale-1", "host-stale-2"} {
		var h model.Host
		db.Where("host_id = ?", id).First(&h)
		if h.Status != model.HostStatusOffline {
			t.Fatalf("主机 %s 应变为 offline, 实际 %s", id, h.Status)
		}
	}

	// 只有 2 条告警
	var alertCount int64
	db.Model(&model.Alert{}).Count(&alertCount)
	if alertCount != 2 {
		t.Fatalf("期望 2 条告警, 实际 %d 条", alertCount)
	}
}
