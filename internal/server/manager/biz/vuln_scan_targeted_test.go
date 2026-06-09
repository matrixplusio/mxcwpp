package biz

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// setupTargetedScanDB 建 sqlite 内存库（包含 vuln_scan_tasks/hosts/host_vulnerabilities/vulnerabilities/software）
func setupTargetedScanDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	tables := []string{
		`CREATE TABLE hosts (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			host_id                   TEXT PRIMARY KEY,
			hostname                  TEXT,
			os_family                 TEXT,
			os_version                TEXT,
			kernel_version            TEXT,
			arch                      TEXT,
			ipv4                      TEXT DEFAULT '[]',
			ipv6                      TEXT DEFAULT '[]',
			public_ipv4               TEXT DEFAULT '[]',
			public_ipv6               TEXT DEFAULT '[]',
			status                    TEXT DEFAULT 'offline',
			last_heartbeat            DATETIME,
			device_model              TEXT,
			manufacturer              TEXT,
			device_serial             TEXT,
			device_id                 TEXT,
			cpu_info                  TEXT,
			memory_size               TEXT,
			system_load               TEXT,
			default_gateway           TEXT,
			dns_servers               TEXT,
			network_mode              TEXT,
			disk_info                 TEXT,
			network_interfaces        TEXT,
			business_line             TEXT,
			system_boot_time          DATETIME,
			agent_start_time          DATETIME,
			last_active_time          DATETIME,
			runtime_type              TEXT DEFAULT 'vm',
			is_container              INTEGER DEFAULT 0,
			container_id              TEXT,
			pod_name                  TEXT,
			pod_namespace             TEXT,
			pod_uid                   TEXT,
			agent_version             TEXT,
			tags                      TEXT,
			edr_mode                  TEXT,
			edr_capabilities          TEXT,
			edr_hook_type             TEXT,
			edr_events_fwd            INTEGER DEFAULT 0,
			edr_events_drop           INTEGER DEFAULT 0,
			edr_rules_version         TEXT,
			edr_rules_count           INTEGER DEFAULT 0,
			edr_rules_matched         INTEGER DEFAULT 0,
			edr_ioc_version           TEXT,
			edr_ioc_count             INTEGER DEFAULT 0,
			edr_ioc_matched           INTEGER DEFAULT 0,
			kernel_livepatch_enabled  INTEGER DEFAULT 0,
			kernel_livepatch_provider TEXT,
			active_livepatches        TEXT,
			created_at                DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at                DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE vuln_scan_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id           TEXT NOT NULL UNIQUE,
			scope             TEXT NOT NULL,
			target_host_ids   TEXT,
			business_line     TEXT,
			sync_db           INTEGER DEFAULT 0,
			reconcile_stale   INTEGER DEFAULT 1,
			status            TEXT NOT NULL DEFAULT 'pending',
			progress_total    INTEGER DEFAULT 0,
			progress_scanned  INTEGER DEFAULT 0,
			new_vulns         INTEGER DEFAULT 0,
			patched_count     INTEGER DEFAULT 0,
			vanished_count    INTEGER DEFAULT 0,
			resurfaced_count  INTEGER DEFAULT 0,
			error_msg         TEXT,
			triggered_by      TEXT,
			started_at        DATETIME,
			finished_at       DATETIME,
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, ddl := range tables {
		require.NoError(t, db.Exec(ddl).Error, "DDL failed: %s", ddl)
	}
	return db
}

func TestCreateScanTask_PendingState(t *testing.T) {
	db := setupTargetedScanDB(t)
	logger := zap.NewNop()
	mgr := NewScanTaskManager(db, logger)

	task, err := mgr.Create(CreateTaskOpts{
		Scope:       model.ScanScopeHosts,
		HostIDs:     []string{"host-1", "host-2"},
		TriggeredBy: "admin",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, task.TaskID)
	assert.Equal(t, model.ScanTaskStatusPending, task.Status)
	assert.Equal(t, 2, task.ProgressTotal)
}

func TestCreateScanTask_HostIDsExceedsLimit_Rejected(t *testing.T) {
	db := setupTargetedScanDB(t)
	logger := zap.NewNop()
	mgr := NewScanTaskManager(db, logger)

	hostIDs := make([]string, 201)
	for i := range hostIDs {
		hostIDs[i] = "host-" + string(rune('a'+i%26))
	}

	_, err := mgr.Create(CreateTaskOpts{
		Scope:       model.ScanScopeHosts,
		HostIDs:     hostIDs,
		TriggeredBy: "admin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "上限 200")
}

func TestCreateScanTask_ConcurrentOverlap_Rejected(t *testing.T) {
	db := setupTargetedScanDB(t)
	logger := zap.NewNop()
	mgr := NewScanTaskManager(db, logger)

	existingTargets, _ := json.Marshal([]string{"host-1", "host-2"})
	require.NoError(t, db.Create(&model.VulnScanTask{
		TaskID:        "t-running",
		Scope:         model.ScanScopeHosts,
		Status:        model.ScanTaskStatusRunning,
		TargetHostIDs: datatypes.JSON(existingTargets),
	}).Error)

	// host-2 与已运行任务交集
	_, err := mgr.Create(CreateTaskOpts{
		Scope:       model.ScanScopeHosts,
		HostIDs:     []string{"host-2", "host-3"},
		TriggeredBy: "admin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "交集")
}

func TestCreateScanTask_BusinessLineResolve(t *testing.T) {
	db := setupTargetedScanDB(t)
	logger := zap.NewNop()

	for _, h := range []model.Host{
		{HostID: "host-1", BusinessLine: "G02-UAT"},
		{HostID: "host-2", BusinessLine: "G02-UAT"},
		{HostID: "host-3", BusinessLine: "G01-PROD"},
	} {
		require.NoError(t, db.Create(&h).Error)
	}

	mgr := NewScanTaskManager(db, logger)
	task, err := mgr.Create(CreateTaskOpts{
		Scope:        model.ScanScopeBusinessLine,
		BusinessLine: "G02-UAT",
		TriggeredBy:  "admin",
	})
	require.NoError(t, err)
	assert.Equal(t, "G02-UAT", task.BusinessLine)
	assert.Equal(t, 2, task.ProgressTotal, "应解析出 2 台 G02-UAT 主机")
}
