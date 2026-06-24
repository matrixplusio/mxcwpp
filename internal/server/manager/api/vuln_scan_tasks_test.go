package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupVulnScanAPITestDB(t *testing.T) *gorm.DB {
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
		`CREATE TABLE security_db_sync_records (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			db_type     TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'pending',
			version     TEXT,
			error_msg   TEXT,
			duration    INTEGER DEFAULT 0,
			started_at  DATETIME,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, ddl := range tables {
		require.NoError(t, db.Exec(ddl).Error, "DDL failed: %s", ddl)
	}
	return db
}

func TestTriggerScan_ScopeHosts_Returns200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupVulnScanAPITestDB(t)

	require.NoError(t, db.Create(&model.Host{HostID: "host-1", BusinessLine: "G02-UAT"}).Error)

	h := NewVulnerabilitiesHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/api/v1/vulnerabilities/scan", h.TriggerScan)

	body, _ := json.Marshal(map[string]any{
		"scope":    "hosts",
		"host_ids": []string{"host-1"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Code int `json:"code"`
		Data struct {
			TaskID          string `json:"task_id"`
			TargetHostCount int    `json:"target_host_count"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.TaskID)
	assert.Equal(t, 1, resp.Data.TargetHostCount)
}

func TestTriggerScan_ScopeBusinessLine_ResolvesHosts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupVulnScanAPITestDB(t)

	for _, host := range []model.Host{
		{HostID: "h-1", BusinessLine: "G02-UAT"},
		{HostID: "h-2", BusinessLine: "G02-UAT"},
		{HostID: "h-3", BusinessLine: "G01-PROD"},
	} {
		require.NoError(t, db.Create(&host).Error)
	}

	h := NewVulnerabilitiesHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/api/v1/vulnerabilities/scan", h.TriggerScan)

	body, _ := json.Marshal(map[string]any{
		"scope":         "business_line",
		"business_line": "G02-UAT",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			TargetHostCount int `json:"target_host_count"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Data.TargetHostCount)
}

func TestTriggerScan_LegacyFullScan_StillWorks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupVulnScanAPITestDB(t)

	h := NewVulnerabilitiesHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/api/v1/vulnerabilities/scan", h.TriggerScan)

	body, _ := json.Marshal(map[string]any{"scan_type": "full_scan"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGetScanTask_Returns200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupVulnScanAPITestDB(t)

	require.NoError(t, db.Create(&model.VulnScanTask{
		TaskID: "test-task-id", Scope: "hosts",
		Status: model.ScanTaskStatusRunning, ProgressTotal: 3, ProgressScanned: 1,
	}).Error)

	h := NewVulnerabilitiesHandler(db, zap.NewNop())
	r := gin.New()
	r.GET("/api/v1/vulnerabilities/scan-tasks/:task_id", h.GetScanTask)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/scan-tasks/test-task-id", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			TaskID string `json:"taskId"`
			Status string `json:"status"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "test-task-id", resp.Data.TaskID)
	assert.Equal(t, "running", resp.Data.Status)
}
