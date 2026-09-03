package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// SQLite ":memory:" 每个 conn 独立 DB,gorm 默认多 conn 池会让其他 goroutine 看到空 schema。
	// 用 file::memory:?cache=shared 让多 conn 共享同一内存 DB,支持并发 query(asset history 等
	// handler 已并发化)。test prod 都安全。
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	// 每次 setupTestDB 开新内存 DB,t.Cleanup 关闭释放 cache
	t.Cleanup(func() {
		if sqlDB, _ := db.DB(); sqlDB != nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.Exec(`CREATE TABLE hosts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		host_id TEXT PRIMARY KEY,
		hostname TEXT,
		ipv4 JSON,
		status TEXT,
		business_line TEXT
	)`).Error; err != nil {
		t.Fatalf("failed to create hosts table: %v", err)
	}
	if err := db.AutoMigrate(
		&model.Process{},
		&model.Port{},
		&model.AssetUser{},
		&model.Software{},
		&model.Container{},
		&model.App{},
		&model.NetInterface{},
		&model.Volume{},
		&model.Kmod{},
		&model.Service{},
		&model.Cron{},
		&model.PluginConfig{},
		&model.Component{},
		&model.ComponentVersion{},
		&model.ComponentPackage{},
		&model.HostPlugin{},
		&model.Vulnerability{},
		&model.HostVulnerability{},
		&model.FIMEvent{},
	); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	return db
}

func TestExportAssets_CSV_EmptyTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	h := NewAssetsHandler(db, zap.NewNop())

	r := gin.New()
	r.GET("/export", h.ExportAssets)

	for _, assetType := range []string{"processes", "ports", "users", "software"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/export?type="+assetType+"&format=csv", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("[%s] status = %d, want 200", assetType, w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/csv") {
			t.Errorf("[%s] Content-Type = %q, want text/csv", assetType, ct)
		}
		// 空表：只有 header 行，至少包含一个逗号
		body := w.Body.String()
		if !strings.Contains(body, ",") {
			t.Errorf("[%s] CSV header missing, body=%q", assetType, body)
		}
	}
}

func TestExportAssets_JSON_EmptyTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	h := NewAssetsHandler(db, zap.NewNop())

	r := gin.New()
	r.GET("/export", h.ExportAssets)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/export?type=processes&format=json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "[") {
		t.Errorf("JSON response should contain array, got %q", body)
	}
}

func TestExportAssets_InvalidType_CSV(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	h := NewAssetsHandler(db, zap.NewNop())

	r := gin.New()
	r.GET("/export", h.ExportAssets)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/export?type=invalid_type&format=csv", nil)
	r.ServeHTTP(w, req)

	// 未知类型：仍返回 200，CSV 中包含 error 提示行
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "error") && !strings.Contains(body, "不支持") {
		t.Errorf("expected error indication in body, got %q", body)
	}
}

func TestExportAssets_InvalidFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	h := NewAssetsHandler(db, zap.NewNop())

	r := gin.New()
	r.GET("/export", h.ExportAssets)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/export?type=processes&format=xml", nil)
	r.ServeHTTP(w, req)

	// 统一响应：不支持的格式走 BadRequest，HTTP 200 + body code=40000
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse body: %v, body=%q", err, w.Body.String())
	}
	if resp.Code != CodeInvalidParam {
		t.Errorf("code = %d, want %d (CodeInvalidParam)", resp.Code, CodeInvalidParam)
	}
	// 错误响应不应带附件下载头（格式校验在设头之前）。
	if cd := w.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("error response should not set Content-Disposition, got %q", cd)
	}
}

func TestExportAssets_WithData_CSV(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)

	// 插入测试数据（直接用 SQL 绕过 NOT NULL 的 zero-value 问题）
	db.Exec(`INSERT INTO processes (id, host_id, pid, ppid, exe, cmdline, uid, gid, username, groupname, exe_hash, container_id, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		"test-id-1", "host-001", "1234", "1", "/usr/bin/nginx", "nginx -g daemon off", "0", "0", "root", "root", "", "")

	h := NewAssetsHandler(db, zap.NewNop())
	r := gin.New()
	r.GET("/export", h.ExportAssets)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/export?type=processes&format=csv&host_id=host-001", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nginx") {
		t.Errorf("CSV should contain 'nginx', got:\n%s", body)
	}
	if !strings.Contains(body, "host-001") {
		t.Errorf("CSV should contain 'host-001', got:\n%s", body)
	}

	// Content-Disposition 包含文件名
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}
}

func TestExportAssets_CrontabsAliasCSV(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	db.Exec(`INSERT INTO cron_jobs (id, host_id, user, schedule, command, cron_type, enabled, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		"cron-1", "host-001", "root", "*/5 * * * *", "/usr/local/bin/cleanup", "crontab", true)

	h := NewAssetsHandler(db, zap.NewNop())
	r := gin.New()
	r.GET("/export", h.ExportAssets)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/export?type=crontabs&format=csv&host_id=host-001", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "/usr/local/bin/cleanup") {
		t.Fatalf("expected cron command in body, got:\n%s", body)
	}
}
