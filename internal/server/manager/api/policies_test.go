package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// setupPoliciesDB 创建内存 SQLite 数据库，包含策略删除测试所需的表
func setupPoliciesDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	tables := []string{
		`CREATE TABLE policies (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			version      TEXT DEFAULT '',
			description  TEXT DEFAULT '',
			os_family    TEXT DEFAULT '[]',
			os_version   TEXT DEFAULT '',
			os_requirements TEXT DEFAULT '[]',
			target_type  TEXT DEFAULT 'all',
			runtime_types TEXT DEFAULT '[]',
			enabled      INTEGER DEFAULT 1,
			group_id     TEXT DEFAULT '',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE rules (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			rule_id       TEXT PRIMARY KEY,
			policy_id     TEXT NOT NULL,
			category      TEXT DEFAULT '',
			title         TEXT DEFAULT '',
			description   TEXT DEFAULT '',
			severity      TEXT DEFAULT 'medium',
			enabled       INTEGER DEFAULT 1,
			target_type   TEXT DEFAULT 'all',
			runtime_types TEXT DEFAULT '[]',
			check_config  TEXT DEFAULT '{}',
			fix_config    TEXT DEFAULT '{}',
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE scan_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			task_id        TEXT PRIMARY KEY,
			name           TEXT DEFAULT '',
			type           TEXT DEFAULT 'baseline_scan',
			target_type    TEXT DEFAULT 'all',
			target_config  TEXT DEFAULT '{}',
			policy_id      TEXT DEFAULT '',
			policy_ids     TEXT DEFAULT '[]',
			rule_ids       TEXT DEFAULT '[]',
			status         TEXT DEFAULT 'created',
			timeout_minutes INTEGER DEFAULT 10,
			dispatched_host_count INTEGER DEFAULT 0,
			completed_host_count  INTEGER DEFAULT 0,
			failed_reason  TEXT DEFAULT '',
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			executed_at    DATETIME,
			completed_at   DATETIME
		)`,
	}
	for _, ddl := range tables {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("failed to create table: %v\nSQL: %s", err, ddl)
		}
	}
	return db
}

func setupPoliciesRouter(db *gorm.DB) (*gin.Engine, *PoliciesHandler) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	handler := NewPoliciesHandler(db, zap.NewNop())
	r.DELETE("/api/v1/policies/:policy_id", handler.DeletePolicy)
	r.POST("/api/v1/policies/batch-delete", handler.BatchDelete)
	return r, handler
}

// seedPolicy 插入一条测试策略
func seedPolicy(t *testing.T, db *gorm.DB, id, name string) {
	t.Helper()
	db.Exec("INSERT INTO policies (id, name) VALUES (?, ?)", id, name)
}

// seedScanTask 插入一条测试任务
func seedScanTask(t *testing.T, db *gorm.DB, taskID, policyID, status string) {
	t.Helper()
	db.Exec("INSERT INTO scan_tasks (task_id, policy_id, status) VALUES (?, ?, ?)",
		taskID, policyID, status)
}

// ===== DeletePolicy 测试 =====

func TestDeletePolicy_NoActiveTasks(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "pol-001", "测试策略1")
	// 只有已完成的任务
	seedScanTask(t, db, "task-1", "pol-001", "completed")
	seedScanTask(t, db, "task-2", "pol-001", "failed")

	req := httptest.NewRequest("DELETE", "/api/v1/policies/pol-001", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 验证策略被删除
	var count int64
	db.Model(&model.Policy{}).Where("id = ?", "pol-001").Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestDeletePolicy_WithPendingTask(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "pol-002", "测试策略2")
	seedScanTask(t, db, "task-3", "pol-002", "pending")

	req := httptest.NewRequest("DELETE", "/api/v1/policies/pol-002", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	// 验证响应包含冲突信息
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "活跃任务")

	// 验证策略未被删除
	var count int64
	db.Model(&model.Policy{}).Where("id = ?", "pol-002").Count(&count)
	assert.Equal(t, int64(1), count)
}

func TestDeletePolicy_WithRunningTask(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "pol-003", "测试策略3")
	seedScanTask(t, db, "task-4", "pol-003", "running")

	req := httptest.NewRequest("DELETE", "/api/v1/policies/pol-003", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var count int64
	db.Model(&model.Policy{}).Where("id = ?", "pol-003").Count(&count)
	assert.Equal(t, int64(1), count)
}

func TestDeletePolicy_NotFound(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	req := httptest.NewRequest("DELETE", "/api/v1/policies/non-existent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeletePolicy_WithPolicyIDsLike(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "pol-004", "测试策略4")
	// 任务使用 policy_ids（多策略关联）包含该策略
	db.Exec(`INSERT INTO scan_tasks (task_id, policy_id, policy_ids, status) VALUES (?, ?, ?, ?)`,
		"task-5", "", `["pol-004","pol-005"]`, "running")

	req := httptest.NewRequest("DELETE", "/api/v1/policies/pol-004", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var count int64
	db.Model(&model.Policy{}).Where("id = ?", "pol-004").Count(&count)
	assert.Equal(t, int64(1), count)
}

func TestDeletePolicy_CompletedAndCancelledTasks(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "pol-005", "测试策略5")
	seedScanTask(t, db, "task-6", "pol-005", "completed")
	seedScanTask(t, db, "task-7", "pol-005", "cancelled")
	seedScanTask(t, db, "task-8", "pol-005", "failed")

	req := httptest.NewRequest("DELETE", "/api/v1/policies/pol-005", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 所有任务都是终态，应允许删除
	assert.Equal(t, http.StatusOK, w.Code)

	var count int64
	db.Model(&model.Policy{}).Where("id = ?", "pol-005").Count(&count)
	assert.Equal(t, int64(0), count)
}

// ===== BatchDelete 测试 =====

func TestBatchDelete_NoActiveTasks(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "bp-001", "批量策略1")
	seedPolicy(t, db, "bp-002", "批量策略2")
	seedScanTask(t, db, "bt-1", "bp-001", "completed")
	seedScanTask(t, db, "bt-2", "bp-002", "failed")

	body, _ := json.Marshal(map[string]any{
		"policy_ids": []string{"bp-001", "bp-002"},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/batch-delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var count int64
	db.Model(&model.Policy{}).Where("id IN ?", []string{"bp-001", "bp-002"}).Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestBatchDelete_PartialActiveTasks(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "bp-003", "批量策略3")
	seedPolicy(t, db, "bp-004", "批量策略4")
	seedScanTask(t, db, "bt-3", "bp-003", "completed") // 无活跃任务
	seedScanTask(t, db, "bt-4", "bp-004", "running")   // 有活跃任务

	body, _ := json.Marshal(map[string]any{
		"policy_ids": []string{"bp-003", "bp-004"},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/batch-delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 部分策略有活跃任务，整批拒绝
	assert.Equal(t, http.StatusConflict, w.Code)

	// 两个策略都不应被删除
	var count int64
	db.Model(&model.Policy{}).Where("id IN ?", []string{"bp-003", "bp-004"}).Count(&count)
	assert.Equal(t, int64(2), count)
}

func TestBatchDelete_InvalidRequest(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	// 空请求体
	req := httptest.NewRequest("POST", "/api/v1/policies/batch-delete", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBatchDelete_CascadeDeleteRules(t *testing.T) {
	db := setupPoliciesDB(t)
	r, _ := setupPoliciesRouter(db)

	seedPolicy(t, db, "bp-005", "级联测试策略")
	db.Exec("INSERT INTO rules (rule_id, policy_id, title) VALUES (?, ?, ?)",
		"rule-001", "bp-005", "测试规则")
	db.Exec("INSERT INTO rules (rule_id, policy_id, title) VALUES (?, ?, ?)",
		"rule-002", "bp-005", "测试规则2")

	body, _ := json.Marshal(map[string]any{
		"policy_ids": []string{"bp-005"},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/batch-delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 验证策略已删除
	var policyCount int64
	db.Model(&model.Policy{}).Where("id = ?", "bp-005").Count(&policyCount)
	assert.Equal(t, int64(0), policyCount)

	// 验证关联规则已级联删除
	var ruleCount int64
	db.Model(&model.Rule{}).Where("policy_id = ?", "bp-005").Count(&ruleCount)
	assert.Equal(t, int64(0), ruleCount)
}
