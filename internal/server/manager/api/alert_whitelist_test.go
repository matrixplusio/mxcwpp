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

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupWhitelistDB 创建内存 SQLite 数据库，含 alert_whitelists 表
func setupWhitelistDB(t *testing.T) *gorm.DB {
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

	// 手写建表而非 AutoMigrate：模型带 MySQL 的 ON UPDATE CURRENT_TIMESTAMP，SQLite 不认
	if err := db.Exec(`CREATE TABLE alert_whitelists (
		tenant_id      TEXT NOT NULL DEFAULT 't-default',
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		name           TEXT NOT NULL,
		rule_id        TEXT DEFAULT '',
		host_id        TEXT DEFAULT '',
		category       TEXT DEFAULT '',
		severity       TEXT DEFAULT '',
		exe            TEXT DEFAULT '',
		cmdline        TEXT DEFAULT '',
		source_ip_cidr TEXT DEFAULT '',
		reason         TEXT DEFAULT '',
		created_by     TEXT DEFAULT '',
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
	)`).Error; err != nil {
		t.Fatalf("failed to create table: %v", err)
	}
	return db
}

func newWhitelistRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := NewAlertWhitelistHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/whitelist", h.CreateWhitelist)
	r.PUT("/whitelist/:id", h.UpdateWhitelist)
	return r
}

// respCode 取响应体里的业务码。项目约定参数错误也回 HTTP 200，错误体现在 code 上。
func respCode(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var body struct {
		Code int `json:"code"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body.Code
}

func postWhitelist(t *testing.T, r *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	assert.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/whitelist", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestCreateWhitelist_PersistsExeAndCmdline 验证 exe/cmdline 能通过 API 写入。
// 回归点：这两列此前只有自动调优采纳路径能写，接口层丢弃了它们，
// 导致运营无法手工创建按进程/命令行收窄的白名单。
func TestCreateWhitelist_PersistsExeAndCmdline(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)

	w := postWhitelist(t, r, map[string]any{
		"name":     "ssh-tunnel-sshd-session",
		"rule_id":  "cel-15",
		"category": "lateral_movement",
		"exe":      "sshd-session",
		"reason":   "openssh 9.8+ sshd 会话进程自身，非 SSH 隧道",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var got model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "ssh-tunnel-sshd-session").First(&got).Error)
	assert.Equal(t, "sshd-session", got.Exe)
	assert.Equal(t, "cel-15", got.RuleID)

	w = postWhitelist(t, r, map[string]any{
		"name":     "man-db-cron-touch",
		"rule_id":  "cel-48",
		"category": "defense_evasion",
		"cmdline":  "man-db.lock",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// 用新变量查询：GORM 对已带主键的结构体会自动附加 id 条件
	var got2 model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "man-db-cron-touch").First(&got2).Error)
	assert.Equal(t, "man-db.lock", got2.Cmdline)
	assert.Empty(t, got2.Exe)
}

// TestCreateWhitelist_RejectsNoNarrowing 只填 rule_id/category 的条目必须被拒绝：
// MatchesAlert 对无收窄维度的条目一律返回 false，存进去也永远不生效。
func TestCreateWhitelist_RejectsNoNarrowing(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)

	w := postWhitelist(t, r, map[string]any{
		"name":     "too-broad",
		"rule_id":  "cel-15",
		"category": "lateral_movement",
		"severity": "medium",
	})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))

	var count int64
	db.Model(&model.AlertWhitelist{}).Count(&count)
	assert.Zero(t, count, "无收窄维度的条目不应落库")
}

// TestCreateWhitelist_AcceptsSourceIPCIDROnly ScanDetector 条目只读 source_ip_cidr，
// 不该被 host/exe/cmdline 的收窄校验挡住。
func TestCreateWhitelist_AcceptsSourceIPCIDROnly(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)

	w := postWhitelist(t, r, map[string]any{
		"name":           "gke-node-subnet",
		"source_ip_cidr": "10.0.0.0/24",
		"reason":         "GKE 节点 exporter 抓取",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var got model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "gke-node-subnet").First(&got).Error)
	assert.Equal(t, "10.0.0.0/24", got.SourceIPCIDR)
}

// TestUpdateWhitelist_PersistsExeAndCmdline 更新路径同样要能改这两个维度，
// 且不能把已生效的条目改成无收窄维度的静默失效状态。
func TestUpdateWhitelist_PersistsExeAndCmdline(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)

	seed := model.AlertWhitelist{Name: "seed", RuleID: "cel-13", Category: "persistence", Exe: "modprobe"}
	assert.NoError(t, db.Create(&seed).Error)

	put := func(body map[string]any) *httptest.ResponseRecorder {
		payload, err := json.Marshal(body)
		assert.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/whitelist/1", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := put(map[string]any{
		"name":     "kernel-module-autoload",
		"rule_id":  "cel-13",
		"category": "persistence",
		"cmdline":  "modprobe -q --",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var got model.AlertWhitelist
	assert.NoError(t, db.First(&got, seed.ID).Error)
	assert.Equal(t, "modprobe -q --", got.Cmdline)
	assert.Empty(t, got.Exe, "exe 未传应被清空，与请求体保持一致")

	w = put(map[string]any{
		"name":     "kernel-module-autoload",
		"rule_id":  "cel-13",
		"category": "persistence",
	})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))
}

// TestValidateNarrowing_MatchesRuntimeSemantics 校验函数与运行时匹配语义一致：
// 接口放行的条目必须真的可能命中，"*" 不算具体收窄。
func TestValidateNarrowing_MatchesRuntimeSemantics(t *testing.T) {
	cases := []struct {
		name                               string
		hostID, exe, cmdline, sourceIPCIDR string
		want                               bool
	}{
		{"exe 具体值", "", "sshd-session", "", "", true},
		{"cmdline 具体值", "", "", "man-db.lock", "", true},
		{"host 具体值", "host-abc", "", "", "", true},
		{"仅 source_ip_cidr", "", "", "", "10.0.0.0/24", true},
		{"全空", "", "", "", "", false},
		{"通配符不算收窄", "*", "*", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateNarrowing(tc.hostID, tc.exe, tc.cmdline, tc.sourceIPCIDR)
			assert.Equal(t, tc.want, got)

			// 与运行时一致性：非 source_ip_cidr 条目的放行结果必须等于 MatchesAlert 的前置判据
			if tc.sourceIPCIDR == "" {
				w := model.AlertWhitelist{HostID: tc.hostID, Exe: tc.exe, Cmdline: tc.cmdline}
				assert.Equal(t, got, w.HasConcreteNarrowing())
			}
		})
	}
}
