package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		expires_at     DATETIME,
		enabled        BOOLEAN NOT NULL DEFAULT 1,
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
	r.Use(func(c *gin.Context) { c.Set("username", "alice"); c.Next() })
	r.GET("/whitelist", h.ListWhitelist)
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
		"exe":      "/usr/sbin/sshd-session",
		"reason":   "openssh 9.8+ sshd 会话进程自身，非 SSH 隧道",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var got model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "ssh-tunnel-sshd-session").First(&got).Error)
	assert.Equal(t, "/usr/sbin/sshd-session", got.Exe)
	assert.Equal(t, "cel-15", got.RuleID)

	w = postWhitelist(t, r, map[string]any{
		"name":     "man-db-cron-touch",
		"rule_id":  "cel-48",
		"category": "defense_evasion",
		"exe":      "/usr/bin/touch",
		"cmdline":  "man-db.lock",
		"reason":   "man-db 定时任务的锁文件",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// 用新变量查询：GORM 对已带主键的结构体会自动附加 id 条件
	var got2 model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "man-db-cron-touch").First(&got2).Error)
	assert.Equal(t, "man-db.lock", got2.Cmdline)
	assert.Equal(t, "/usr/bin/touch", got2.Exe)

	// 对全部主机生效时只写命令行不行：命令行由执行者决定，可被借用。
	w = postWhitelist(t, r, map[string]any{
		"name": "cmdline-only", "rule_id": "cel-48", "severity": "medium", "cmdline": "man-db.lock", "reason": "x",
	})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))
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
		"name":           "monitor-subnet",
		"source_ip_cidr": "10.0.0.0/24",
		"reason":         "监控节点 exporter 抓取",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var got model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "monitor-subnet").First(&got).Error)
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
		"exe":      "/usr/sbin/modprobe",
		"cmdline":  "modprobe -q --",
		"reason":   "内核模块按需自动加载",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var got model.AlertWhitelist
	assert.NoError(t, db.First(&got, seed.ID).Error)
	assert.Equal(t, "modprobe -q --", got.Cmdline)
	assert.Equal(t, "/usr/sbin/modprobe", got.Exe, "历史上只写程序名的条目更新时按请求体改成完整路径")

	w = put(map[string]any{
		"name":     "kernel-module-autoload",
		"rule_id":  "cel-13",
		"category": "persistence",
		"reason":   "内核模块按需自动加载",
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

// 抑制规则必须写明原因：它会长期压下命中，事后要能回答为什么。
func TestCreateWhitelist_RequiresReason(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)
	w := postWhitelist(t, r, map[string]any{"name": "x", "rule_id": "cel-1", "host_id": "h1", "exe": "/opt/scripts/backup.sh"})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))
}

// 可能压下 critical 告警的条目必须带具体证据；限定为非 critical 的可以只按规则与主机。
func TestCreateWhitelist_CriticalNeedsEvidence(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)

	// 未限定严重度、只写主机：可能覆盖 critical，必须拒绝。
	w := postWhitelist(t, r, map[string]any{"name": "broad", "host_id": "h1", "reason": "测试机"})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))

	// 显式限定 medium：不会压下 critical，允许只按主机。
	w = postWhitelist(t, r, map[string]any{"name": "medium-only", "host_id": "h1", "severity": "medium", "reason": "测试机"})
	assert.Equal(t, 0, respCode(t, w))

	// 带进程证据：允许。
	w = postWhitelist(t, r, map[string]any{"name": "scoped", "rule_id": "cel-1", "host_id": "h1", "exe": "/opt/scripts/backup.sh", "reason": "备份脚本"})
	assert.Equal(t, 0, respCode(t, w))
}

// 新建默认 30 天到期，最长 90 天，并记下是谁建的。
func TestCreateWhitelist_DefaultExpiryAndCreator(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)
	w := postWhitelist(t, r, map[string]any{"name": "scoped", "rule_id": "cel-1", "host_id": "h1", "exe": "/opt/scripts/backup.sh", "reason": "备份脚本"})
	assert.Equal(t, 0, respCode(t, w))

	var got model.AlertWhitelist
	assert.NoError(t, db.Where("name = ?", "scoped").First(&got).Error)
	assert.Equal(t, "alice", got.CreatedBy)
	assert.True(t, got.Enabled)
	if assert.NotNil(t, got.ExpiresAt) {
		days := time.Until(time.Time(*got.ExpiresAt)).Hours() / 24
		assert.InDelta(t, 30, days, 1)
	}

	w = postWhitelist(t, r, map[string]any{"name": "too-long", "rule_id": "cel-1", "host_id": "h1", "exe": "/a", "reason": "x", "expires_in_days": 91})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))
}

// 停用能写进库（GORM 默认跳过 false），并能按状态筛出来。
func TestDisableAndFilterByStatus(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)
	postWhitelist(t, r, map[string]any{"name": "scoped", "rule_id": "cel-1", "host_id": "h1", "exe": "/opt/scripts/backup.sh", "reason": "备份脚本"})

	payload, _ := json.Marshal(map[string]any{"name": "scoped", "rule_id": "cel-1", "host_id": "h1", "exe": "/opt/scripts/backup.sh", "reason": "备份脚本", "enabled": false})
	req := httptest.NewRequest(http.MethodPut, "/whitelist/1", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 0, respCode(t, w))

	var got model.AlertWhitelist
	assert.NoError(t, db.First(&got, 1).Error)
	assert.False(t, got.Enabled, "停用必须真的写进库")

	for status, want := range map[string]int{"disabled": 1, "active": 0} {
		req := httptest.NewRequest(http.MethodGet, "/whitelist?status="+status, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Data struct {
				Total int `json:"total"`
			} `json:"data"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, want, body.Data.Total, "status=%s", status)
	}
}

// 历史上不合规的条目（critical 只按主机豁免、没写原因）必须能先停掉；重新启用时才校验。
func TestDisableLegacyNonCompliantEntry(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)
	assert.NoError(t, db.Create(&model.AlertWhitelist{Name: "legacy", HostID: "h1", Enabled: true}).Error)

	put := func(body map[string]any) int {
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/whitelist/1", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return respCode(t, w)
	}
	assert.Equal(t, 0, put(map[string]any{"name": "legacy", "host_id": "h1", "enabled": false}))
	assert.Equal(t, CodeInvalidParam, put(map[string]any{"name": "legacy", "host_id": "h1", "enabled": true}))
}

// 只写程序名的豁免可被同名程序借用，必须写完整路径。
func TestCreateWhitelist_RejectsBasenameExe(t *testing.T) {
	db := setupWhitelistDB(t)
	r := newWhitelistRouter(db)
	w := postWhitelist(t, r, map[string]any{"name": "dnf", "rule_id": "cel-72", "severity": "medium", "exe": "dnf", "reason": "包管理器"})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))

	w = postWhitelist(t, r, map[string]any{"name": "dnf", "rule_id": "cel-72", "severity": "medium", "exe": "/usr/bin/dnf", "reason": "包管理器"})
	assert.Equal(t, 0, respCode(t, w))
}

// 豁免的进程正是规则要检测的进程时拒绝：那等于把规则停掉。
func TestCreateWhitelist_RejectsConflictWithRule(t *testing.T) {
	db := setupWhitelistDB(t)
	assert.NoError(t, db.Exec(`CREATE TABLE detection_rules (id INTEGER PRIMARY KEY, expression TEXT, severity TEXT)`).Error)
	assert.NoError(t, db.Exec(`INSERT INTO detection_rules (id, expression, severity) VALUES (10, ?, 'high')`,
		`(cmdline.contains(">/dev/null") || cmdline.contains("history -c")) && exe.contains("bash")`).Error)
	r := newWhitelistRouter(db)

	w := postWhitelist(t, r, map[string]any{"name": "bash", "rule_id": "cel-10", "exe": "/usr/bin/bash", "reason": "脚本输出重定向"})
	assert.Equal(t, CodeInvalidParam, respCode(t, w))

	// 再约束命令行就只豁免那个脚本，规则对其他 bash 照常生效。
	w = postWhitelist(t, r, map[string]any{"name": "bash-backup", "rule_id": "cel-10", "exe": "/usr/bin/bash",
		"cmdline": "/opt/scripts/backup.sh", "reason": "备份脚本输出重定向"})
	assert.Equal(t, 0, respCode(t, w))
}
