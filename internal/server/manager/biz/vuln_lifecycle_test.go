package biz

import (
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ===== 测试基础设施 =====

// setupVulnLifecycleDB 创建内存 SQLite 数据库，包含生命周期测试所需的所有表
// 手动建表以避免 MySQL 专有语法在 SQLite 中报错
func setupVulnLifecycleDB(t *testing.T) *gorm.DB {
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
		`CREATE TABLE hosts (
			host_id  TEXT PRIMARY KEY,
			hostname TEXT,
			ipv4     TEXT DEFAULT '[]',
			status   TEXT DEFAULT 'offline'
		)`,
		`CREATE TABLE vulnerabilities (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id          TEXT NOT NULL UNIQUE,
			osv_id          TEXT,
			purl            TEXT,
			severity        TEXT NOT NULL DEFAULT 'medium',
			cvss_score      REAL DEFAULT 0,
			component       TEXT,
			description     TEXT,
			affected_hosts  INTEGER DEFAULT 0,
			patched_hosts   INTEGER DEFAULT 0,
			status          TEXT NOT NULL DEFAULT 'unpatched',
			discovered_at   DATETIME,
			patched_at      DATETIME,
			current_version TEXT,
			fixed_version   TEXT,
			reference_url   TEXT,
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE host_vulnerabilities (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			vuln_id         INTEGER NOT NULL,
			host_id         TEXT NOT NULL,
			hostname        TEXT,
			ip              TEXT,
			current_version TEXT,
			status          TEXT NOT NULL DEFAULT 'unpatched',
			patched_at      DATETIME,
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(vuln_id, host_id)
		)`,
		`CREATE TABLE remediation_tasks (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			vuln_id       INTEGER NOT NULL,
			cve_id        TEXT NOT NULL,
			host_id       TEXT NOT NULL,
			hostname      TEXT,
			ip            TEXT,
			component     TEXT,
			fixed_version TEXT,
			command       TEXT,
			status        TEXT NOT NULL DEFAULT 'pending',
			exec_output   TEXT,
			exit_code     INTEGER,
			created_by    TEXT,
			confirmed_by  TEXT,
			confirmed_at  DATETIME,
			started_at    DATETIME,
			finished_at   DATETIME,
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE software (
			id           TEXT PRIMARY KEY,
			host_id      TEXT NOT NULL,
			name         TEXT NOT NULL,
			version      TEXT,
			architecture TEXT,
			package_type TEXT NOT NULL DEFAULT 'rpm',
			vendor       TEXT,
			install_time TEXT,
			purl         TEXT,
			collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, ddl := range tables {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatalf("failed to create table: %v\nSQL: %s", err, ddl)
		}
	}
	return db
}

func nopLogger() *zap.Logger { return zap.NewNop() }

// ===== 场景 1: 漏洞发现 → 主机关联 =====

func TestScenario_VulnDiscovery_HostAssociation(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0001", Severity: "high", Component: "openssl",
		Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)

	scanner := NewVulnScanner(db, nopLogger())
	scanner.upsertHostVulnsBatch(vuln.ID, []hostVulnEntry{
		{HostID: "host-001", Hostname: "web-01", IP: "10.0.0.1", Version: "1.1.1k"},
		{HostID: "host-002", Hostname: "web-02", IP: "10.0.0.2", Version: "1.1.1k"},
		{HostID: "host-003", Hostname: "db-01", IP: "10.0.0.3", Version: "1.1.1j"},
	})

	// 验证：3 条主机-漏洞关联记录
	var count int64
	db.Model(&model.HostVulnerability{}).Where("vuln_id = ?", vuln.ID).Count(&count)
	if count != 3 {
		t.Errorf("expected 3 host_vulnerabilities, got %d", count)
	}

	// 验证：affected_hosts 自动更新
	db.First(vuln, vuln.ID)
	if vuln.AffectedHosts != 3 {
		t.Errorf("expected affected_hosts=3, got %d", vuln.AffectedHosts)
	}

	// 验证：所有主机状态为 unpatched
	var statuses []string
	db.Model(&model.HostVulnerability{}).Where("vuln_id = ?", vuln.ID).Pluck("status", &statuses)
	for i, s := range statuses {
		if s != "unpatched" {
			t.Errorf("host[%d] expected 'unpatched', got %q", i, s)
		}
	}
}

// ===== 场景 2: 已修复漏洞在重新扫描中出现（版本回退/重装）=====

func TestScenario_VulnReEmergence(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0002", Severity: "critical", Component: "openssl",
		FixedVersion: "1.1.2", Status: "patched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)

	now := model.Now()
	db.Create(&model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-001", Hostname: "web-01", IP: "10.0.0.1",
		CurrentVersion: "1.1.2", Status: "patched", PatchedAt: &now,
	})

	// 重新扫描：该主机版本回退到旧版本（如重装系统后版本倒退）
	scanner := NewVulnScanner(db, nopLogger())
	scanner.upsertHostVulnsBatch(vuln.ID, []hostVulnEntry{
		{HostID: "host-001", Hostname: "web-01", IP: "10.0.0.1", Version: "1.1.1"},
	})

	// 验证：主机状态回退为 unpatched
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-001").First(&hv)
	if hv.Status != "unpatched" {
		t.Errorf("expected host status to revert to 'unpatched', got %q", hv.Status)
	}
	if hv.PatchedAt != nil {
		t.Error("expected patched_at to be cleared after re-emergence")
	}

	// 验证：漏洞主表也回退为 unpatched
	db.First(vuln, vuln.ID)
	if vuln.Status != "unpatched" {
		t.Errorf("expected vuln status to revert to 'unpatched', got %q", vuln.Status)
	}
}

// ===== 场景 3: 完整修复生命周期（含自动版本验证）=====
// pending → confirmed → running → success → VerifyHost → patched

func TestScenario_Remediation_FullLifecycle_WithVerification(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	log := nopLogger()

	// Step 1: 漏洞发现，创建漏洞和主机关联
	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0003", Severity: "high", Component: "openssl",
		FixedVersion: "1.1.1l", Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-001", Hostname: "web-01", IP: "10.0.0.1",
		CurrentVersion: "1.1.1k", Status: "unpatched",
	})
	db.Exec(`INSERT INTO software (id, host_id, name, version, package_type, updated_at)
		VALUES (?, ?, ?, ?, 'rpm', datetime('now'))`, "host-001-openssl", "host-001", "openssl", "1.1.1k")

	// Step 2: 创建修复任务（pending）
	task := &model.RemediationTask{
		VulnID: vuln.ID, CveID: "CVE-2024-0003", HostID: "host-001",
		Hostname: "web-01", IP: "10.0.0.1", Component: "openssl",
		FixedVersion: "1.1.1l", Command: "yum update openssl-1.1.1l -y",
		Status: "pending", CreatedBy: "admin",
	}
	db.Create(task)
	if task.Status != "pending" {
		t.Fatalf("task should start as 'pending', got %q", task.Status)
	}

	// Step 3: 管理员确认
	confirmTime := model.Now()
	db.Model(task).Updates(map[string]any{
		"status": "confirmed", "confirmed_by": "admin", "confirmed_at": confirmTime,
	})

	// Step 4: 调度器下发（模拟 CAS 更新）
	startTime := model.Now()
	db.Model(task).Where("status = ?", "confirmed").Updates(map[string]any{
		"status": "running", "started_at": startTime,
	})

	// Step 5: Agent 执行成功，软件版本已更新
	db.Exec(`UPDATE software SET version = ?, updated_at = datetime('now') WHERE id = ?`,
		"1.1.1l", "host-001-openssl")

	// Step 6: Agent 上报执行结果
	executor := NewRemediationExecutor(db, log)
	err := executor.HandleResult("host-001", map[string]string{
		"task_id": fmt.Sprintf("%d", task.ID), "exit_code": "0",
		"stdout": "Updated: openssl-1.1.1l-1.el7.x86_64",
	})
	if err != nil {
		t.Fatalf("HandleResult failed: %v", err)
	}

	// 验证：任务状态 = success
	db.First(task, task.ID)
	if task.Status != "success" {
		t.Errorf("expected task status 'success', got %q", task.Status)
	}
	if task.ExitCode == nil || *task.ExitCode != 0 {
		t.Error("expected exit_code = 0")
	}
	if task.FinishedAt == nil {
		t.Error("expected finished_at to be set")
	}

	// 验证：HostVulnerability = patched（自动验证通过）
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-001").First(&hv)
	if hv.Status != "patched" {
		t.Errorf("expected host_vuln 'patched', got %q", hv.Status)
	}
	if hv.PatchedAt == nil {
		t.Error("expected patched_at to be set")
	}

	// 验证：漏洞主表 = patched（所有主机都已修复）
	db.First(vuln, vuln.ID)
	if vuln.Status != "patched" {
		t.Errorf("expected vuln status 'patched', got %q", vuln.Status)
	}
}

// ===== 场景 4: 修复成功但验证未通过（回退到按执行结果标记）=====

func TestScenario_Remediation_FallbackPatch(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	log := nopLogger()

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0004", Severity: "medium", Component: "curl",
		FixedVersion: "7.88.0", Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-002", CurrentVersion: "7.76.1", Status: "unpatched",
	})
	// 不插入 software 记录 → VerifyHost 无法找到组件信息 → 回退到 PatchVulnerability

	startTime := model.Now()
	task := &model.RemediationTask{
		VulnID: vuln.ID, CveID: "CVE-2024-0004", HostID: "host-002",
		Component: "curl", FixedVersion: "7.88.0",
		Command: "yum update curl-7.88.0 -y", Status: "running", StartedAt: &startTime,
	}
	db.Create(task)

	executor := NewRemediationExecutor(db, log)
	err := executor.HandleResult("host-002", map[string]string{
		"task_id": fmt.Sprintf("%d", task.ID), "exit_code": "0", "stdout": "Updated curl",
	})
	if err != nil {
		t.Fatalf("HandleResult failed: %v", err)
	}

	// 验证：尽管自动验证未通过，仍通过 PatchVulnerability 标记为 patched
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-002").First(&hv)
	if hv.Status != "patched" {
		t.Errorf("expected fallback to mark 'patched', got %q", hv.Status)
	}
}

// ===== 场景 5: 修复执行失败 =====

func TestScenario_Remediation_Failed(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	log := nopLogger()

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0005", Severity: "high", Component: "nginx",
		Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-003", Status: "unpatched",
	})

	startTime := model.Now()
	task := &model.RemediationTask{
		VulnID: vuln.ID, CveID: "CVE-2024-0005", HostID: "host-003",
		Command: "yum update nginx -y", Status: "running", StartedAt: &startTime,
	}
	db.Create(task)

	executor := NewRemediationExecutor(db, log)
	err := executor.HandleResult("host-003", map[string]string{
		"task_id": fmt.Sprintf("%d", task.ID), "exit_code": "1",
		"stderr": "No package nginx available",
	})
	if err != nil {
		t.Fatalf("HandleResult failed: %v", err)
	}

	// 验证：任务标记为 failed
	db.First(task, task.ID)
	if task.Status != "failed" {
		t.Errorf("expected task status 'failed', got %q", task.Status)
	}
	if task.ExitCode == nil || *task.ExitCode != 1 {
		t.Error("expected exit_code = 1")
	}
	if task.ExecOutput == "" {
		t.Error("expected exec_output to contain error details")
	}

	// 验证：主机漏洞状态保持 unpatched
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-003").First(&hv)
	if hv.Status != "unpatched" {
		t.Errorf("expected host_vuln to remain 'unpatched' after failed task, got %q", hv.Status)
	}
}

// ===== 场景 6: 修复任务超时 =====

func TestScenario_Remediation_TaskTimeout(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	log := nopLogger()

	// 31 分钟前开始的 running 任务 → 应超时
	oldStart := model.LocalTime(time.Now().Add(-31 * time.Minute))
	db.Create(&model.RemediationTask{
		VulnID: 1, CveID: "CVE-2024-0006", HostID: "host-004",
		Command: "yum update openssl -y", Status: "running", StartedAt: &oldStart,
	})

	// 10 分钟前开始的 running 任务 → 不应超时
	recentStart := model.LocalTime(time.Now().Add(-10 * time.Minute))
	db.Create(&model.RemediationTask{
		VulnID: 1, CveID: "CVE-2024-0006", HostID: "host-005",
		Command: "yum update openssl -y", Status: "running", StartedAt: &recentStart,
	})

	executor := NewRemediationExecutor(db, log)
	executor.timeoutRunningTasks()

	// 验证：超时任务 → failed
	var timedOut model.RemediationTask
	db.Where("host_id = ?", "host-004").First(&timedOut)
	if timedOut.Status != "failed" {
		t.Errorf("expected timed-out task to be 'failed', got %q", timedOut.Status)
	}
	if timedOut.ExecOutput == "" {
		t.Error("expected timeout message in exec_output")
	}

	// 验证：未超时任务 → 仍然 running
	var active model.RemediationTask
	db.Where("host_id = ?", "host-005").First(&active)
	if active.Status != "running" {
		t.Errorf("expected non-timed-out task to remain 'running', got %q", active.Status)
	}
}

// ===== 场景 7: HandleResult 安全校验 =====

func TestScenario_HandleResult_UnauthorizedAgent(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	startTime := model.Now()
	db.Create(&model.RemediationTask{
		VulnID: 1, CveID: "CVE-2024-0007", HostID: "host-001",
		Command: "yum update openssl -y", Status: "running", StartedAt: &startTime,
	})

	executor := NewRemediationExecutor(db, nopLogger())
	err := executor.HandleResult("host-999", map[string]string{
		"task_id": "1", "exit_code": "0",
	})

	// 验证：拒绝非授权 Agent 上报
	if err == nil {
		t.Fatal("expected error for unauthorized agent")
	}

	// 验证：任务状态不受影响
	var task model.RemediationTask
	db.First(&task, 1)
	if task.Status != "running" {
		t.Errorf("expected task to remain 'running', got %q", task.Status)
	}
}

func TestScenario_HandleResult_DuplicateResult(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	db.Create(&model.RemediationTask{
		VulnID: 1, CveID: "CVE-2024-0008", HostID: "host-001",
		Status: "success", // 已处理过
	})

	executor := NewRemediationExecutor(db, nopLogger())
	// 重复上报应静默忽略
	err := executor.HandleResult("host-001", map[string]string{
		"task_id": "1", "exit_code": "0",
	})
	if err != nil {
		t.Errorf("expected duplicate result to be silently ignored, got: %v", err)
	}
}

func TestScenario_HandleResult_MissingTaskID(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	executor := NewRemediationExecutor(db, nopLogger())

	err := executor.HandleResult("host-001", map[string]string{"exit_code": "0"})
	if err == nil {
		t.Fatal("expected error for missing task_id")
	}
}

func TestScenario_HandleResult_NonexistentTask(t *testing.T) {
	db := setupVulnLifecycleDB(t)
	executor := NewRemediationExecutor(db, nopLogger())

	err := executor.HandleResult("host-001", map[string]string{
		"task_id": "99999", "exit_code": "0",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent task")
	}
}

// ===== 场景 8: 忽略与取消忽略 =====

func TestScenario_IgnoreUnignore(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0009", Severity: "low", Component: "vim",
		Status: "unpatched", DiscoveredAt: model.Now(), AffectedHosts: 2,
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{VulnID: vuln.ID, HostID: "host-001", Status: "unpatched"})
	db.Create(&model.HostVulnerability{VulnID: vuln.ID, HostID: "host-002", Status: "unpatched"})

	// ===== 忽略操作（模拟 API handler 事务）=====
	db.Transaction(func(tx *gorm.DB) error {
		tx.Model(&model.Vulnerability{}).Where("id = ?", vuln.ID).Update("status", "ignored")
		tx.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").
			Update("status", "ignored")
		return nil
	})

	db.First(vuln, vuln.ID)
	if vuln.Status != "ignored" {
		t.Errorf("expected vuln status 'ignored', got %q", vuln.Status)
	}
	var ignoredCount int64
	db.Model(&model.HostVulnerability{}).Where("vuln_id = ? AND status = ?", vuln.ID, "ignored").Count(&ignoredCount)
	if ignoredCount != 2 {
		t.Errorf("expected 2 ignored host_vulns, got %d", ignoredCount)
	}

	// ===== 取消忽略 =====
	db.Transaction(func(tx *gorm.DB) error {
		tx.Model(&model.Vulnerability{}).Where("id = ?", vuln.ID).Update("status", "unpatched")
		tx.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vuln.ID, "ignored").
			Update("status", "unpatched")
		return nil
	})

	db.First(vuln, vuln.ID)
	if vuln.Status != "unpatched" {
		t.Errorf("expected vuln 'unpatched' after unignore, got %q", vuln.Status)
	}
	var unpatchedCount int64
	db.Model(&model.HostVulnerability{}).Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").Count(&unpatchedCount)
	if unpatchedCount != 2 {
		t.Errorf("expected 2 unpatched host_vulns after unignore, got %d", unpatchedCount)
	}
}

// ===== 场景 9: 版本验证（epoch:version-release 格式）=====

func TestScenario_VerifyHost_EpochVersion(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0010", Severity: "high", Component: "openssl-libs",
		FixedVersion: "1:3.0.7-18.el9", Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-001", CurrentVersion: "1:3.0.7-16.el9", Status: "unpatched",
	})

	// 软件已升级到修复版本
	db.Exec(`INSERT INTO software (id, host_id, name, version, package_type, updated_at)
		VALUES (?, ?, ?, ?, 'rpm', datetime('now'))`,
		"host-001-openssl-libs", "host-001", "openssl-libs", "1:3.0.7-18.el9")

	verifier := NewRemediationVerifier(db, nopLogger())
	result, err := verifier.VerifyHost(vuln.ID, "host-001")
	if err != nil {
		t.Fatalf("VerifyHost failed: %v", err)
	}
	if !result.Verified {
		t.Errorf("expected verification to pass for epoch version, got message: %s", result.Message)
	}

	// 验证：HostVulnerability 自动更新为 patched
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-001").First(&hv)
	if hv.Status != "patched" {
		t.Errorf("expected host_vuln 'patched', got %q", hv.Status)
	}
}

func TestScenario_VerifyHost_NoFixedVersion(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0011", Severity: "medium", Component: "zlib",
		Status: "unpatched", DiscoveredAt: model.Now(),
		// FixedVersion 为空 → 无法自动验证
	}
	db.Create(vuln)

	verifier := NewRemediationVerifier(db, nopLogger())
	result, err := verifier.VerifyHost(vuln.ID, "host-001")
	if err != nil {
		t.Fatalf("VerifyHost failed: %v", err)
	}
	if result.Verified {
		t.Error("expected verification to fail when no fixed version")
	}
	if result.Message == "" {
		t.Error("expected message explaining why verification cannot proceed")
	}
}

func TestScenario_VerifyHost_VersionNotUpgraded(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0012", Severity: "high", Component: "openssl",
		FixedVersion: "1.1.2", Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{
		VulnID: vuln.ID, HostID: "host-001", Status: "unpatched",
	})

	// 软件版本仍然是旧版本
	db.Exec(`INSERT INTO software (id, host_id, name, version, package_type, updated_at)
		VALUES (?, ?, ?, ?, 'rpm', datetime('now'))`,
		"host-001-openssl", "host-001", "openssl", "1.1.1")

	verifier := NewRemediationVerifier(db, nopLogger())
	result, err := verifier.VerifyHost(vuln.ID, "host-001")
	if err != nil {
		t.Fatalf("VerifyHost failed: %v", err)
	}
	if result.Verified {
		t.Error("expected verification to fail when version not upgraded")
	}

	// 验证：HostVulnerability 仍为 unpatched
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-001").First(&hv)
	if hv.Status != "unpatched" {
		t.Errorf("expected host_vuln to remain 'unpatched', got %q", hv.Status)
	}
}

// ===== 场景 10: 部分修复不改变漏洞主状态 =====

func TestScenario_PartialRemediation(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0013", Severity: "critical", Component: "openssl",
		FixedVersion: "1.1.1l", Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)
	db.Create(&model.HostVulnerability{VulnID: vuln.ID, HostID: "host-001", Status: "unpatched"})
	db.Create(&model.HostVulnerability{VulnID: vuln.ID, HostID: "host-002", Status: "unpatched"})

	svc := NewRemediationService(db, nopLogger())

	// 只修复 host-001
	if err := svc.PatchVulnerability(vuln.ID, []string{"host-001"}); err != nil {
		t.Fatalf("PatchVulnerability failed: %v", err)
	}

	// 验证：漏洞仍为 unpatched（host-002 未修复）
	db.First(vuln, vuln.ID)
	if vuln.Status != "unpatched" {
		t.Errorf("expected vuln to remain 'unpatched', got %q", vuln.Status)
	}
	if vuln.PatchedHosts != 1 {
		t.Errorf("expected patched_hosts=1, got %d", vuln.PatchedHosts)
	}

	// 修复 host-002
	if err := svc.PatchVulnerability(vuln.ID, []string{"host-002"}); err != nil {
		t.Fatalf("PatchVulnerability failed: %v", err)
	}

	// 验证：全部修复后漏洞标记为 patched
	db.First(vuln, vuln.ID)
	if vuln.Status != "patched" {
		t.Errorf("expected vuln 'patched' when all hosts done, got %q", vuln.Status)
	}
	if vuln.PatchedAt == nil {
		t.Error("expected patched_at to be set")
	}
	if vuln.PatchedHosts != 2 {
		t.Errorf("expected patched_hosts=2, got %d", vuln.PatchedHosts)
	}
}

// ===== 场景 11: 调度器下发任务（含主机在线检查）=====

// mockTransfer 模拟 gRPC 下发服务
type mockTransfer struct {
	dispatched []string
}

func (m *mockTransfer) SendCommand(agentID string, cmd *grpcProto.Command) error {
	m.dispatched = append(m.dispatched, agentID)
	return nil
}

func TestScenario_DispatchConfirmedTasks(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	// 创建主机：一台在线，一台离线
	db.Exec(`INSERT INTO hosts (host_id, hostname, status) VALUES (?, ?, ?)`, "host-001", "web-01", "online")
	db.Exec(`INSERT INTO hosts (host_id, hostname, status) VALUES (?, ?, ?)`, "host-002", "web-02", "offline")

	db.Create(&model.RemediationTask{
		VulnID: 1, CveID: "CVE-2024-0014", HostID: "host-001",
		Component: "openssl", Command: "yum update openssl -y", Status: "confirmed",
	})
	db.Create(&model.RemediationTask{
		VulnID: 1, CveID: "CVE-2024-0014", HostID: "host-002",
		Component: "openssl", Command: "yum update openssl -y", Status: "confirmed",
	})

	mock := &mockTransfer{}
	executor := NewRemediationExecutor(db, nopLogger())
	if err := executor.DispatchConfirmedTasks(mock); err != nil {
		t.Fatalf("DispatchConfirmedTasks failed: %v", err)
	}

	// 验证：只有在线主机的任务被下发
	if len(mock.dispatched) != 1 || mock.dispatched[0] != "host-001" {
		t.Errorf("expected only host-001 dispatched, got %v", mock.dispatched)
	}

	// host-001 任务 → running
	var task1 model.RemediationTask
	db.Where("host_id = ?", "host-001").First(&task1)
	if task1.Status != "running" {
		t.Errorf("expected online host task 'running', got %q", task1.Status)
	}
	if task1.StartedAt == nil {
		t.Error("expected started_at to be set for dispatched task")
	}

	// host-002 任务 → 仍为 confirmed
	var task2 model.RemediationTask
	db.Where("host_id = ?", "host-002").First(&task2)
	if task2.Status != "confirmed" {
		t.Errorf("expected offline host task to remain 'confirmed', got %q", task2.Status)
	}
}

// ===== 场景 12: 批量验证 =====

func TestScenario_BatchVerify(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0015", Severity: "high", Component: "openssl",
		FixedVersion: "1.1.2", Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)

	// 两台主机，一台已升级，一台未升级
	db.Create(&model.HostVulnerability{VulnID: vuln.ID, HostID: "host-001", Status: "unpatched"})
	db.Create(&model.HostVulnerability{VulnID: vuln.ID, HostID: "host-002", Status: "unpatched"})

	db.Exec(`INSERT INTO software (id, host_id, name, version, package_type, updated_at) VALUES (?, ?, ?, ?, 'rpm', datetime('now'))`,
		"h1-openssl", "host-001", "openssl", "1.1.2") // 已升级
	db.Exec(`INSERT INTO software (id, host_id, name, version, package_type, updated_at) VALUES (?, ?, ?, ?, 'rpm', datetime('now'))`,
		"h2-openssl", "host-002", "openssl", "1.1.1") // 未升级

	verifier := NewRemediationVerifier(db, nopLogger())
	results, err := verifier.BatchVerify(vuln.ID)
	if err != nil {
		t.Fatalf("BatchVerify failed: %v", err)
	}

	// 只对 unpatched 的主机做验证，但 host-001 在验证中被标记为 patched
	// BatchVerify 查询 status='unpatched' 的主机。两台都是 unpatched。
	// host-001 验证通过 → 标记 patched。host-002 验证不通过 → 保持 unpatched
	verified := 0
	for _, r := range results {
		if r.Verified {
			verified++
		}
	}
	if verified != 1 {
		t.Errorf("expected 1 verified host, got %d", verified)
	}

	// 验证：host-001 已被标记为 patched
	var hv1 model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-001").First(&hv1)
	if hv1.Status != "patched" {
		t.Errorf("expected host-001 'patched', got %q", hv1.Status)
	}

	// host-002 仍为 unpatched
	var hv2 model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-002").First(&hv2)
	if hv2.Status != "unpatched" {
		t.Errorf("expected host-002 'unpatched', got %q", hv2.Status)
	}
}

// ===== 场景 13: 重复发现不创建重复记录 =====

func TestScenario_UpsertHostVulns_NoDuplicate(t *testing.T) {
	db := setupVulnLifecycleDB(t)

	vuln := &model.Vulnerability{
		CveID: "CVE-2024-0016", Severity: "medium", Component: "curl",
		Status: "unpatched", DiscoveredAt: model.Now(),
	}
	db.Create(vuln)

	scanner := NewVulnScanner(db, nopLogger())

	// 首次插入
	scanner.upsertHostVulnsBatch(vuln.ID, []hostVulnEntry{
		{HostID: "host-001", Hostname: "web-01", IP: "10.0.0.1", Version: "7.76.1"},
	})

	// 再次插入相同主机（IP 变更 → 应更新而非新建）
	scanner.upsertHostVulnsBatch(vuln.ID, []hostVulnEntry{
		{HostID: "host-001", Hostname: "web-01", IP: "10.0.0.99", Version: "7.76.1"},
	})

	// 验证：仍然只有 1 条记录
	var count int64
	db.Model(&model.HostVulnerability{}).Where("vuln_id = ?", vuln.ID).Count(&count)
	if count != 1 {
		t.Errorf("expected 1 host_vulnerability (upsert), got %d", count)
	}

	// 验证：IP 已更新
	var hv model.HostVulnerability
	db.Where("vuln_id = ? AND host_id = ?", vuln.ID, "host-001").First(&hv)
	if hv.IP != "10.0.0.99" {
		t.Errorf("expected IP updated to '10.0.0.99', got %q", hv.IP)
	}
}
