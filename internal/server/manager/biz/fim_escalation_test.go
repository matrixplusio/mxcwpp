package biz

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupFIMEscalationDB 建 sqlite 内存库 + 手动建表。
// 手动 CREATE TABLE 而非 AutoMigrate：避免 GORM 在 sqlite 上的 MySQL 专有索引语法报错。
func setupFIMEscalationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	for _, ddl := range []string{
		`CREATE TABLE fim_policies (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			policy_id TEXT PRIMARY KEY,
			escalation_timeout_min INTEGER DEFAULT 1440
		)`,
		`CREATE TABLE fim_tasks (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			task_id TEXT PRIMARY KEY,
			policy_id TEXT
		)`,
		`CREATE TABLE fim_events (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			event_id TEXT PRIMARY KEY,
			host_id TEXT,
			hostname TEXT,
			task_id TEXT,
			file_path TEXT,
			change_type TEXT,
			change_detail TEXT,
			severity TEXT,
			category TEXT,
			detected_at DATETIME,
			status TEXT DEFAULT 'pending',
			confirmed_by TEXT,
			confirmed_at DATETIME,
			confirm_reason TEXT,
			alert_id INTEGER,
			created_at DATETIME
		)`,
		// result_id 上的唯一索引是本用例的核心：重复升级必须冲突
		// alerts 列按 model.Alert 全量建，缺一列 Create 就会失败——
		// 而失败正是本用例要复现的死循环入口，建表偷懒会把 bug 藏起来
		`CREATE TABLE alerts (
			tenant_id TEXT NOT NULL DEFAULT 't-default',
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			result_id TEXT NOT NULL UNIQUE,
			host_id TEXT, rule_id TEXT, policy_id TEXT, source TEXT,
			severity TEXT, category TEXT, title TEXT, description TEXT,
			expected TEXT, actual TEXT, fix_suggestion TEXT,
			status TEXT, mode TEXT, would_action TEXT,
			action TEXT, action_result TEXT,
			attck_tactic TEXT, attck_technique TEXT,
			risk_score REAL, hit_count INTEGER DEFAULT 0,
			notify_count INTEGER DEFAULT 0, last_notified_at DATETIME,
			resolve_reason TEXT, resolved_by TEXT, resolved_at DATETIME,
			first_seen_at DATETIME, last_seen_at DATETIME,
			created_at DATETIME, updated_at DATETIME
		)`,
	} {
		require.NoError(t, db.Exec(ddl).Error)
	}

	require.NoError(t, db.Exec(`INSERT INTO fim_policies (policy_id, escalation_timeout_min) VALUES ('p1', 60)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO fim_tasks (task_id, policy_id) VALUES ('t1','p1')`).Error)
	stale := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	require.NoError(t, db.Exec(
		`INSERT INTO fim_events (event_id, task_id, host_id, file_path, change_type, severity, category, status, detected_at)
		 VALUES ('ev-1','t1','h1','/etc/passwd','modify','high','integrity','pending',?)`, stale).Error)
	return db
}

func fimEventStatus(t *testing.T, db *gorm.DB, eventID string) string {
	t.Helper()
	var status string
	require.NoError(t, db.Raw(`SELECT status FROM fim_events WHERE event_id = ?`, eventID).Scan(&status).Error)
	return status
}

// TestEscalatePendingFIMEvents_MarksEscalated 正常路径：超时事件升级后状态推进
func TestEscalatePendingFIMEvents_MarksEscalated(t *testing.T) {
	db := setupFIMEscalationDB(t)

	EscalatePendingFIMEvents(db, zap.NewNop())

	require.Equal(t, "escalated", fimEventStatus(t, db, "ev-1"))

	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(1), alerts)
}

// TestEscalatePendingFIMEvents_RecoversFromExistingAlert 回归用例：
// 告警已存在但事件仍是 pending（历史上因写库失败留下的状态）。
// 修复前这里会因唯一键冲突而 continue，事件永远停在 pending，
// 每轮调度重新命中同一批 → 无限重试刷错误日志。
func TestEscalatePendingFIMEvents_RecoversFromExistingAlert(t *testing.T) {
	db := setupFIMEscalationDB(t)

	// 预置一条 result_id 冲突的告警，模拟"已升级但状态没落库"
	require.NoError(t, db.Exec(
		`INSERT INTO alerts (result_id, host_id, status) VALUES ('fim-escalation-ev-1','h1','active')`).Error)

	EscalatePendingFIMEvents(db, zap.NewNop())

	require.Equal(t, "escalated", fimEventStatus(t, db, "ev-1"),
		"告警已存在时必须补齐事件状态，否则形成无限重试")

	// 不得插入重复告警
	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(1), alerts)

	// alert_id 必须关联到已存在的那条
	var alertID int64
	require.NoError(t, db.Raw(`SELECT alert_id FROM fim_events WHERE event_id='ev-1'`).Scan(&alertID).Error)
	require.NotZero(t, alertID, "必须回填已存在告警的 ID")
}

// TestEscalatePendingFIMEvents_IsIdempotent 连跑两轮不产生重复告警、不回退状态
func TestEscalatePendingFIMEvents_IsIdempotent(t *testing.T) {
	db := setupFIMEscalationDB(t)

	EscalatePendingFIMEvents(db, zap.NewNop())
	EscalatePendingFIMEvents(db, zap.NewNop())

	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(1), alerts)
	require.Equal(t, "escalated", fimEventStatus(t, db, "ev-1"))
}

// insertFIMEvent 插入一条已超时的待升级事件。
func insertFIMEvent(t *testing.T, db *gorm.DB, eventID, hostID, filePath, changeType, severity string) {
	t.Helper()
	stale := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	require.NoError(t, db.Exec(
		`INSERT INTO fim_events (event_id, task_id, host_id, file_path, change_type, severity, category, status, detected_at)
		 VALUES (?,'t1',?,?,?,?,'binary','pending',?)`,
		eventID, hostID, filePath, changeType, severity, stale).Error)
}

// TestEscalatePendingFIMEvents_BatchesWidespreadChange 同一文件在足够多主机上
// 发生同种变更时合并为一条告警。
//
// 一次系统包更新会在每台主机上改写同一批二进制；逐条升级等于把一次运维操作
// 拆成成百上千条告警，真正的威胁就淹没在里面。
func TestEscalatePendingFIMEvents_BatchesWidespreadChange(t *testing.T) {
	db := setupFIMEscalationDB(t)
	require.NoError(t, db.Exec(`DELETE FROM fim_events`).Error)

	for i := 0; i < fimBatchHostThreshold; i++ {
		insertFIMEvent(t, db,
			fmt.Sprintf("ev-batch-%d", i), fmt.Sprintf("host-%d", i),
			"/usr/bin/systemctl", "changed", "critical")
	}

	EscalatePendingFIMEvents(db, zap.NewNop())

	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(1), alerts, "达到阈值的批量变更应合并为一条告警")

	var title string
	require.NoError(t, db.Raw(`SELECT title FROM alerts LIMIT 1`).Scan(&title).Error)
	require.Contains(t, title, fmt.Sprintf("%d 台主机", fimBatchHostThreshold),
		"标题要写明影响面，聚合不能让规模消失")

	// 每条事件都要推进并关联到那条告警，从任一主机都能追回来
	var stillPending int64
	require.NoError(t, db.Raw(`SELECT COUNT(*) FROM fim_events WHERE status='pending'`).Scan(&stillPending).Error)
	require.Zero(t, stillPending)
	var linked int64
	require.NoError(t, db.Raw(`SELECT COUNT(DISTINCT alert_id) FROM fim_events WHERE status='escalated'`).Scan(&linked).Error)
	require.Equal(t, int64(1), linked)
}

// TestEscalatePendingFIMEvents_BelowThresholdStaysIndividual 未达阈值仍逐条升级，
// 小范围变更不该被合并——那正是横向移动的样子。
func TestEscalatePendingFIMEvents_BelowThresholdStaysIndividual(t *testing.T) {
	db := setupFIMEscalationDB(t)
	require.NoError(t, db.Exec(`DELETE FROM fim_events`).Error)

	const n = 3
	for i := 0; i < n; i++ {
		insertFIMEvent(t, db,
			fmt.Sprintf("ev-few-%d", i), fmt.Sprintf("host-%d", i),
			"/usr/bin/curl", "changed", "critical")
	}

	EscalatePendingFIMEvents(db, zap.NewNop())

	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(n), alerts, "未达阈值应保持逐条告警")
}

// TestEscalatePendingFIMEvents_SuppressesSelfUpgrade 平台自身文件的变更不产生告警。
//
// 升级 agent 必然改写它自己的二进制，把这个报成完整性违规没有任何检测价值。
// 但状态必须推进，否则事件停在 pending，下一轮又被捞出来，变成无限重试。
func TestEscalatePendingFIMEvents_SuppressesSelfUpgrade(t *testing.T) {
	db := setupFIMEscalationDB(t)
	require.NoError(t, db.Exec(`DELETE FROM fim_events`).Error)

	insertFIMEvent(t, db, "ev-self-1", "h1", "/usr/bin/mxcwpp-agent", "changed", "critical")
	insertFIMEvent(t, db, "ev-self-2", "h2", "/opt/mxcwpp/plugins/fim", "changed", "critical")
	insertFIMEvent(t, db, "ev-other", "h3", "/etc/ssh/sshd_config", "changed", "high")

	EscalatePendingFIMEvents(db, zap.NewNop())

	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(1), alerts, "只有非自身路径的变更应产生告警")

	var suppressed int64
	require.NoError(t, db.Raw(`SELECT COUNT(*) FROM fim_events WHERE status='suppressed'`).Scan(&suppressed).Error)
	require.Equal(t, int64(2), suppressed, "自身路径事件应标为 suppressed 而非留在 pending")

	var stillPending int64
	require.NoError(t, db.Raw(`SELECT COUNT(*) FROM fim_events WHERE status='pending'`).Scan(&stillPending).Error)
	require.Zero(t, stillPending, "留在 pending 会让下一轮重新命中，形成无限重试")
}

// TestEscalatePendingFIMEvents_BatchIsIdempotent 批量告警跨轮次幂等：
// 事件分批超时时不会产生第二条聚合告警。
func TestEscalatePendingFIMEvents_BatchIsIdempotent(t *testing.T) {
	db := setupFIMEscalationDB(t)
	require.NoError(t, db.Exec(`DELETE FROM fim_events`).Error)

	for i := 0; i < fimBatchHostThreshold; i++ {
		insertFIMEvent(t, db,
			fmt.Sprintf("ev-idem-%d", i), fmt.Sprintf("host-%d", i),
			"/usr/bin/journalctl", "changed", "critical")
	}
	EscalatePendingFIMEvents(db, zap.NewNop())

	// 第二批同样的变更稍后才超时，应并进已有的那条
	for i := 0; i < fimBatchHostThreshold; i++ {
		insertFIMEvent(t, db,
			fmt.Sprintf("ev-idem2-%d", i), fmt.Sprintf("host2-%d", i),
			"/usr/bin/journalctl", "changed", "critical")
	}
	EscalatePendingFIMEvents(db, zap.NewNop())

	var alerts int64
	require.NoError(t, db.Model(&model.Alert{}).Count(&alerts).Error)
	require.Equal(t, int64(1), alerts, "同一天同一批变更应收敛到一条告警")
}

// TestEscalatePendingFIMEvents_CountsAlreadyEscalatedTowardBatchSize
// 判定批量规模时必须把此前轮次已升级的事件算进去。
//
// 同一次包更新在各主机上的检测时刻有先后，到期升级因而分散在多轮调度里。
// 若只数本轮捞到的 pending，先处理掉的那部分会让后来者看起来"没那么大范围"，
// 于是同一个文件既留下一堆单条告警、又生成一条聚合告警，两边都不完整。
func TestEscalatePendingFIMEvents_CountsAlreadyEscalatedTowardBatchSize(t *testing.T) {
	db := setupFIMEscalationDB(t)
	require.NoError(t, db.Exec(`DELETE FROM fim_events`).Error)

	const path = "/usr/bin/systemctl"
	stale := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")

	// 前几轮已经升级过的同批事件——它们证明这次变更的真实规模
	for i := 0; i < fimBatchHostThreshold; i++ {
		require.NoError(t, db.Exec(
			`INSERT INTO fim_events (event_id, task_id, host_id, file_path, change_type, severity, category, status, detected_at)
			 VALUES (?,'t1',?,?,'changed','critical','binary','escalated',?)`,
			fmt.Sprintf("ev-done-%d", i), fmt.Sprintf("host-d%d", i), path, stale).Error)
	}
	// 本轮才到期的少数几台，单看它们远不到阈值
	for i := 0; i < 3; i++ {
		require.NoError(t, db.Exec(
			`INSERT INTO fim_events (event_id, task_id, host_id, file_path, change_type, severity, category, status, detected_at)
			 VALUES (?,'t1',?,?,'changed','critical','binary','pending',?)`,
			fmt.Sprintf("ev-late-%d", i), fmt.Sprintf("host-l%d", i), path, stale).Error)
	}

	EscalatePendingFIMEvents(db, zap.NewNop())

	var batch, single int64
	require.NoError(t, db.Raw(
		`SELECT COUNT(*) FROM alerts WHERE result_id LIKE 'fim-escalation-batch-%'`).Scan(&batch).Error)
	require.NoError(t, db.Raw(
		`SELECT COUNT(*) FROM alerts WHERE result_id NOT LIKE 'fim-escalation-batch-%'`).Scan(&single).Error)

	require.Equal(t, int64(1), batch, "已知总规模超阈值时，迟到的这几台也该并入聚合")
	require.Zero(t, single, "不得因为本轮只捞到 3 台就退化成逐条告警")
}
