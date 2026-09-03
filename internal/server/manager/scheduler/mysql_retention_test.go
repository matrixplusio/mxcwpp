package scheduler

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func retentionDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开内存库失败: %v", err)
	}
	// 全部用裸 SQL 建表：retention_policies 的模型带 MySQL 专有的
	// ON UPDATE CURRENT_TIMESTAMP，sqlite 的 AutoMigrate 会在此报语法错。
	stmts := []string{
		`CREATE TABLE retention_policies (
			tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
			ch_table TEXT UNIQUE, display_name TEXT, description TEXT,
			retention_days INTEGER, updated_by TEXT,
			updated_at DATETIME, created_at DATETIME)`,
		`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, last_heartbeat DATETIME)`,
		`CREATE TABLE host_metrics (host_id TEXT, collected_at DATETIME)`,
		`CREATE TABLE audit_logs (created_at DATETIME)`,
	}
	for _, s := range stmts {
		if err := db.Exec(s).Error; err != nil {
			t.Fatalf("建表失败 %q: %v", s, err)
		}
	}
	return db
}

// TestPruneTable_DeletesOnlyExpired 只删过期行。
func TestPruneTable_DeletesOnlyExpired(t *testing.T) {
	db := retentionDB(t)
	now := time.Now()
	db.Exec(`INSERT INTO audit_logs (created_at) VALUES (?)`, now.AddDate(0, 0, -200))
	db.Exec(`INSERT INTO audit_logs (created_at) VALUES (?)`, now.AddDate(0, 0, -181))
	db.Exec(`INSERT INTO audit_logs (created_at) VALUES (?)`, now.AddDate(0, 0, -10))

	tgt := retentionTarget{Table: "audit_logs", TimeColumn: "created_at", FallbackDays: 180}
	stmt, args := pruneStatement(tgt, now.AddDate(0, 0, -180))
	res := db.Exec(stmt, args...)
	if res.Error != nil {
		t.Fatalf("清理失败: %v", res.Error)
	}
	if res.RowsAffected != 2 {
		t.Errorf("应删除 2 行超 180 天的记录，实际 %d", res.RowsAffected)
	}

	var left int64
	db.Raw(`SELECT COUNT(*) FROM audit_logs`).Scan(&left)
	if left != 1 {
		t.Errorf("保留期内的记录应留下 1 行，实际 %d", left)
	}
}

// TestPruneTable_KeepsDataOfHostsThatStoppedReporting 停报主机的历史必须原样保留。
//
// 这是本任务里最容易出事的地方：一台主机停止上报后，它的历史行会随时间全部
// 越过保留期，主机的最后已知状态就凭空消失了——而这类主机恰恰是出问题的那些，
// 排查时最需要它最后一刻的数据。限定只清理仍在上报的主机即可避免。
func TestPruneTable_KeepsDataOfHostsThatStoppedReporting(t *testing.T) {
	db := retentionDB(t)
	now := time.Now()

	// live 仍在上报；dead 一个月前就没动静了
	db.Exec(`INSERT INTO hosts (host_id, last_heartbeat) VALUES (?, ?)`, "live", now)
	db.Exec(`INSERT INTO hosts (host_id, last_heartbeat) VALUES (?, ?)`, "dead", now.AddDate(0, 0, -35))

	for _, h := range []string{"live", "dead"} {
		db.Exec(`INSERT INTO host_metrics (host_id, collected_at) VALUES (?, ?)`, h, now.AddDate(0, 0, -40))
		db.Exec(`INSERT INTO host_metrics (host_id, collected_at) VALUES (?, ?)`, h, now.AddDate(0, 0, -31))
	}

	tgt := retentionTarget{
		Table: "host_metrics", TimeColumn: "collected_at",
		FallbackDays: 30, ScopedToLiveHosts: true,
	}
	stmt, args := pruneStatement(tgt, now.AddDate(0, 0, -30))
	if err := db.Exec(stmt, args...).Error; err != nil {
		t.Fatalf("清理失败: %v", err)
	}

	var liveLeft, deadLeft int64
	db.Raw(`SELECT COUNT(*) FROM host_metrics WHERE host_id = 'live'`).Scan(&liveLeft)
	db.Raw(`SELECT COUNT(*) FROM host_metrics WHERE host_id = 'dead'`).Scan(&deadLeft)

	if liveLeft != 0 {
		t.Errorf("仍在上报的主机，过期行应被清理，实际剩 %d", liveLeft)
	}
	if deadLeft != 2 {
		t.Errorf("停报主机的历史必须原样保留（期望 2 行），实际剩 %d —— "+
			"删掉它等于抹去这台主机最后的已知状态", deadLeft)
	}
}

// TestPruneTable_RejectsNonPositiveRetention 保留天数为 0 或负数时必须报错而不是清空全表。
func TestPruneTable_RejectsNonPositiveRetention(t *testing.T) {
	db := retentionDB(t)
	db.Exec(`INSERT INTO audit_logs (created_at) VALUES (?)`, time.Now())

	tgt := retentionTarget{Table: "audit_logs", TimeColumn: "created_at"}
	for _, days := range []int{0, -1} {
		if _, err := pruneTable(db, tgt, days); err == nil {
			t.Errorf("保留天数 %d 应报错，否则 cutoff 会漂到未来把整表删空", days)
		}
	}

	var left int64
	db.Raw(`SELECT COUNT(*) FROM audit_logs`).Scan(&left)
	if left != 1 {
		t.Errorf("报错路径不得删除任何数据，实际剩 %d 行", left)
	}
}

// TestLoadRetentionDays_PolicyOverridesFallback 策略表里的天数优先于兜底值。
func TestLoadRetentionDays_PolicyOverridesFallback(t *testing.T) {
	db := retentionDB(t)
	db.Create(&model.RetentionPolicy{CHTable: "host_metrics", DisplayName: "主机指标", RetentionDays: 7})

	days := loadRetentionDays(db, zap.NewNop())
	if got := days["host_metrics"]; got != 7 {
		t.Errorf("应读到策略表里的 7 天，实际 %d", got)
	}
	if _, ok := days["not_configured"]; ok {
		t.Error("未配置的表不应出现在结果里，调用方据此回落兜底值")
	}
}

// TestRetentionTargets_ExcludeCurrentSnapshotTables 快照语义的表不得进清理白名单。
//
// 实测 kernel_modules 绝大多数主机只存在一个 collected_at——它是覆盖式的
// 当前快照，不是历史流水。按时间删等于直接抹掉资产数据，且除非主机重新上报否则不再生成。
// services 的每主机份数同样混杂（1~8）。这两张表要的是"每主机保留最近 N 份"，
// 与"删除 N 天前"不是同一个语义。
func TestRetentionTargets_ExcludeCurrentSnapshotTables(t *testing.T) {
	forbidden := map[string]string{
		"kernel_modules": "实测绝大多数主机仅有单个 collected_at，是当前快照",
		"services":       "每主机份数 1~8 混杂，语义不确定",
		"processes":      "快照语义未经确认",
	}
	for _, tgt := range mysqlRetentionTargets {
		if why, bad := forbidden[tgt.Table]; bad {
			t.Errorf("%s 不应按时间清理：%s。需要的是每主机保留最近 N 份的实现。", tgt.Table, why)
		}
	}
}

// TestRetentionTargets_HostScopedTablesAreConsistent 开了 ScopedToLiveHosts 的表
// 必须真的有 host 维度，否则 SQL 在运行时才炸。
func TestRetentionTargets_HostScopedTablesAreConsistent(t *testing.T) {
	// 事件流型的表按语义就不该开 ScopedToLiveHosts（见 mysqlRetentionTargets 注释）；
	// audit_logs 更是连 host_id 列都没有，开了会在运行时炸。
	hostless := map[string]bool{"audit_logs": true, "storyline_events": true, "fim_events": true}
	for _, tgt := range mysqlRetentionTargets {
		if tgt.ScopedToLiveHosts && hostless[tgt.Table] {
			t.Errorf("%s 无 host 维度，不能开 ScopedToLiveHosts", tgt.Table)
		}
		if tgt.TimeColumn == "" {
			t.Errorf("%s 缺 TimeColumn", tgt.Table)
		}
		if tgt.FallbackDays <= 0 {
			t.Errorf("%s 的 FallbackDays 必须为正，实际 %d", tgt.Table, tgt.FallbackDays)
		}
	}
}

// TestPruneTable_MySQLDialect 验证批处理用的 DELETE ... LIMIT 在真实 MySQL 上可执行。
// 不设 PROBE_DSN 时自动跳过。
//
//	PROBE_DSN='user:pass@tcp(127.0.0.1:3306)/mxcwpp?parseTime=True&loc=Local' \
//	    go test ./internal/server/manager/scheduler/ -run MySQLDialect
//
// 为什么必须跑真库：这是方言差异。sqlite 不支持 DELETE ... LIMIT（需编译期开关），
// 单测里只能验证 WHERE 语义；而分批本身正是 MySQL 侧防长事务锁表的关键，
// 语法写错要到生产上才炸。同类教训见 biz/kube_prune_mysql_test.go。
func TestPruneTable_MySQLDialect(t *testing.T) {
	dsn := os.Getenv("PROBE_DSN")
	if dsn == "" {
		t.Skip("未设置 PROBE_DSN，跳过 MySQL 方言验证")
	}
	db, err := gorm.Open(mysqldriver.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("连接 MySQL 失败: %v", err)
	}

	// 只读意义上的验证：删 0 天前……不行，那会删数据。
	// 改为对一张临时表执行完整语句，确认语法与批处理都成立。
	const tmp = "mxcwpp_retention_dialect_probe"
	db.Exec("DROP TABLE IF EXISTS " + tmp)
	if err := db.Exec("CREATE TABLE " + tmp + " (host_id VARCHAR(64), collected_at DATETIME)").Error; err != nil {
		t.Fatalf("建临时表失败: %v", err)
	}
	defer db.Exec("DROP TABLE IF EXISTS " + tmp)

	old := time.Now().AddDate(0, 0, -60)
	for i := range 3 {
		if err := db.Exec("INSERT INTO "+tmp+" (host_id, collected_at) VALUES (?, ?)",
			"probe", old.Add(time.Duration(i)*time.Minute)).Error; err != nil {
			t.Fatalf("插入失败: %v", err)
		}
	}

	tgt := retentionTarget{Table: tmp, TimeColumn: "collected_at", FallbackDays: 30}
	deleted, err := pruneTable(db, tgt, 30)
	if err != nil {
		t.Fatalf("DELETE ... LIMIT 在 MySQL 上失败: %v", err)
	}
	if deleted != 3 {
		t.Errorf("应删除 3 行，实际 %d", deleted)
	}
}
