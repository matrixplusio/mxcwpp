// Command etl-alerts-vulns-ch 一次性把 MySQL 的 alerts / vulnerabilities /
// host_vulnerabilities 三张表全量迁到 ClickHouse 对应表。
//
// 用法:
//
//	go run ./cmd/tools/etl-alerts-vulns-ch \
//	    -config /etc/mxsec-platform/server.yaml \
//	    -table all \
//	    -batch 5000
//
//	# 单表迁移
//	go run ./cmd/tools/etl-alerts-vulns-ch -config ... -table alerts
//	go run ./cmd/tools/etl-alerts-vulns-ch -config ... -table vulnerabilities
//	go run ./cmd/tools/etl-alerts-vulns-ch -config ... -table host_vulnerabilities
//
//	# 直接传 DSN（覆盖 config）
//	go run ./cmd/tools/etl-alerts-vulns-ch \
//	    -mysql-dsn "user:pass@tcp(host:3306)/mxsec?parseTime=true&loc=Local" \
//	    -ch-dsn   "clickhouse://user:pass@host:9000/mxsec" \
//	    -table all
//
// 迁移逻辑:
//   - 按 id 升序分批扫 MySQL（避免 OFFSET 慢查）
//   - 每批用 chConn.PrepareBatch 一次性 Append + Send
//   - 进度日志每 batch 输出 + 总进度
//   - 完成后对账 MySQL 总行数 vs CH 总行数
//
// 安全：仅 INSERT，不删 MySQL 数据；CH 端 ReplacingMergeTree 由 cve_id/(host_id,vuln_id)/result_id
// 作为去重 key，version=UnixNano 保证后写覆盖。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/database"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	tableAlerts    = "alerts"
	tableVulns     = "vulnerabilities"
	tableHostVulns = "host_vulnerabilities"
	tableAll       = "all"
)

func main() {
	configPath := flag.String("config", "", "配置文件路径（与 mysql-dsn/ch-dsn 二选一）")
	mysqlDSN := flag.String("mysql-dsn", "", "MySQL DSN（覆盖 config）")
	chDSN := flag.String("ch-dsn", "", "ClickHouse DSN，如 clickhouse://user:pass@host:9000/mxsec")
	table := flag.String("table", tableAll, "目标表: alerts / vulnerabilities / host_vulnerabilities / all")
	batchSize := flag.Int("batch", 5000, "每批扫描行数（默认 5000）")
	flag.Parse()

	switch *table {
	case tableAlerts, tableVulns, tableHostVulns, tableAll:
	default:
		log.Fatalf("非法 table: %s（合法值: alerts/vulnerabilities/host_vulnerabilities/all）", *table)
	}

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	db, chConn := connect(*configPath, *mysqlDSN, *chDSN, logger)

	startedAt := time.Now()
	results := map[string]migrateResult{}

	if *table == tableAlerts || *table == tableAll {
		results[tableAlerts] = migrateAlerts(db, chConn, *batchSize, logger)
	}
	if *table == tableVulns || *table == tableAll {
		results[tableVulns] = migrateVulns(db, chConn, *batchSize, logger)
	}
	if *table == tableHostVulns || *table == tableAll {
		results[tableHostVulns] = migrateHostVulns(db, chConn, *batchSize, logger)
	}

	fmt.Printf("\n=== ETL 完成 ===\n")
	fmt.Printf("总耗时: %s\n\n", time.Since(startedAt))
	mismatch := false
	for name, r := range results {
		mark := "OK"
		if int64(r.chTotal) < r.mysqlTotal {
			mark = "MISMATCH"
			mismatch = true
		}
		fmt.Printf("[%s] %s\n", mark, name)
		fmt.Printf("  MySQL 行数: %d\n", r.mysqlTotal)
		fmt.Printf("  CH 总行数:  %d\n", r.chTotal)
		fmt.Printf("  迁移条数:  %d\n", r.migrated)
		fmt.Printf("  耗时:      %s\n\n", r.elapsed)
	}
	if mismatch {
		os.Exit(2)
	}
}

type migrateResult struct {
	mysqlTotal int64
	chTotal    uint64
	migrated   uint64
	elapsed    time.Duration
}

// connect 初始化 MySQL + ClickHouse 连接。优先用 DSN，否则走 config 文件。
func connect(configPath, mysqlDSN, chDSN string, logger *zap.Logger) (*gorm.DB, chdriver.Conn) {
	var (
		db     *gorm.DB
		chConn chdriver.Conn
	)

	if mysqlDSN != "" {
		gdb, err := gorm.Open(mysql.Open(mysqlDSN), &gorm.Config{})
		if err != nil {
			logger.Fatal("MySQL 连接失败", zap.Error(err))
		}
		db = gdb
	}
	if chDSN != "" {
		opts, err := clickhouse.ParseDSN(chDSN)
		if err != nil {
			logger.Fatal("ClickHouse DSN 解析失败", zap.Error(err))
		}
		conn, err := clickhouse.Open(opts)
		if err != nil {
			logger.Fatal("ClickHouse 连接失败", zap.Error(err))
		}
		chConn = conn
	}

	if db != nil && chConn != nil {
		return db, chConn
	}

	if configPath == "" && (db == nil || chConn == nil) {
		logger.Fatal("必须提供 -config 或同时提供 -mysql-dsn + -ch-dsn")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatal("加载配置失败", zap.Error(err))
	}
	if db == nil {
		gdb, err := database.Init(cfg.Database, logger, cfg.Log)
		if err != nil {
			logger.Fatal("MySQL 连接失败", zap.Error(err))
		}
		db = gdb
	}
	if chConn == nil {
		if !cfg.ClickHouse.Enabled {
			logger.Fatal("ClickHouse 未启用，配置 clickhouse.enabled=true 后再运行")
		}
		conn, err := database.InitClickHouse(cfg.ClickHouse, logger)
		if err != nil {
			logger.Fatal("ClickHouse 连接失败", zap.Error(err))
		}
		if conn == nil {
			logger.Fatal("ClickHouse 连接为空")
		}
		chConn = conn
	}
	return db, chConn
}

// =========================== alerts ===========================

func migrateAlerts(db *gorm.DB, chConn chdriver.Conn, batchSize int, logger *zap.Logger) migrateResult {
	var total int64
	if err := db.Model(&model.Alert{}).Count(&total).Error; err != nil {
		logger.Fatal("MySQL alerts count 失败", zap.Error(err))
	}
	logger.Info("开始迁移 alerts", zap.Int64("mysql_total", total))

	startedAt := time.Now()
	lastID := uint64(0)
	migrated := uint64(0)
	batchNo := 0
	for {
		var rows []model.Alert
		if err := db.Where("id > ?", lastID).Order("id ASC").Limit(batchSize).Find(&rows).Error; err != nil {
			logger.Fatal("alerts MySQL 扫描失败", zap.Uint64("last_id", lastID), zap.Error(err))
		}
		if len(rows) == 0 {
			break
		}
		if err := insertAlertsCH(chConn, rows); err != nil {
			logger.Fatal("alerts CH 写入失败", zap.Uint64("last_id", lastID), zap.Error(err))
		}
		lastID = uint64(rows[len(rows)-1].ID)
		migrated += uint64(len(rows))
		batchNo++
		logger.Info("alerts 进度",
			zap.Int("batch", batchNo),
			zap.Uint64("migrated", migrated),
			zap.Int64("total", total),
			zap.Uint64("last_id", lastID),
		)
	}
	chTotal := countCH(chConn, tableAlerts, logger)
	return migrateResult{
		mysqlTotal: total, chTotal: chTotal, migrated: migrated, elapsed: time.Since(startedAt),
	}
}

func insertAlertsCH(conn chdriver.Conn, rows []model.Alert) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO alerts (
		id, result_id, host_id, rule_id, policy_id, source, severity, category,
		title, description, actual, expected, fix_suggestion, status,
		first_seen_at, last_seen_at, hit_count, last_notified_at, notify_count,
		resolved_at, resolved_by, resolve_reason, created_at, updated_at, version
	)`)
	if err != nil {
		return err
	}
	now := uint64(time.Now().UnixNano())
	for i, a := range rows {
		if err := batch.Append(
			uint64(a.ID), a.ResultID, a.HostID, a.RuleID, a.PolicyID, a.Source, a.Severity, a.Category,
			a.Title, a.Description, a.Actual, a.Expected, a.FixSuggestion, string(a.Status),
			time.Time(a.FirstSeenAt), time.Time(a.LastSeenAt), uint32(a.HitCount),
			asTime(a.LastNotifiedAt), uint32(a.NotifyCount),
			asTime(a.ResolvedAt), a.ResolvedBy, a.ResolveReason,
			time.Time(a.CreatedAt), time.Time(a.UpdatedAt), now+uint64(i),
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

// =========================== vulnerabilities ===========================

func migrateVulns(db *gorm.DB, chConn chdriver.Conn, batchSize int, logger *zap.Logger) migrateResult {
	var total int64
	if err := db.Unscoped().Model(&model.Vulnerability{}).Count(&total).Error; err != nil {
		logger.Fatal("MySQL vulnerabilities count 失败", zap.Error(err))
	}
	logger.Info("开始迁移 vulnerabilities", zap.Int64("mysql_total", total))

	startedAt := time.Now()
	lastID := uint64(0)
	migrated := uint64(0)
	batchNo := 0
	for {
		var rows []model.Vulnerability
		// Unscoped: 把 soft-deleted (deleted_at != null) 也迁过去，保留历史
		if err := db.Unscoped().Where("id > ?", lastID).Order("id ASC").Limit(batchSize).Find(&rows).Error; err != nil {
			logger.Fatal("vulnerabilities MySQL 扫描失败", zap.Uint64("last_id", lastID), zap.Error(err))
		}
		if len(rows) == 0 {
			break
		}
		if err := insertVulnsCH(chConn, rows); err != nil {
			logger.Fatal("vulnerabilities CH 写入失败", zap.Uint64("last_id", lastID), zap.Error(err))
		}
		lastID = uint64(rows[len(rows)-1].ID)
		migrated += uint64(len(rows))
		batchNo++
		logger.Info("vulnerabilities 进度",
			zap.Int("batch", batchNo),
			zap.Uint64("migrated", migrated),
			zap.Int64("total", total),
			zap.Uint64("last_id", lastID),
		)
	}
	chTotal := countCH(chConn, tableVulns, logger)
	return migrateResult{
		mysqlTotal: total, chTotal: chTotal, migrated: migrated, elapsed: time.Since(startedAt),
	}
}

func insertVulnsCH(conn chdriver.Conn, rows []model.Vulnerability) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO vulnerabilities (
		id, cve_id, osv_id, purl, severity, cvss_score, component, description,
		affected_hosts, patched_hosts, status, discovered_at, patched_at,
		current_version, fixed_version, reference_url,
		cvss_vector, attack_vector, vuln_type, affected_versions, source,
		patch_available, epss_score, cwe_id, confidence,
		vuln_category, restart_action, vuln_category_override, restart_action_override,
		cnvd_id, cnnvd_id, has_exploit, in_kev,
		created_at, updated_at, version
	)`)
	if err != nil {
		return err
	}
	now := uint64(time.Now().UnixNano())
	for i, v := range rows {
		if err := batch.Append(
			uint64(v.ID), v.CveID, v.OsvID, v.PURL, v.Severity, float32(v.CvssScore), v.Component, v.Description,
			uint32(v.AffectedHosts), uint32(v.PatchedHosts), v.Status,
			time.Time(v.DiscoveredAt), asTime(v.PatchedAt),
			v.CurrentVersion, v.FixedVersion, v.ReferenceUrl,
			v.CvssVector, v.AttackVector, v.VulnType, v.AffectedVersions, v.Source,
			boolU8(v.PatchAvailable), float32(v.EpssScore), v.CweID, v.Confidence,
			v.VulnCategory, v.RestartAction, v.VulnCategoryOverride, v.RestartActionOverride,
			v.CnvdID, v.CnnvdID, boolU8(v.HasExploit), boolU8(v.InKEV),
			time.Time(v.CreatedAt), time.Time(v.UpdatedAt), now+uint64(i),
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

// =========================== host_vulnerabilities ===========================

func migrateHostVulns(db *gorm.DB, chConn chdriver.Conn, batchSize int, logger *zap.Logger) migrateResult {
	var total int64
	if err := db.Model(&model.HostVulnerability{}).Count(&total).Error; err != nil {
		logger.Fatal("MySQL host_vulnerabilities count 失败", zap.Error(err))
	}
	logger.Info("开始迁移 host_vulnerabilities", zap.Int64("mysql_total", total))

	startedAt := time.Now()
	lastID := uint64(0)
	migrated := uint64(0)
	batchNo := 0
	for {
		var rows []model.HostVulnerability
		if err := db.Where("id > ?", lastID).Order("id ASC").Limit(batchSize).Find(&rows).Error; err != nil {
			logger.Fatal("host_vulnerabilities MySQL 扫描失败", zap.Uint64("last_id", lastID), zap.Error(err))
		}
		if len(rows) == 0 {
			break
		}
		if err := insertHostVulnsCH(chConn, rows); err != nil {
			logger.Fatal("host_vulnerabilities CH 写入失败", zap.Uint64("last_id", lastID), zap.Error(err))
		}
		lastID = uint64(rows[len(rows)-1].ID)
		migrated += uint64(len(rows))
		batchNo++
		logger.Info("host_vulnerabilities 进度",
			zap.Int("batch", batchNo),
			zap.Uint64("migrated", migrated),
			zap.Int64("total", total),
			zap.Uint64("last_id", lastID),
		)
	}
	chTotal := countCH(chConn, tableHostVulns, logger)
	return migrateResult{
		mysqlTotal: total, chTotal: chTotal, migrated: migrated, elapsed: time.Since(startedAt),
	}
}

func insertHostVulnsCH(conn chdriver.Conn, rows []model.HostVulnerability) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO host_vulnerabilities (
		id, vuln_id, host_id, hostname, ip, current_version, status, patched_at,
		precheck_status, precheck_message, precheck_packages, precheck_affected_processes,
		precheck_checked_at, created_at, updated_at, version
	)`)
	if err != nil {
		return err
	}
	now := uint64(time.Now().UnixNano())
	for i, h := range rows {
		if err := batch.Append(
			uint64(h.ID), uint64(h.VulnID), h.HostID, h.Hostname, h.IP, h.CurrentVersion, h.Status,
			asTime(h.PatchedAt),
			h.PreCheckStatus, h.PreCheckMessage, h.PreCheckPackages, h.PreCheckAffectedProcesses,
			asTime(h.PreCheckCheckedAt),
			time.Time(h.CreatedAt), time.Time(h.UpdatedAt), now+uint64(i),
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

// =========================== helpers ===========================

// countCH 查询 CH 表当前行数（去重前粗略 count，含未 merge 的副本）。
func countCH(conn chdriver.Conn, table string, logger *zap.Logger) uint64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n uint64
	if err := conn.QueryRow(ctx, fmt.Sprintf("SELECT count() FROM %s FINAL", table)).Scan(&n); err != nil {
		logger.Warn("CH count 失败", zap.String("table", table), zap.Error(err))
		return 0
	}
	return n
}

// asTime 把 *LocalTime 转 time.Time，nil 时返回零值。
func asTime(t *model.LocalTime) time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Time(*t)
}

// boolU8 bool → UInt8。
func boolU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
