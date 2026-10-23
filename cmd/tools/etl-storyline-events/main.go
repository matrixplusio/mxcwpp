// Command etl-storyline-events 一次性把 MySQL storyline_events 全表迁到
// ClickHouse mxcwpp.storyline_events。
//
// 用法:
//
//	go run ./cmd/tools/etl-storyline-events -config /etc/mxcwpp/server.yaml
//	# 可选: -batch 10000 -from-id 0 -dry-run
//
// 迁移逻辑:
//   - 按 id 升序分批扫 MySQL（避免 OFFSET 慢查）
//   - 每批转换为 CH 行并 PrepareBatch + Send
//   - 进度日志每 100k 行一次
//   - 失败时输出最后已迁 id，可 -from-id 续跑
//   - 完成后对账 row count
//
// 安全：
//   - 仅 INSERT，不删 MySQL 数据
//   - CH 端用 INSERT (MergeTree 重复主键不去重，需保证 -from-id 续跑准确)
//   - 完成后由人工/调度操作 RENAME / DROP MySQL 表
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/database"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func main() {
	configPath := flag.String("config", "", "配置文件路径（默认: ./configs/server.yaml）")
	batchSize := flag.Int("batch", 10000, "每批扫描行数（默认 10000）")
	fromID := flag.Uint64("from-id", 0, "续跑起点 id（仅迁 id > from-id 的行）")
	dryRun := flag.Bool("dry-run", false, "只统计不迁移")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	db, err := database.Init(cfg.Database, logger, cfg.Log)
	if err != nil {
		logger.Fatal("MySQL 连接失败", zap.Error(err))
	}

	if !cfg.ClickHouse.Enabled {
		logger.Fatal("ClickHouse 未启用，配置 clickhouse.enabled=true 后再运行")
	}
	chConn, err := database.InitClickHouse(cfg.ClickHouse, logger)
	if err != nil {
		logger.Fatal("ClickHouse 连接失败", zap.Error(err))
	}
	if chConn == nil {
		logger.Fatal("ClickHouse 连接为空")
	}

	// 1. 对账：MySQL 总行数
	var mysqlTotal int64
	if err := db.Model(&model.StorylineEvent{}).Count(&mysqlTotal).Error; err != nil {
		logger.Fatal("MySQL count 失败", zap.Error(err))
	}
	logger.Info("MySQL 源数据", zap.Int64("total", mysqlTotal))

	// 2. 对账：CH 已有行数
	chCount, err := chRowCount(chConn)
	if err != nil {
		logger.Warn("CH count 失败（表可能未建）", zap.Error(err))
	}
	logger.Info("CH 当前数据", zap.Uint64("count", chCount))

	if *dryRun {
		fmt.Printf("\n[dry-run] MySQL %d 行 → CH 已有 %d 行 → 待迁 ~%d 行\n",
			mysqlTotal, chCount, uint64(mysqlTotal)-chCount)
		return
	}

	// 3. 分批迁移
	lastID := *fromID
	totalMigrated := uint64(0)
	startedAt := time.Now()

	for {
		var rows []model.StorylineEvent
		if err := db.Where("id > ?", lastID).
			Order("id ASC").
			Limit(*batchSize).
			Find(&rows).Error; err != nil {
			logger.Fatal("MySQL 扫描失败",
				zap.Uint64("last_id", lastID), zap.Error(err))
		}
		if len(rows) == 0 {
			break
		}

		if err := insertCH(chConn, rows); err != nil {
			logger.Fatal("CH 写入失败",
				zap.Uint64("last_id", lastID),
				zap.Int("batch_size", len(rows)),
				zap.Error(err))
		}
		lastID = uint64(rows[len(rows)-1].ID)
		totalMigrated += uint64(len(rows))

		// 100k 行一次进度日志
		if totalMigrated%100000 < uint64(*batchSize) {
			elapsed := time.Since(startedAt)
			rate := float64(totalMigrated) / elapsed.Seconds()
			logger.Info("ETL 进度",
				zap.Uint64("migrated", totalMigrated),
				zap.Uint64("last_id", lastID),
				zap.Float64("rate_per_sec", rate),
				zap.Duration("elapsed", elapsed))
		}
	}

	// 4. 完成对账
	chFinal, _ := chRowCount(chConn)
	elapsed := time.Since(startedAt)
	logger.Info("ETL 完成",
		zap.Uint64("migrated", totalMigrated),
		zap.Uint64("ch_total", chFinal),
		zap.Int64("mysql_total", mysqlTotal),
		zap.Uint64("last_id", lastID),
		zap.Duration("elapsed", elapsed))

	fmt.Printf("\n✓ ETL 完成\n")
	fmt.Printf("  迁移行数: %d\n", totalMigrated)
	fmt.Printf("  CH 总行数: %d (含历史)\n", chFinal)
	fmt.Printf("  MySQL 行数: %d\n", mysqlTotal)
	fmt.Printf("  最后 ID:   %d\n", lastID)
	fmt.Printf("  耗时:     %s\n", elapsed)
	if int64(chFinal) < mysqlTotal {
		fmt.Printf("\n⚠️ CH 行数 < MySQL，可能有迁移遗漏，建议带 -from-id=%d 续跑\n", lastID)
		os.Exit(2)
	}
}

// chRowCount 查 CH storyline_events 总行数。
func chRowCount(conn chdriver.Conn) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n uint64
	if err := conn.QueryRow(ctx, "SELECT count() FROM storyline_events").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// insertCH 批量写一组 events 到 CH。
func insertCH(conn chdriver.Conn, rows []model.StorylineEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	batch, err := conn.PrepareBatch(ctx,
		"INSERT INTO storyline_events (id, story_id, host_id, data_type, event_type, pid, exe, detail, rule_name, severity, timestamp, created_at)")
	if err != nil {
		return err
	}
	for _, ev := range rows {
		ts := time.Time(ev.Timestamp)
		ct := time.Time(ev.CreatedAt)
		if ts.IsZero() {
			ts = time.Now()
		}
		if ct.IsZero() {
			ct = ts
		}
		if err := batch.Append(
			uint64(ev.ID),
			ev.StoryID, ev.HostID,
			ev.DataType, ev.EventType,
			ev.PID, ev.Exe, ev.Detail, ev.RuleName, ev.Severity,
			ts, ct,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}
