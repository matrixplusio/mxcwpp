// Command etl-host-metrics 把 MySQL host_metrics 全表迁到 ClickHouse mxsec.host_metrics。
//
// 用法:
//
//	go run ./cmd/tools/etl-host-metrics -config /etc/mxsec-platform/server.yaml
//	# 可选: -batch 10000 -from-id 0 -dry-run
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

	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/database"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

func main() {
	configPath := flag.String("config", "", "配置文件路径")
	batchSize := flag.Int("batch", 10000, "每批扫描行数")
	fromID := flag.Uint64("from-id", 0, "续跑起点 id")
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
		logger.Fatal("ClickHouse 未启用")
	}
	chConn, err := database.InitClickHouse(cfg.ClickHouse, logger)
	if err != nil {
		logger.Fatal("ClickHouse 连接失败", zap.Error(err))
	}

	var mysqlTotal int64
	if err := db.Model(&model.HostMetric{}).Count(&mysqlTotal).Error; err != nil {
		logger.Fatal("MySQL count 失败", zap.Error(err))
	}
	logger.Info("MySQL 源数据", zap.Int64("total", mysqlTotal))

	chCount, _ := chRowCount(chConn)
	logger.Info("CH 当前数据", zap.Uint64("count", chCount))

	if *dryRun {
		fmt.Printf("\n[dry-run] MySQL %d → CH 已有 %d → 待迁 ~%d\n",
			mysqlTotal, chCount, uint64(mysqlTotal)-chCount)
		return
	}

	lastID := *fromID
	totalMigrated := uint64(0)
	startedAt := time.Now()

	for {
		var rows []model.HostMetric
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
				zap.Int("batch", len(rows)),
				zap.Error(err))
		}
		lastID = uint64(rows[len(rows)-1].ID)
		totalMigrated += uint64(len(rows))

		if totalMigrated%200000 < uint64(*batchSize) {
			elapsed := time.Since(startedAt)
			rate := float64(totalMigrated) / elapsed.Seconds()
			logger.Info("ETL 进度",
				zap.Uint64("migrated", totalMigrated),
				zap.Uint64("last_id", lastID),
				zap.Float64("rate_per_sec", rate),
				zap.Duration("elapsed", elapsed))
		}
	}

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
	fmt.Printf("  CH 总:    %d\n", chFinal)
	fmt.Printf("  MySQL:    %d\n", mysqlTotal)
	fmt.Printf("  最后 ID:  %d\n", lastID)
	fmt.Printf("  耗时:     %s\n", elapsed)
	if int64(chFinal) < mysqlTotal {
		fmt.Printf("\n⚠️ CH < MySQL，可 -from-id=%d 续跑\n", lastID)
		os.Exit(2)
	}
}

func chRowCount(conn chdriver.Conn) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n uint64
	if err := conn.QueryRow(ctx, "SELECT count() FROM host_metrics").Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func insertCH(conn chdriver.Conn, rows []model.HostMetric) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	batch, err := conn.PrepareBatch(ctx,
		"INSERT INTO host_metrics (timestamp, host_id, hostname, cpu_usage, mem_usage, disk_usage, load_1, load_5, load_15, net_in, net_out, disk_read_bytes, disk_write_bytes)")
	if err != nil {
		return err
	}
	for _, m := range rows {
		var cpu, mem, disk float32
		if m.CPUUsage != nil {
			cpu = float32(*m.CPUUsage)
		}
		if m.MemUsage != nil {
			mem = float32(*m.MemUsage)
		}
		if m.DiskUsage != nil {
			disk = float32(*m.DiskUsage)
		}
		var netIn, netOut, dRead, dWrite uint64
		if m.NetBytesRecv != nil {
			netIn = *m.NetBytesRecv
		}
		if m.NetBytesSent != nil {
			netOut = *m.NetBytesSent
		}
		ts := time.Time(m.CollectedAt)
		if ts.IsZero() {
			ts = time.Now()
		}
		if err := batch.Append(
			ts, m.HostID, "",
			cpu, mem, disk,
			float32(0), float32(0), float32(0),
			netIn, netOut, dRead, dWrite,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}
