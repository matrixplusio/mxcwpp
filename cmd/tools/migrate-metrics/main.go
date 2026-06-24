// migrate-metrics 将 MySQL host_metrics 历史数据迁移到 ClickHouse
//
// 字段映射：
//
//	MySQL                  ClickHouse
//	------                 ----------
//	host_id           →    host_id
//	collected_at      →    timestamp
//	cpu_usage         →    cpu_usage
//	mem_usage         →    mem_usage
//	disk_usage        →    disk_usage
//	net_bytes_sent    →    net_out
//	net_bytes_recv    →    net_in
//	(无)              →    hostname   = ""
//	(无)              →    load_1/5/15 = 0
//
// 用法：
//
//	go run ./cmd/tools/migrate-metrics \
//	  --mysql-dsn "user:pass@tcp(127.0.0.1:3306)/mxcwpp?parseTime=true&loc=Asia%2FShanghai" \
//	  --clickhouse-addr "127.0.0.1:9000" \
//	  --clickhouse-db mxcwpp \
//	  --batch-size 5000 \
//	  --since "2025-01-01T00:00:00+08:00" \
//	  --dry-run
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	_ "github.com/go-sql-driver/mysql"
)

var (
	mysqlDSN    = flag.String("mysql-dsn", "", "MySQL DSN（必填）")
	chAddr      = flag.String("clickhouse-addr", "127.0.0.1:9000", "ClickHouse 原生协议地址")
	chDB        = flag.String("clickhouse-db", "mxcwpp", "ClickHouse 数据库名")
	chUser      = flag.String("clickhouse-user", "default", "ClickHouse 用户名")
	chPass      = flag.String("clickhouse-pass", "", "ClickHouse 密码")
	batchSize   = flag.Int("batch-size", 5000, "每批读取/写入行数")
	sinceStr    = flag.String("since", "", "仅迁移该时间之后的数据（RFC3339 格式，留空则全量）")
	dryRun      = flag.Bool("dry-run", false, "仅统计行数，不写入 ClickHouse")
	dialTimeout = flag.Duration("dial-timeout", 10*time.Second, "数据库连接超时")
)

// mysqlRow 对应 MySQL host_metrics 一行
type mysqlRow struct {
	HostID       string
	CPUUsage     float64
	MemUsage     float64
	DiskUsage    float64
	NetBytesSent uint64
	NetBytesRecv uint64
	CollectedAt  time.Time
}

func main() {
	flag.Parse()

	if *mysqlDSN == "" {
		log.Fatal("--mysql-dsn 为必填参数")
	}

	var since time.Time
	if *sinceStr != "" {
		var err error
		since, err = time.Parse(time.RFC3339, *sinceStr)
		if err != nil {
			log.Fatalf("--since 格式错误（需 RFC3339，如 2025-01-01T00:00:00+08:00）: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("收到终止信号，正在停止...")
		cancel()
	}()

	// 连接 MySQL
	log.Println("连接 MySQL...")
	mysqlDB, err := sql.Open("mysql", *mysqlDSN)
	if err != nil {
		log.Fatalf("MySQL 连接失败: %v", err)
	}
	defer mysqlDB.Close()

	pingCtx, pingCancel := context.WithTimeout(ctx, *dialTimeout)
	defer pingCancel()
	if err := mysqlDB.PingContext(pingCtx); err != nil {
		log.Fatalf("MySQL Ping 失败: %v", err)
	}
	log.Println("MySQL 连接成功")

	// 连接 ClickHouse
	var chConn chdriver.Conn
	if !*dryRun {
		log.Println("连接 ClickHouse...")
		chConn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{*chAddr},
			Auth: clickhouse.Auth{
				Database: *chDB,
				Username: *chUser,
				Password: *chPass,
			},
			DialTimeout:  *dialTimeout,
			MaxOpenConns: 5,
		})
		if err != nil {
			log.Fatalf("ClickHouse 连接失败: %v", err)
		}
		defer chConn.Close()
		if err := chConn.Ping(ctx); err != nil {
			log.Fatalf("ClickHouse Ping 失败: %v", err)
		}
		log.Println("ClickHouse 连接成功")
	}

	start := time.Now()
	total, migrated, errCount := run(ctx, mysqlDB, chConn, since)
	elapsed := time.Since(start)

	printReport(total, migrated, errCount, elapsed)
	if errCount > 0 {
		os.Exit(1)
	}
}

// run 执行分批迁移，返回（总行数, 已迁移行数, 错误行数）
func run(ctx context.Context, mysqlDB *sql.DB, chConn chdriver.Conn, since time.Time) (total, migrated, errCount int64) {
	// 统计总行数
	countSQL := "SELECT COUNT(*) FROM host_metrics"
	args := []any{}
	if !since.IsZero() {
		countSQL += " WHERE collected_at >= ?"
		args = append(args, since)
	}

	if err := mysqlDB.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		log.Printf("统计总行数失败: %v", err)
		total = -1
	}
	if total == 0 {
		log.Println("MySQL 中无符合条件的数据，退出")
		return
	}
	if total > 0 {
		log.Printf("待迁移行数: %d", total)
	}

	// 分批游标查询（使用 id 作为翻页游标，避免 OFFSET 大表性能问题）
	querySQL := buildQuery(since)

	var lastID uint64
	batchNum := 0

	for {
		if ctx.Err() != nil {
			log.Println("迁移被中断")
			break
		}

		rows, err := mysqlDB.QueryContext(ctx, querySQL, append([]any{lastID}, args...)...)
		if err != nil {
			log.Printf("查询 MySQL 失败（lastID=%d）: %v", lastID, err)
			errCount++
			break
		}

		batch, maxID, n := scanRows(rows)
		rows.Close()

		if n == 0 {
			break // 全部迁移完毕
		}

		batchNum++
		log.Printf("[Batch %d] 读取 %d 行（lastID=%d → %d）", batchNum, n, lastID, maxID)

		if *dryRun {
			migrated += int64(n)
		} else {
			written, batchErr := writeBatch(ctx, chConn, batch)
			migrated += int64(written)
			if batchErr != nil {
				log.Printf("[Batch %d] 写入 ClickHouse 部分失败: %v", batchNum, batchErr)
				errCount++
			}
		}

		lastID = maxID
		if n < *batchSize {
			break // 最后一批
		}
	}

	return
}

func buildQuery(since time.Time) string {
	q := `SELECT id, host_id,
		COALESCE(cpu_usage, 0),
		COALESCE(mem_usage, 0),
		COALESCE(disk_usage, 0),
		COALESCE(net_bytes_sent, 0),
		COALESCE(net_bytes_recv, 0),
		collected_at
	FROM host_metrics
	WHERE id > ?`
	if !since.IsZero() {
		q += " AND collected_at >= ?"
	}
	q += fmt.Sprintf(" ORDER BY id ASC LIMIT %d", *batchSize)
	return q
}

func scanRows(rows *sql.Rows) (batch []mysqlRow, maxID uint64, n int) {
	for rows.Next() {
		var id uint64
		var r mysqlRow
		if err := rows.Scan(&id, &r.HostID, &r.CPUUsage, &r.MemUsage, &r.DiskUsage,
			&r.NetBytesSent, &r.NetBytesRecv, &r.CollectedAt); err != nil {
			log.Printf("Scan 行失败: %v", err)
			continue
		}
		batch = append(batch, r)
		if id > maxID {
			maxID = id
		}
		n++
	}
	return
}

// writeBatch 将一批行批量写入 ClickHouse，返回成功写入行数
func writeBatch(ctx context.Context, conn chdriver.Conn, batch []mysqlRow) (int, error) {
	b, err := conn.PrepareBatch(ctx, "INSERT INTO host_metrics (timestamp, host_id, hostname, cpu_usage, mem_usage, disk_usage, load_1, load_5, load_15, net_in, net_out)")
	if err != nil {
		return 0, fmt.Errorf("PrepareBatch 失败: %w", err)
	}

	for _, r := range batch {
		if err := b.Append(
			r.CollectedAt, // timestamp
			r.HostID,      // host_id
			"",            // hostname（MySQL 无此字段）
			float32(r.CPUUsage),
			float32(r.MemUsage),
			float32(r.DiskUsage),
			float32(0),     // load_1
			float32(0),     // load_5
			float32(0),     // load_15
			r.NetBytesRecv, // net_in  = bytes received
			r.NetBytesSent, // net_out = bytes sent
		); err != nil {
			// Append 失败整批作废
			return 0, fmt.Errorf("Append 失败: %w", err)
		}
	}

	if err := b.Send(); err != nil {
		return 0, fmt.Errorf("Send 失败: %w", err)
	}
	return len(batch), nil
}

func printReport(total, migrated, errCount int64, elapsed time.Duration) {
	fmt.Println("\n========== 迁移报告 ==========")
	if total >= 0 {
		fmt.Printf("MySQL 总行数  : %d\n", total)
	}
	fmt.Printf("已迁移行数  : %d\n", migrated)
	fmt.Printf("错误批次数  : %d\n", errCount)
	fmt.Printf("耗时        : %v\n", elapsed.Round(time.Millisecond))
	if elapsed.Seconds() > 0 && migrated > 0 {
		fmt.Printf("平均速率    : %.0f 行/s\n", float64(migrated)/elapsed.Seconds())
	}
	if *dryRun {
		fmt.Println("模式        : DRY RUN（未写入 ClickHouse）")
	}
	fmt.Println("==============================")

	if errCount > 0 {
		fmt.Println("[警告] 存在写入错误，请检查 ClickHouse 日志并重新运行（支持断点续传：调大 --since）")
	}
}
