// Package service 提供 AgentCenter 业务逻辑
package service

import (
	"context"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// MetricsBuffer 监控指标缓冲区（批量插入优化）。
//
// 写入路径由 target 决定:
//   - "mysql"（默认）→ host_metrics 表 (GORM CreateInBatches)
//   - "ch"            → ClickHouse mxsec.host_metrics (PrepareBatch)
//
// chConn 为 nil 或 target 非 "ch" 时一律走 MySQL。
type MetricsBuffer struct {
	buffer        []*model.HostMetric
	mu            sync.Mutex
	maxSize       int
	flushInterval time.Duration
	db            *gorm.DB
	chConn        chdriver.Conn // 可为 nil
	target        string        // "mysql" / "ch"
	logger        *zap.Logger
	stopCh        chan struct{}
}

// NewMetricsBuffer 创建新的指标缓冲区，默认写 MySQL。
// 启用 CH 写入需后续调 SetClickHouse(conn, "ch")。
func NewMetricsBuffer(db *gorm.DB, logger *zap.Logger, maxSize int, flushInterval time.Duration) *MetricsBuffer {
	buf := &MetricsBuffer{
		buffer:        make([]*model.HostMetric, 0, maxSize),
		maxSize:       maxSize,
		flushInterval: flushInterval,
		db:            db,
		target:        "mysql",
		logger:        logger,
		stopCh:        make(chan struct{}),
	}

	// 启动定期刷新 goroutine
	go buf.startFlushLoop()

	return buf
}

// SetClickHouse 注入 CH 连接并切换写入目标。
// target = "ch" 启用 CH 写入；其它值（含空）回落 mysql。
func (b *MetricsBuffer) SetClickHouse(conn chdriver.Conn, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.chConn = conn
	if target == "ch" {
		b.target = "ch"
	} else {
		b.target = "mysql"
	}
}

// Add 添加指标到缓冲区
func (b *MetricsBuffer) Add(metric *model.HostMetric) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buffer = append(b.buffer, metric)

	// 如果缓冲区满了，立即刷新
	if len(b.buffer) >= b.maxSize {
		return b.flushLocked()
	}

	return nil
}

// flushLocked 刷新缓冲区（需要先获取锁）
func (b *MetricsBuffer) flushLocked() error {
	if len(b.buffer) == 0 {
		return nil
	}

	// 按 target 路由
	if b.target == "ch" && b.chConn != nil {
		if err := b.flushCHLocked(); err != nil {
			b.logger.Warn("CH flush 失败，回落 MySQL", zap.Error(err))
			if err := b.flushMySQLLocked(); err != nil {
				return err
			}
		}
	} else {
		if err := b.flushMySQLLocked(); err != nil {
			return err
		}
	}

	b.logger.Debug("flushed metrics buffer",
		zap.Int("count", len(b.buffer)), zap.String("target", b.target))
	b.buffer = b.buffer[:0]
	return nil
}

// flushMySQLLocked 批量写 MySQL host_metrics。
func (b *MetricsBuffer) flushMySQLLocked() error {
	batchSize := 100
	for i := 0; i < len(b.buffer); i += batchSize {
		end := i + batchSize
		if end > len(b.buffer) {
			end = len(b.buffer)
		}
		batch := b.buffer[i:end]
		if err := b.db.CreateInBatches(batch, batchSize).Error; err != nil {
			b.logger.Error("failed to insert metrics batch (MySQL)",
				zap.Error(err), zap.Int("batch_size", len(batch)))
			return err
		}
	}
	return nil
}

// flushCHLocked 批量写 ClickHouse mxsec.host_metrics。
func (b *MetricsBuffer) flushCHLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch, err := b.chConn.PrepareBatch(ctx,
		"INSERT INTO host_metrics (timestamp, host_id, hostname, cpu_usage, mem_usage, disk_usage, load_1, load_5, load_15, net_in, net_out, disk_read_bytes, disk_write_bytes)")
	if err != nil {
		return err
	}
	for _, m := range b.buffer {
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
			ts,
			m.HostID,
			"", // hostname 当前 model 没存，留空
			cpu, mem, disk,
			float32(0), float32(0), float32(0), // load_1/5/15 (model 也没字段)
			netIn, netOut, dRead, dWrite,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

// Flush 手动刷新缓冲区
func (b *MetricsBuffer) Flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flushLocked()
}

// startFlushLoop 启动定期刷新循环
func (b *MetricsBuffer) startFlushLoop() {
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			// 停止时刷新剩余数据
			b.Flush()
			return
		case <-ticker.C:
			b.Flush()
		}
	}
}

// Stop 停止缓冲区
func (b *MetricsBuffer) Stop() {
	close(b.stopCh)
}
