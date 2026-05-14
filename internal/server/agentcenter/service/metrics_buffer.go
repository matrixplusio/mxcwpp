// Package service 提供 AgentCenter 业务逻辑
package service

import (
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// MetricsBuffer 监控指标缓冲区（批量插入优化）
type MetricsBuffer struct {
	buffer        []*model.HostMetric
	mu            sync.Mutex
	maxSize       int
	flushInterval time.Duration
	db            *gorm.DB
	logger        *zap.Logger
	stopCh        chan struct{}
}

// NewMetricsBuffer 创建新的指标缓冲区
func NewMetricsBuffer(db *gorm.DB, logger *zap.Logger, maxSize int, flushInterval time.Duration) *MetricsBuffer {
	buf := &MetricsBuffer{
		buffer:        make([]*model.HostMetric, 0, maxSize),
		maxSize:       maxSize,
		flushInterval: flushInterval,
		db:            db,
		logger:        logger,
		stopCh:        make(chan struct{}),
	}

	// 启动定期刷新 goroutine
	go buf.startFlushLoop()

	return buf
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

	// 批量插入（每批 100 条）
	batchSize := 100
	for i := 0; i < len(b.buffer); i += batchSize {
		end := i + batchSize
		if end > len(b.buffer) {
			end = len(b.buffer)
		}

		batch := b.buffer[i:end]
		if err := b.db.CreateInBatches(batch, batchSize).Error; err != nil {
			b.logger.Error("failed to insert metrics batch", zap.Error(err), zap.Int("batch_size", len(batch)))
			return err
		}
	}

	b.logger.Debug("flushed metrics buffer", zap.Int("count", len(b.buffer)))
	b.buffer = b.buffer[:0]

	return nil
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
