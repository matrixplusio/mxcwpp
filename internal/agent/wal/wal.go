// Package wal provides a Write-Ahead Log for EDR events.
// When the ring buffer is full or the gRPC connection is down,
// events are persisted to disk and replayed on reconnection.
//
// File format: sequence of [4-byte big-endian length][protobuf EncodedRecord].
// Entries are append-only. After successful replay, the WAL file is truncated.
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

// P2-1: WAL record buffer pool 减 per-record make([]byte) GC 压力.
//
// 高 EPS 场景 (10k events/s) 累计每秒 10k 个 []byte alloc → GC 压力大.
// 用 sync.Pool 复用 4KB 起步 buffer, 大 record (>4KB) 走原路径 (不还池).
var walBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4096)
		return &buf
	},
}

// getWALBuf 取池化 buffer (cap >= want), 不够 cap 直接 make.
func getWALBuf(want int) []byte {
	if want > 64*1024 {
		// 大 record 不走池, 防 oversized buffer 滞留池
		return make([]byte, want)
	}
	p := walBufPool.Get().(*[]byte)
	if cap(*p) < want {
		*p = make([]byte, want)
	}
	return (*p)[:want]
}

// putWALBuf 还池 (仅小 buffer).
func putWALBuf(buf []byte) {
	if cap(buf) > 64*1024 {
		return
	}
	walBufPool.Put(&buf)
}

const (
	// DefaultMaxSize is the maximum WAL file size (200MB).
	DefaultMaxSize int64 = 200 * 1024 * 1024

	// walFileName is the WAL file name.
	walFileName = "edr-events.wal"

	// headerSize is the 4-byte length prefix per entry.
	headerSize = 4

	// maxRecordSize is the maximum single record size (1MB).
	maxRecordSize = 1 * 1024 * 1024
)

// WAL is an append-only write-ahead log for EDR event records.
type WAL struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
	maxSize  int64
	curSize  int64
	logger   *zap.Logger

	// Stats.
	written  uint64
	replayed uint64
	dropped  uint64
}

// New creates a new WAL instance. walDir is the directory for the WAL file.
func New(walDir string, maxSize int64, logger *zap.Logger) (*WAL, error) {
	if err := os.MkdirAll(walDir, 0755); err != nil {
		return nil, fmt.Errorf("create WAL dir: %w", err)
	}

	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}

	filePath := filepath.Join(walDir, walFileName)

	// Open or create the WAL file (append mode).
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open WAL file: %w", err)
	}

	// Get current file size.
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat WAL file: %w", err)
	}

	w := &WAL{
		file:     f,
		filePath: filePath,
		maxSize:  maxSize,
		curSize:  info.Size(),
		logger:   logger,
	}

	if w.curSize > 0 {
		logger.Info("WAL file contains unreplayed events",
			zap.String("path", filePath),
			zap.Int64("size_bytes", w.curSize))
	}

	return w, nil
}

// Write appends an EncodedRecord to the WAL file.
// Returns false if the WAL is full (record dropped).
func (w *WAL) Write(record *grpcProto.EncodedRecord) bool {
	data, err := proto.Marshal(record)
	if err != nil {
		w.logger.Warn("WAL: failed to marshal record", zap.Error(err))
		return false
	}

	entrySize := int64(headerSize + len(data))

	w.mu.Lock()
	defer w.mu.Unlock()

	// Check size limit.
	if w.curSize+entrySize > w.maxSize {
		w.dropped++
		return false
	}

	// Write length prefix (big-endian uint32).
	var header [headerSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))

	if _, err := w.file.Write(header[:]); err != nil {
		w.logger.Warn("WAL: write header failed", zap.Error(err))
		return false
	}

	if _, err := w.file.Write(data); err != nil {
		w.logger.Warn("WAL: write data failed", zap.Error(err))
		return false
	}

	w.curSize += entrySize
	w.written++

	return true
}

// Replay reads all entries from the WAL and calls the handler for each batch.
// After successful replay, the WAL file is truncated.
// batchSize controls how many records are batched per handler call.
// batchDelay 是批间暂停时长，用于限速削峰：断网恢复时 ~232 台 agent 同时重放会瞬时洪峰
// 冲垮 AC kafka producer（实测 burst 丢弃），放缓批间隔可削峰。batchDelay<=0 回退 50ms。
func (w *WAL) Replay(batchSize int, batchDelay time.Duration, handler func([]*grpcProto.EncodedRecord) error) error {
	if batchDelay <= 0 {
		batchDelay = 50 * time.Millisecond
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.curSize == 0 {
		return nil
	}

	// Seek to beginning for reading.
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("WAL seek: %w", err)
	}

	var totalReplayed int
	batch := make([]*grpcProto.EncodedRecord, 0, batchSize)

	for {
		// Read length header.
		var header [headerSize]byte
		if _, err := io.ReadFull(w.file, header[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return fmt.Errorf("WAL read header: %w", err)
		}

		dataLen := binary.BigEndian.Uint32(header[:])
		if dataLen == 0 || dataLen > maxRecordSize {
			w.logger.Warn("WAL: invalid record size, stopping replay",
				zap.Uint32("size", dataLen))
			break
		}

		// Read record data (P2-1: 池化 buffer).
		data := getWALBuf(int(dataLen))
		if _, err := io.ReadFull(w.file, data); err != nil {
			putWALBuf(data)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return fmt.Errorf("WAL read data: %w", err)
		}

		// Unmarshal record.
		record := &grpcProto.EncodedRecord{}
		if err := proto.Unmarshal(data, record); err != nil {
			putWALBuf(data)
			w.logger.Warn("WAL: corrupt record, skipping", zap.Error(err))
			continue
		}
		putWALBuf(data)

		batch = append(batch, record)

		// Flush batch when full.
		if len(batch) >= batchSize {
			if err := handler(batch); err != nil {
				return fmt.Errorf("WAL replay handler: %w", err)
			}
			totalReplayed += len(batch)
			batch = batch[:0]

			// Small delay between batches to avoid overwhelming the connection / AC producer.
			time.Sleep(batchDelay)
		}
	}

	// Flush remaining.
	if len(batch) > 0 {
		if err := handler(batch); err != nil {
			return fmt.Errorf("WAL replay handler: %w", err)
		}
		totalReplayed += len(batch)
	}

	w.replayed += uint64(totalReplayed)

	// Truncate WAL file after successful replay.
	if err := w.truncate(); err != nil {
		return fmt.Errorf("WAL truncate: %w", err)
	}

	w.logger.Info("WAL replay complete",
		zap.Int("events_replayed", totalReplayed))

	return nil
}

// HasData returns true if the WAL contains unreplayed events.
func (w *WAL) HasData() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.curSize > 0
}

// Size returns the current WAL file size in bytes.
func (w *WAL) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.curSize
}

// Stats returns WAL counters (written, replayed, dropped).
func (w *WAL) Stats() (written, replayed, dropped uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written, w.replayed, w.dropped
}

// Close closes the WAL file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// truncate resets the WAL file to empty (must be called with lock held).
func (w *WAL) truncate() error {
	if err := w.file.Truncate(0); err != nil {
		return err
	}
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	w.curSize = 0
	return nil
}
