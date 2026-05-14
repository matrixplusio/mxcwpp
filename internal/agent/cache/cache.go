// Package cache 提供本地缓存功能，用于断网时暂存数据
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/grpc"
)

// Manager 是缓存管理器
type Manager struct {
	cacheDir    string
	maxSize     int64         // 最大缓存大小（字节）
	maxAge      time.Duration // 最大缓存时间
	logger      *zap.Logger
	mu          sync.RWMutex
	currentSize int64 // 当前缓存大小
}

// CacheEntry 是缓存条目
type CacheEntry struct {
	Data      *grpc.PackagedData `json:"data"`
	Timestamp int64              `json:"timestamp"`
	Retries   int                `json:"retries"`
}

// NewManager 创建新的缓存管理器
func NewManager(cacheDir string, maxSize int64, maxAge time.Duration, logger *zap.Logger) (*Manager, error) {
	// 创建缓存目录
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	mgr := &Manager{
		cacheDir: cacheDir,
		maxSize:  maxSize,
		maxAge:   maxAge,
		logger:   logger,
	}

	// 加载现有缓存文件，计算当前大小
	if err := mgr.loadCacheSize(); err != nil {
		logger.Warn("failed to load cache size", zap.Error(err))
	}

	return mgr, nil
}

// Put 将数据放入缓存
func (m *Manager) Put(data *grpc.PackagedData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查缓存大小限制
	if m.currentSize >= m.maxSize {
		// 清理过期缓存
		if err := m.cleanExpired(); err != nil {
			m.logger.Warn("failed to clean expired cache", zap.Error(err))
		}
		// 如果仍然超过限制，删除最旧的缓存
		if m.currentSize >= m.maxSize {
			if err := m.cleanOldest(); err != nil {
				return fmt.Errorf("cache is full and cleanup failed: %w", err)
			}
		}
	}

	// 创建缓存条目
	entry := &CacheEntry{
		Data:      data,
		Timestamp: time.Now().Unix(),
		Retries:   0,
	}

	// 序列化
	entryData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	// 生成文件名（使用时间戳和随机数）
	filename := fmt.Sprintf("cache_%d_%d.json", time.Now().UnixNano(), len(entryData))
	filePath := filepath.Join(m.cacheDir, filename)

	// 写入文件
	if err := os.WriteFile(filePath, entryData, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// 更新当前大小
	m.currentSize += int64(len(entryData))

	m.logger.Debug("data cached",
		zap.String("file", filename),
		zap.Int64("size", int64(len(entryData))),
		zap.Int64("total_size", m.currentSize))

	return nil
}

// Get 从缓存中获取数据（FIFO 顺序）
func (m *Manager) Get() (*grpc.PackagedData, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 读取缓存目录中的所有文件
	files, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read cache dir: %w", err)
	}

	// 找到最旧的文件
	var oldestFile os.DirEntry
	var oldestTime time.Time
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		if oldestFile == nil || info.ModTime().Before(oldestTime) {
			oldestFile = file
			oldestTime = info.ModTime()
		}
	}

	if oldestFile == nil {
		return nil, "", nil // 缓存为空
	}

	// 读取文件
	filePath := filepath.Join(m.cacheDir, oldestFile.Name())
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read cache file: %w", err)
	}

	// 解析缓存条目
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// 文件损坏，删除它
		os.Remove(filePath)
		m.currentSize -= int64(len(data))
		return nil, "", fmt.Errorf("failed to unmarshal cache entry: %w", err)
	}

	// 检查是否过期
	if time.Since(time.Unix(entry.Timestamp, 0)) > m.maxAge {
		os.Remove(filePath)
		m.currentSize -= int64(len(data))
		return nil, "", nil // 已过期，继续查找下一个
	}

	return entry.Data, filePath, nil
}

// Remove 删除指定的缓存文件
func (m *Manager) Remove(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 获取文件大小
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	// 删除文件
	if err := os.Remove(filePath); err != nil {
		return err
	}

	// 更新当前大小
	m.currentSize -= info.Size()

	return nil
}

// Size 返回当前缓存大小
func (m *Manager) Size() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentSize
}

// Count 返回缓存文件数量
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	files, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".json" {
			count++
		}
	}

	return count
}

// Cleanup 清理过期和过大的缓存
func (m *Manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 清理过期缓存
	if err := m.cleanExpired(); err != nil {
		return err
	}

	// 如果仍然超过限制，删除最旧的缓存
	for m.currentSize >= m.maxSize {
		if err := m.cleanOldest(); err != nil {
			return err
		}
	}

	return nil
}

// cleanExpired 清理过期缓存
func (m *Manager) cleanExpired() error {
	files, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(m.cacheDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var entry CacheEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			// 文件损坏，删除它
			os.Remove(filePath)
			m.currentSize -= int64(len(data))
			continue
		}

		// 检查是否过期
		if now.Sub(time.Unix(entry.Timestamp, 0)) > m.maxAge {
			os.Remove(filePath)
			m.currentSize -= int64(len(data))
			m.logger.Debug("removed expired cache file", zap.String("file", file.Name()))
		}
	}

	return nil
}

// cleanOldest 删除最旧的缓存文件
func (m *Manager) cleanOldest() error {
	files, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return err
	}

	var oldestFile os.DirEntry
	var oldestTime time.Time
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		if oldestFile == nil || info.ModTime().Before(oldestTime) {
			oldestFile = file
			oldestTime = info.ModTime()
		}
	}

	if oldestFile == nil {
		return nil // 没有文件可删除
	}

	filePath := filepath.Join(m.cacheDir, oldestFile.Name())
	info, err := oldestFile.Info()
	if err != nil {
		return err
	}

	if err := os.Remove(filePath); err != nil {
		return err
	}

	m.currentSize -= info.Size()
	m.logger.Debug("removed oldest cache file", zap.String("file", oldestFile.Name()))

	return nil
}

// loadCacheSize 加载当前缓存大小
func (m *Manager) loadCacheSize() error {
	files, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return err
	}

	m.currentSize = 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		m.currentSize += info.Size()
	}

	return nil
}

// StartCleanupLoop 启动定期清理循环
func (m *Manager) StartCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Cleanup(); err != nil {
				m.logger.Error("failed to cleanup cache", zap.Error(err))
			}
		}
	}
}
