// Package config 为 5 微服务 (Manager/AgentCenter/Consumer/Engine/VulnSync)
// 提供 SystemConfig DB 行 → viper 热重载的桥接 (P4-15).
//
// 设计:
//  1. service 启动后 NewSystemConfigWatcher 拉一次 system_configs 表
//  2. 用 viper.Set(key, value) 写入运行时, 业务 viper.GetXxx 拿到新值
//  3. 周期轮询 (默认 30s) 检查 updated_at 变化, 重新拉取
//
// 配合 ConfigChangeWorker (P1-1) 闭环:
//
//	用户提变更 → CR approved → ConfigChangeWorker.applySystemConfig 写表 →
//	5 服务的 Watcher 拉到新值 → viper.Set 热生效.
//
// 不走 Webhook / 事件总线, 是因为 5 服务可能跨集群部署, DB 是最简公共总线.
package config

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ViperSetter 抽象 viper.Set, 便于测试 + 解耦 (viper 全局 import 链).
type ViperSetter interface {
	Set(key string, value any)
}

// SystemConfigWatcher 周期拉 system_configs 表并 hot-reload.
type SystemConfigWatcher struct {
	db       *gorm.DB
	viper    ViperSetter
	tenantID string
	interval time.Duration
	logger   *zap.Logger

	lastSeenMaxUpdatedAt atomic.Int64 // unix ms
	stopCh               chan struct{}
	stopOnce             sync.Once
}

// NewSystemConfigWatcher 构造.
func NewSystemConfigWatcher(db *gorm.DB, viper ViperSetter, tenantID string, interval time.Duration, logger *zap.Logger) *SystemConfigWatcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if tenantID == "" {
		tenantID = "t-default"
	}
	return &SystemConfigWatcher{
		db:       db,
		viper:    viper,
		tenantID: tenantID,
		interval: interval,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Start 阻塞循环 (一般 go w.Start(ctx)).
func (w *SystemConfigWatcher) Start(ctx context.Context) {
	w.reload(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	w.logger.Info("system_config watcher started",
		zap.String("tenant_id", w.tenantID),
		zap.Duration("interval", w.interval))
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-t.C:
			w.reload(ctx)
		}
	}
}

// Stop 关闭.
func (w *SystemConfigWatcher) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
}

func (w *SystemConfigWatcher) reload(ctx context.Context) {
	var rows []model.SystemConfig
	if err := w.db.WithContext(ctx).
		Where("tenant_id = ?", w.tenantID).
		Find(&rows).Error; err != nil {
		w.logger.Warn("system_config reload failed", zap.Error(err))
		return
	}
	var changed int
	var maxUpdated int64
	for i := range rows {
		ms := rows[i].UpdatedAt.Time().UnixMilli()
		if ms > maxUpdated {
			maxUpdated = ms
		}
		w.viper.Set(rows[i].Key, rows[i].Value)
		changed++
	}
	if maxUpdated > w.lastSeenMaxUpdatedAt.Load() {
		w.lastSeenMaxUpdatedAt.Store(maxUpdated)
		w.logger.Info("system_config hot-reloaded",
			zap.Int("count", changed),
			zap.Int64("max_updated_ms", maxUpdated))
	}
}
