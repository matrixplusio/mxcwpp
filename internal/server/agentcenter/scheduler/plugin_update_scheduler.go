// Package scheduler 提供任务调度器
package scheduler

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// PluginUpdateScheduler 插件更新调度器
// 定期检查 plugin_configs 表是否有更新，只广播实际发生变更的插件
type PluginUpdateScheduler struct {
	db              *gorm.DB
	transferService *transfer.Service
	logger          *zap.Logger
	lastCheckTime   time.Time
	// pluginVersions 记录每个插件上次广播时的版本和 SHA256，用于差异检测
	pluginVersions map[string]string // name -> "version|sha256"
	mu             sync.Mutex
}

// NewPluginUpdateScheduler 创建插件更新调度器
func NewPluginUpdateScheduler(db *gorm.DB, transferService *transfer.Service, logger *zap.Logger) *PluginUpdateScheduler {
	return &PluginUpdateScheduler{
		db:              db,
		transferService: transferService,
		logger:          logger,
		lastCheckTime:   time.Now(),
		pluginVersions:  make(map[string]string),
	}
}

// Start 启动插件更新调度器
func (s *PluginUpdateScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // 每 30 秒检查一次
	defer ticker.Stop()

	s.logger.Info("插件更新调度器已启动", zap.Duration("interval", 30*time.Second))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("插件更新调度器已停止")
			return
		case <-ticker.C:
			s.checkAndBroadcast(ctx)
		}
	}
}

// checkAndBroadcast 检查是否有更新并广播（差异广播：只广播实际变更的插件）
func (s *PluginUpdateScheduler) checkAndBroadcast(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 查询最近更新的插件配置
	var latestUpdate sql.NullTime
	err := s.db.Model(&model.PluginConfig{}).
		Select("MAX(updated_at)").
		Where("enabled = ?", true).
		Scan(&latestUpdate).Error

	if err != nil {
		s.logger.Error("查询插件配置更新时间失败", zap.Error(err))
		return
	}

	if !latestUpdate.Valid {
		return
	}

	// 如果没有新更新，跳过
	if !latestUpdate.Time.After(s.lastCheckTime) {
		return
	}

	// 查询所有启用的插件配置，对比版本判断哪些有变化
	var pluginConfigs []model.PluginConfig
	if err := s.db.Where("enabled = ?", true).Find(&pluginConfigs).Error; err != nil {
		s.logger.Error("查询插件配置失败", zap.Error(err))
		return
	}

	var changedPlugins []string
	for _, pc := range pluginConfigs {
		key := pc.Name
		currentVersion := pc.Version + "|" + pc.SHA256
		if lastVersion, ok := s.pluginVersions[key]; !ok || lastVersion != currentVersion {
			changedPlugins = append(changedPlugins, key)
			s.pluginVersions[key] = currentVersion
		}
	}

	if len(changedPlugins) == 0 {
		s.lastCheckTime = time.Now()
		return
	}

	s.logger.Info("检测到插件配置更新，开始差异广播",
		zap.Time("last_check", s.lastCheckTime),
		zap.Time("latest_update", latestUpdate.Time),
		zap.Strings("changed_plugins", changedPlugins))

	// 只广播变更的插件
	successCount, failedAgents, err := s.transferService.BroadcastPluginConfigsByName(ctx, changedPlugins)
	if err != nil {
		s.logger.Error("广播插件配置失败", zap.Error(err))
	} else {
		s.logger.Info("差异广播插件配置完成",
			zap.Int("success_count", successCount),
			zap.Strings("failed_agents", failedAgents),
			zap.Strings("changed_plugins", changedPlugins))
	}

	// 更新检查时间
	s.lastCheckTime = time.Now()
}

// TriggerBroadcast 手动触发广播（供 API 调用）
func (s *PluginUpdateScheduler) TriggerBroadcast(ctx context.Context) (int, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("手动触发插件配置广播")

	successCount, failedAgents, err := s.transferService.BroadcastPluginConfigs(ctx)
	if err != nil {
		return 0, nil, err
	}

	// 更新检查时间
	s.lastCheckTime = time.Now()

	return successCount, failedAgents, nil
}
