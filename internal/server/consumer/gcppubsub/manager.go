package gcppubsub

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// consumerEntry 一个活跃消费者的条目
type consumerEntry struct {
	cancel context.CancelFunc
	// 使用此 subscription 的集群 ID 列表（用于去重）
	clusterIDs []uint
}

// subscriptionKey 用于去重的键
func subscriptionKey(projectID, subscription string) string {
	return fmt.Sprintf("%s/%s", projectID, subscription)
}

// ConsumerManager 管理多个 per-cluster GCP Pub/Sub 消费者
// 同一个 (project_id, subscription) 只启动一个消费者，避免消息竞争
type ConsumerManager struct {
	db           *gorm.DB
	logger       *zap.Logger
	alarmService *kube.KubeAlarmService

	mu        sync.Mutex
	consumers map[string]*consumerEntry // key: "project_id/subscription"
	parentCtx context.Context
}

// NewConsumerManager 创建消费者管理器
func NewConsumerManager(db *gorm.DB, logger *zap.Logger, alarmService *kube.KubeAlarmService) *ConsumerManager {
	return &ConsumerManager{
		db:           db,
		logger:       logger,
		alarmService: alarmService,
		consumers:    make(map[string]*consumerEntry),
	}
}

// Start 启动管理器：从数据库加载所有启用 GCP 的集群并启动消费者
func (m *ConsumerManager) Start(ctx context.Context) {
	m.parentCtx = ctx

	var clusters []model.KubeCluster
	if err := m.db.Where("gcp_enabled = ?", true).Find(&clusters).Error; err != nil {
		m.logger.Error("加载 GCP 配置的集群失败", zap.Error(err))
		return
	}

	if len(clusters) == 0 {
		m.logger.Info("没有启用 GCP Pub/Sub 的集群")
		return
	}

	m.logger.Info("加载 GCP Pub/Sub 集群配置", zap.Int("count", len(clusters)))

	for _, c := range clusters {
		m.startConsumerForCluster(c)
	}
}

// startConsumerForCluster 为单个集群启动（或复用）消费者
func (m *ConsumerManager) startConsumerForCluster(cluster model.KubeCluster) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := subscriptionKey(cluster.GCPProjectID, cluster.GCPSubscription)

	// 如果相同 subscription 已有消费者在运行，只记录集群 ID
	if entry, exists := m.consumers[key]; exists {
		for _, id := range entry.clusterIDs {
			if id == cluster.ID {
				return // 已注册
			}
		}
		entry.clusterIDs = append(entry.clusterIDs, cluster.ID)
		m.logger.Info("集群复用已有 Pub/Sub 消费者",
			zap.Uint("cluster_id", cluster.ID),
			zap.String("subscription_key", key),
		)
		return
	}

	// 创建新消费者
	cfg := ClusterGCPConfig{
		ClusterID:       cluster.ID,
		ClusterName:     cluster.Name,
		ProjectID:       cluster.GCPProjectID,
		Subscription:    cluster.GCPSubscription,
		CredentialsJSON: cluster.GCPCredentialsJSON,
	}

	consumerCtx, cancel := context.WithCancel(m.parentCtx)
	consumer := NewConsumer(cfg, m.db, m.logger, m.alarmService)

	m.consumers[key] = &consumerEntry{
		cancel:     cancel,
		clusterIDs: []uint{cluster.ID},
	}

	go consumer.Start(consumerCtx)

	m.logger.Info("启动 Pub/Sub 消费者",
		zap.Uint("cluster_id", cluster.ID),
		zap.String("subscription_key", key),
	)
}

// stopConsumerForKey 停止指定 subscription key 的消费者
func (m *ConsumerManager) stopConsumerForKey(key string) {
	// 调用者已持锁
	if entry, exists := m.consumers[key]; exists {
		entry.cancel()
		delete(m.consumers, key)
		m.logger.Info("停止 Pub/Sub 消费者", zap.String("subscription_key", key))
	}
}

// OnClusterGCPConfigChanged 集群 GCP 配置变更时调用（新增/更新/删除）
// 重新加载该集群的配置，必要时重启消费者
func (m *ConsumerManager) OnClusterGCPConfigChanged(clusterID uint) {
	var cluster model.KubeCluster
	if err := m.db.First(&cluster, clusterID).Error; err != nil {
		m.logger.Error("加载集群失败", zap.Uint("cluster_id", clusterID), zap.Error(err))
		return
	}

	m.mu.Lock()

	// 1. 先从所有 entry 中移除该集群
	for key, entry := range m.consumers {
		newIDs := make([]uint, 0, len(entry.clusterIDs))
		for _, id := range entry.clusterIDs {
			if id != clusterID {
				newIDs = append(newIDs, id)
			}
		}
		entry.clusterIDs = newIDs
		// 如果该 subscription 没有集群使用了，停止消费者
		if len(entry.clusterIDs) == 0 {
			m.stopConsumerForKey(key)
		}
	}

	m.mu.Unlock()

	// 2. 如果集群已启用 GCP，启动新消费者
	if cluster.GCPEnabled && cluster.GCPProjectID != "" && cluster.GCPSubscription != "" {
		m.startConsumerForCluster(cluster)
	}
}

// OnClusterDeleted 集群删除时调用
func (m *ConsumerManager) OnClusterDeleted(clusterID uint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, entry := range m.consumers {
		newIDs := make([]uint, 0, len(entry.clusterIDs))
		for _, id := range entry.clusterIDs {
			if id != clusterID {
				newIDs = append(newIDs, id)
			}
		}
		entry.clusterIDs = newIDs
		if len(entry.clusterIDs) == 0 {
			m.stopConsumerForKey(key)
		}
	}
}
