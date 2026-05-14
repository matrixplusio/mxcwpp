package biz

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeSyncService 集群状态同步服务
type KubeSyncService struct {
	db           *gorm.DB
	logger       *zap.Logger
	kubeClient   *KubeClientManager
	alarmService *KubeAlarmService
	interval     time.Duration
	stopCh       chan struct{}
}

// NewKubeSyncService 创建集群同步服务
func NewKubeSyncService(db *gorm.DB, logger *zap.Logger, kubeClient *KubeClientManager, alarmService *KubeAlarmService) *KubeSyncService {
	return &KubeSyncService{
		db:           db,
		logger:       logger,
		kubeClient:   kubeClient,
		alarmService: alarmService,
		interval:     5 * time.Minute,
		stopCh:       make(chan struct{}),
	}
}

// Start 启动后台同步
func (s *KubeSyncService) Start(ctx context.Context) {
	s.logger.Info("K8s 集群同步服务已启动", zap.Duration("interval", s.interval))

	// 立即执行一次
	s.syncAll()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.syncAll()
		case <-ctx.Done():
			s.logger.Info("K8s 集群同步服务已停止")
			return
		case <-s.stopCh:
			s.logger.Info("K8s 集群同步服务已停止")
			return
		}
	}
}

// Stop 停止同步
func (s *KubeSyncService) Stop() {
	close(s.stopCh)
}

// syncAll 同步所有集群状态
func (s *KubeSyncService) syncAll() {
	var clusters []model.KubeCluster
	if err := s.db.Find(&clusters).Error; err != nil {
		s.logger.Error("查询集群列表失败", zap.Error(err))
		return
	}

	for _, cluster := range clusters {
		s.syncCluster(cluster)
	}
}

// syncCluster 同步单个集群状态
func (s *KubeSyncService) syncCluster(cluster model.KubeCluster) {
	version, nodeCount, podCount, nsCount, _, _, _, err := s.kubeClient.GetClusterInfo(cluster.ID)
	if err != nil {
		s.logger.Warn("同步集群失败，标记为 offline",
			zap.String("cluster", cluster.Name),
			zap.Error(err),
		)
		s.db.Model(&cluster).Updates(map[string]interface{}{
			"status": model.KubeClusterStatusOffline,
		})
		return
	}

	// 更新集群信息
	updates := map[string]interface{}{
		"version":         version,
		"node_count":      nodeCount,
		"pod_count":       podCount,
		"namespace_count": nsCount,
		"status":          model.KubeClusterStatusRunning,
	}

	// 检查 NotReady 节点
	nodes, nodeErr := s.kubeClient.GetNodes(cluster.ID)
	if nodeErr == nil {
		notReadyCount := 0
		for _, node := range nodes {
			if node.Status == "NotReady" {
				notReadyCount++
				s.createNodeNotReadyAlarm(cluster, node.Name)
			}
		}
		if notReadyCount > 0 {
			updates["status"] = model.KubeClusterStatusWarning
		}
	}

	s.db.Model(&cluster).Updates(updates)
}

// createNodeNotReadyAlarm 为 NotReady 节点创建告警
func (s *KubeSyncService) createNodeNotReadyAlarm(cluster model.KubeCluster, nodeName string) {
	// 检查是否已有未处理的同类告警，避免重复
	var count int64
	s.db.Model(&model.KubeAlarm{}).
		Where("cluster_id = ? AND node_name = ? AND alarm_type = ? AND status = ?",
			cluster.ID, nodeName, model.KubeAlarmTypeAbnormalNetwork, model.KubeAlarmStatusPending).
		Count(&count)
	if count > 0 {
		return
	}

	alarm := model.KubeAlarm{
		ClusterID:   cluster.ID,
		ClusterName: cluster.Name,
		Severity:    "high",
		AlarmType:   model.KubeAlarmTypeAbnormalNetwork,
		Title:       "节点 NotReady: " + nodeName,
		Description: "集群 " + cluster.Name + " 中节点 " + nodeName + " 状态为 NotReady",
		NodeName:    nodeName,
		Status:      model.KubeAlarmStatusPending,
	}

	if _, err := s.alarmService.CreateAlarmWithFilter(&alarm); err != nil {
		s.logger.Error("创建节点 NotReady 告警失败",
			zap.String("node", nodeName), zap.Error(err))
	}
}
