// Package federation — 多集群联邦管理骨架 (C3).
//
// 场景: 客户在 3 个 K8s 集群部署 mxsec, 单一 Manager 控制台聚合管理.
//
// 设计:
//   - 子集群 mxsec 实例向中心 Manager 注册 (FederatedCluster 记录)
//   - 子集群定期 push 摘要 (alert 数 / host 数 / 漏洞数 / 模式)
//   - 中心 Manager pull 详情 (按需查具体告警 → reverse-call 子集群 API)
//   - 跨集群告警聚合视图 (UI: ClusterFederationConsole)
//
// 不引 kubefed, 走 mxsec 自实现轻量 federation 协议.
package federation

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Cluster 联邦中一个被管理集群.
type Cluster struct {
	ID            string    `gorm:"column:id;primaryKey" json:"id"`
	Name          string    `gorm:"column:name" json:"name"`
	Endpoint      string    `gorm:"column:endpoint" json:"endpoint"` // 子集群 Manager URL
	Token         string    `gorm:"column:token" json:"-"`           // 鉴权 token (KMS 加密)
	Region        string    `gorm:"column:region" json:"region"`
	Status        string    `gorm:"column:status" json:"status"` // online / offline / unreachable / paused
	LastHeartbeat time.Time `gorm:"column:last_heartbeat" json:"last_heartbeat"`

	// 子集群最新摘要
	HostCount       int64  `gorm:"column:host_count" json:"host_count"`
	OnlineHostCount int64  `gorm:"column:online_host_count" json:"online_host_count"`
	OpenAlertCount  int64  `gorm:"column:open_alert_count" json:"open_alert_count"`
	CriticalAlerts  int64  `gorm:"column:critical_alerts" json:"critical_alerts"`
	UnpatchedVulns  int64  `gorm:"column:unpatched_vulns" json:"unpatched_vulns"`
	Mode            string `gorm:"column:mode" json:"mode"` // observe / protect
}

// TableName GORM.
func (Cluster) TableName() string { return "federated_clusters" }

// HeartbeatPayload 子集群上报.
type HeartbeatPayload struct {
	ClusterID       string `json:"cluster_id"`
	Token           string `json:"token"`
	HostCount       int64  `json:"host_count"`
	OnlineHostCount int64  `json:"online_host_count"`
	OpenAlertCount  int64  `json:"open_alert_count"`
	CriticalAlerts  int64  `json:"critical_alerts"`
	UnpatchedVulns  int64  `json:"unpatched_vulns"`
	Mode            string `json:"mode"`
	Version         string `json:"version"`
	AgentVersionMin string `json:"agent_version_min"`
}

// Service 中心 Manager 侧的联邦管理.
type Service struct {
	db     *gorm.DB
	logger *zap.Logger

	mu      sync.RWMutex
	offline map[string]time.Time // cluster_id → 最早 offline 时间, 用于告警
}

// NewService 构造.
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, logger: logger, offline: map[string]time.Time{}}
}

// Register 注册新子集群.
func (s *Service) Register(ctx context.Context, c *Cluster) error {
	if c.ID == "" || c.Endpoint == "" {
		return errors.New("federation: id + endpoint required")
	}
	c.Status = "pending"
	return s.db.WithContext(ctx).Create(c).Error
}

// HandleHeartbeat 接子集群心跳, 更状态.
func (s *Service) HandleHeartbeat(ctx context.Context, p *HeartbeatPayload) error {
	var c Cluster
	if err := s.db.WithContext(ctx).First(&c, "id = ?", p.ClusterID).Error; err != nil {
		return errors.New("unknown cluster")
	}
	if c.Token != "" && c.Token != p.Token {
		return errors.New("token mismatch")
	}
	updates := map[string]any{
		"status":            "online",
		"last_heartbeat":    time.Now(),
		"host_count":        p.HostCount,
		"online_host_count": p.OnlineHostCount,
		"open_alert_count":  p.OpenAlertCount,
		"critical_alerts":   p.CriticalAlerts,
		"unpatched_vulns":   p.UnpatchedVulns,
		"mode":              p.Mode,
	}
	if err := s.db.WithContext(ctx).Model(&Cluster{}).Where("id = ?", p.ClusterID).Updates(updates).Error; err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.offline, p.ClusterID)
	s.mu.Unlock()
	return nil
}

// MarkOfflineSweeper 后台周期跑, 超 3 倍 heartbeat 间隔即标 offline.
func (s *Service) MarkOfflineSweeper(ctx context.Context, heartbeatInterval time.Duration) {
	if heartbeatInterval <= 0 {
		heartbeatInterval = 60 * time.Second
	}
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	threshold := heartbeatInterval * 3
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepOffline(ctx, threshold)
		}
	}
}

func (s *Service) sweepOffline(ctx context.Context, threshold time.Duration) {
	cutoff := time.Now().Add(-threshold)
	var stale []Cluster
	if err := s.db.WithContext(ctx).
		Where("status = ? AND last_heartbeat < ?", "online", cutoff).
		Find(&stale).Error; err != nil {
		return
	}
	for _, c := range stale {
		_ = s.db.WithContext(ctx).Model(&Cluster{}).
			Where("id = ?", c.ID).
			Update("status", "offline").Error
		s.mu.Lock()
		if _, ok := s.offline[c.ID]; !ok {
			s.offline[c.ID] = time.Now()
		}
		s.mu.Unlock()
		s.logger.Warn("federated cluster offline",
			zap.String("cluster_id", c.ID),
			zap.String("name", c.Name),
			zap.Time("last_heartbeat", c.LastHeartbeat))
	}
}

// AggregateSummary 跨所有集群聚合摘要 (中心 Dashboard 用).
func (s *Service) AggregateSummary(ctx context.Context) (*Summary, error) {
	var clusters []Cluster
	if err := s.db.WithContext(ctx).Find(&clusters).Error; err != nil {
		return nil, err
	}
	sum := &Summary{TotalClusters: len(clusters)}
	for _, c := range clusters {
		if c.Status == "online" {
			sum.OnlineClusters++
		}
		sum.TotalHosts += c.HostCount
		sum.OnlineHosts += c.OnlineHostCount
		sum.OpenAlerts += c.OpenAlertCount
		sum.CriticalAlerts += c.CriticalAlerts
		sum.UnpatchedVulns += c.UnpatchedVulns
	}
	return sum, nil
}

// Summary 中心 dashboard 视图.
type Summary struct {
	TotalClusters  int   `json:"total_clusters"`
	OnlineClusters int   `json:"online_clusters"`
	TotalHosts     int64 `json:"total_hosts"`
	OnlineHosts    int64 `json:"online_hosts"`
	OpenAlerts     int64 `json:"open_alerts"`
	CriticalAlerts int64 `json:"critical_alerts"`
	UnpatchedVulns int64 `json:"unpatched_vulns"`
}

// ListClusters 列出已注册集群.
func (s *Service) ListClusters(ctx context.Context, region, status string) ([]Cluster, error) {
	q := s.db.WithContext(ctx).Model(&Cluster{})
	if region != "" {
		q = q.Where("region = ?", region)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var out []Cluster
	if err := q.Order("id ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}
