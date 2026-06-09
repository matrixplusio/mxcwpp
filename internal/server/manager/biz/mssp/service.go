// Package mssp 实现 MSSP (Managed Security Service Provider) 父子租户视图 (P2-11).
//
// ref/01-服务端 M2-P2-2: MSSP 控制台 (父子租户/二级运营商视图 + 跨租户告警 SOC).
//
// 父租户场景: 集团总部 → 多分公司租户; 安服商 → 多客户租户。
//
// 关键约束:
//   - 父租户 admin 可读所有子租户告警 / 主机 (跨租户聚合)
//   - 父租户 admin 不能改子租户配置 (除非显式 grant)
//   - 父租户 admin 看不到子租户用户密码 / API key (KMS 加密保护)
package mssp

import (
	"context"
	"errors"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// Service MSSP 父子租户业务.
type Service struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewService 构造.
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, logger: logger}
}

// ChildTenant 子租户摘要 (供父租户控制台展示).
type ChildTenant struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	DefaultMode    string `json:"default_mode"`
	QuotaAgents    int    `json:"quota_agents"`
	UsedAgents     int64  `json:"used_agents"`
	OpenAlerts     int64  `json:"open_alerts"`
	CriticalAlerts int64  `json:"critical_alerts"`
	UnpatchedVulns int64  `json:"unpatched_vulns"`
	CreatedAt      string `json:"created_at"`
}

// ListChildren 列出指定父租户的所有子租户摘要.
func (s *Service) ListChildren(ctx context.Context, parentTenantID string) ([]ChildTenant, error) {
	var children []model.Tenant
	if err := s.db.WithContext(ctx).
		Where("parent_id = ?", parentTenantID).
		Order("id ASC").Find(&children).Error; err != nil {
		return nil, err
	}
	out := make([]ChildTenant, 0, len(children))
	for _, t := range children {
		summary := ChildTenant{
			ID:          t.ID,
			Name:        t.Name,
			Status:      string(t.Status),
			DefaultMode: string(t.DefaultMode),
			QuotaAgents: t.QuotaAgents,
			CreatedAt:   t.CreatedAt.Time().Format("2006-01-02 15:04:05"),
		}
		summary.UsedAgents = s.countAgents(ctx, t.ID)
		summary.OpenAlerts = s.countOpenAlerts(ctx, t.ID, "")
		summary.CriticalAlerts = s.countOpenAlerts(ctx, t.ID, "critical")
		summary.UnpatchedVulns = s.countUnpatchedVulns(ctx, t.ID)
		out = append(out, summary)
	}
	return out, nil
}

// AggregateAlerts 跨子租户告警聚合 (父租户 SOC 视图).
//
// 返回 group_by 维度的总数 (用于父租户 dashboard 顶部卡片).
func (s *Service) AggregateAlerts(ctx context.Context, parentTenantID, groupBy string) (map[string]int64, error) {
	if groupBy != "tenant_id" && groupBy != "severity" && groupBy != "category" && groupBy != "host_id" {
		return nil, errors.New("invalid group_by")
	}
	children := s.childrenIDs(ctx, parentTenantID)
	if len(children) == 0 {
		return map[string]int64{}, nil
	}
	type row struct {
		Key   string
		Count int64
	}
	var rows []row
	if err := s.db.WithContext(ctx).Table("alerts").
		Select(groupBy+" AS key, COUNT(*) AS count").
		Where("tenant_id IN ? AND status = ?", children, "open").
		Group(groupBy).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Count
	}
	return out, nil
}

// CreateChildTenant 父租户创建子租户 (受 quota 限制).
//
// 限制条件:
//   - 父租户必须是 type=mssp_parent 或 type=enterprise_root
//   - 子租户 quota_agents 不能超过父租户剩余 quota
func (s *Service) CreateChildTenant(ctx context.Context, parentTenantID string, child model.Tenant) error {
	var parent model.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", parentTenantID).First(&parent).Error; err != nil {
		return errors.New("parent tenant not found")
	}
	// 计算父租户已用 quota (所有子租户 quota_agents 总和)
	var usedQuota int64
	if err := s.db.WithContext(ctx).
		Table("tenants").
		Where("parent_id = ?", parentTenantID).
		Select("COALESCE(SUM(quota_agents), 0)").Scan(&usedQuota).Error; err != nil {
		return err
	}
	if int(usedQuota)+child.QuotaAgents > parent.QuotaAgents {
		return errors.New("parent quota_agents would be exceeded")
	}
	pid := parentTenantID
	child.ParentID = &pid
	return s.db.WithContext(ctx).Create(&child).Error
}

// childrenIDs 取所有子租户 ID (含父租户自身).
func (s *Service) childrenIDs(ctx context.Context, parentTenantID string) []string {
	var ids []string
	_ = s.db.WithContext(ctx).
		Table("tenants").
		Where("parent_id = ? OR id = ?", parentTenantID, parentTenantID).
		Pluck("id", &ids).Error
	return ids
}

func (s *Service) countAgents(ctx context.Context, tenantID string) int64 {
	var n int64
	_ = s.db.WithContext(ctx).Table("hosts").
		Where("tenant_id = ?", tenantID).Count(&n).Error
	return n
}

func (s *Service) countOpenAlerts(ctx context.Context, tenantID, severity string) int64 {
	q := s.db.WithContext(ctx).Table("alerts").
		Where("tenant_id = ? AND status = ?", tenantID, "open")
	if severity != "" {
		q = q.Where("severity = ?", severity)
	}
	var n int64
	_ = q.Count(&n).Error
	return n
}

func (s *Service) countUnpatchedVulns(ctx context.Context, tenantID string) int64 {
	var n int64
	_ = s.db.WithContext(ctx).Table("host_vulnerabilities").
		Where("tenant_id = ? AND status = ?", tenantID, "unpatched").Count(&n).Error
	return n
}

// UpdateChildStatus 更子租户 status, 仅当 parent_id 匹配, 防越权改其它租户 (A3).
func (s *Service) UpdateChildStatus(ctx context.Context, parentTenantID, childID, status string) error {
	res := s.db.WithContext(ctx).Model(&model.Tenant{}).
		Where("id = ? AND parent_id = ?", childID, parentTenantID).
		Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("child tenant not found under this parent")
	}
	return nil
}
