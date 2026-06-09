// Package honeypot 实现 Server 端 honeypot 策略管理与白名单过滤。
//
// 设计点:
//
//  1. Policy CRUD: 不同 host_label 选择不同诱饵投放方案
//  2. 白名单过滤: 合法备份/运维进程触发不告警 (rsync/borg/restic 等)
//  3. 部署快照: Agent 投放完回报, 落 honeypot_deployments 表
//  4. 命中关联: 触发事件 join deployment 表查 decoy 元信息
package honeypot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// Service 提供 honeypot 策略 + 部署记录的业务操作。
type Service struct {
	db     *gorm.DB
	logger *zap.Logger

	mu         sync.RWMutex
	wlCompiled []*regexp.Regexp // 默认白名单 + policy 白名单合并编译
}

// NewService 构造。
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &Service{db: db, logger: logger}
	s.refreshWhitelist(model.DefaultHoneypotWhitelist)
	return s
}

// CreatePolicy 创建策略。
//
// targetDirs / decoyKinds / whitelistExe 为字符串数组,内部序列化为 JSON 落库。
func (s *Service) CreatePolicy(ctx context.Context, tenantID string,
	p model.HoneypotPolicy, targetDirs, decoyKinds, whitelistExe []string) (uint, error) {
	if p.Name == "" {
		return 0, errors.New("policy name required")
	}
	p.TenantID = tenantID
	td, _ := json.Marshal(targetDirs)
	dk, _ := json.Marshal(decoyKinds)
	we, _ := json.Marshal(whitelistExe)
	p.TargetDirsJSON = string(td)
	p.DecoyKindsJSON = string(dk)
	p.WhitelistExeJSON = string(we)
	if err := s.db.WithContext(ctx).Create(&p).Error; err != nil {
		return 0, fmt.Errorf("create honeypot policy: %w", err)
	}
	s.logger.Info("honeypot policy created",
		zap.Uint("id", p.ID), zap.String("name", p.Name), zap.String("tenant", tenantID))
	return p.ID, nil
}

// ListPolicies 列出某租户启用的 policy。
func (s *Service) ListPolicies(ctx context.Context, tenantID string) ([]model.HoneypotPolicy, error) {
	var policies []model.HoneypotPolicy
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND enabled = 1", tenantID).
		Order("id DESC").Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("list honeypot policies: %w", err)
	}
	return policies, nil
}

// DisablePolicy 禁用 (软关) policy。
func (s *Service) DisablePolicy(ctx context.Context, tenantID string, id uint) error {
	return s.db.WithContext(ctx).
		Model(&model.HoneypotPolicy{}).
		Where("tenant_id = ? AND id = ?", tenantID, id).
		Update("enabled", false).Error
}

// MatchPolicyForHost 按 host_label_selector 给主机选 policy (返回首条命中)。
//
// 多 policy 匹配场景: 用 ID DESC 取最新; 后续可加 priority 字段精细化。
func (s *Service) MatchPolicyForHost(ctx context.Context, tenantID string, hostLabels map[string]string) (*model.HoneypotPolicy, error) {
	policies, err := s.ListPolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range policies {
		if matchLabelSelector(policies[i].HostLabelSelector, hostLabels) {
			return &policies[i], nil
		}
	}
	return nil, nil
}

// RecordDeployment 落 Agent 回报的诱饵部署快照。
//
// 幂等: 同 host_id + decoy_path 重复回报仅更新 last_seen_at。
func (s *Service) RecordDeployment(ctx context.Context, r model.HoneypotDeploymentRecord) error {
	now := time.Now()
	r.LastSeenAt = model.LocalTime(now)
	// upsert by (host_id, decoy_path)
	res := s.db.WithContext(ctx).
		Where("host_id = ? AND decoy_path = ?", r.HostID, r.DecoyPath).
		Assign(map[string]any{
			"last_seen_at": r.LastSeenAt,
			"policy_id":    r.PolicyID,
			"size":         r.Size,
		}).
		FirstOrCreate(&r)
	return res.Error
}

// IncrTrigger 命中后递增 trigger_count。
func (s *Service) IncrTrigger(ctx context.Context, hostID, decoyPath string) error {
	return s.db.WithContext(ctx).
		Model(&model.HoneypotDeploymentRecord{}).
		Where("host_id = ? AND decoy_path = ?", hostID, decoyPath).
		UpdateColumn("trigger_count", gorm.Expr("trigger_count + 1")).Error
}

// IsLegitimateActor 判定触发进程是否为合法备份/运维 (走全局 + policy 白名单)。
//
// true → 应抑制告警, 仅记 info 级日志。
// false → 继续走告警通路。
func (s *Service) IsLegitimateActor(exePath string, policyWhitelistJSON string) bool {
	if exePath == "" {
		return false
	}
	// 1. 全局白名单 (默认进程)
	s.mu.RLock()
	for _, re := range s.wlCompiled {
		if re.MatchString(exePath) {
			s.mu.RUnlock()
			return true
		}
	}
	s.mu.RUnlock()
	// 2. policy 自定义白名单
	if policyWhitelistJSON != "" {
		var extra []string
		if err := json.Unmarshal([]byte(policyWhitelistJSON), &extra); err == nil {
			for _, pat := range extra {
				re, err := regexp.Compile(pat)
				if err == nil && re.MatchString(exePath) {
					return true
				}
			}
		}
	}
	return false
}

// refreshWhitelist 重新编译白名单 (路径 prefix → regex)。
func (s *Service) refreshWhitelist(items []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wlCompiled = s.wlCompiled[:0]
	for _, p := range items {
		// 字面 exe 路径用 ^path$ 精确匹配 (避免 /usr/bin/find 误中 /opt/find_evil/find)
		pat := "^" + regexp.QuoteMeta(p) + "$"
		if re, err := regexp.Compile(pat); err == nil {
			s.wlCompiled = append(s.wlCompiled, re)
		}
	}
}

// matchLabelSelector 解析 "k1=v1,k2=v2" 全部命中。
//
// 空 selector → 匹配所有 (默认 policy 用)。
func matchLabelSelector(selector string, labels map[string]string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		kv := strings.SplitN(term, "=", 2)
		if len(kv) != 2 {
			return false
		}
		if labels[kv[0]] != kv[1] {
			return false
		}
	}
	return true
}
