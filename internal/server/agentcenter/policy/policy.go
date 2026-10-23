// Package policy 让 AgentCenter 读取控制台里设置的 Agent 运行时策略，改动无需重启即可生效。
package policy

import (
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// refreshInterval 控制台改动最迟多久生效。
const refreshInterval = 30 * time.Second

// Store 缓存当前策略，过期后从数据库刷新。
type Store struct {
	db     *gorm.DB
	logger *zap.Logger

	mu       sync.Mutex
	current  model.AgentPolicy
	loadedAt time.Time
}

// New 创建策略存储。数据库里还没有策略时，用配置文件里的值初始化一次：
// 之后以数据库为准，控制台显示的就是实际生效的值，重新渲染配置文件也不会把它改回去。
func New(db *gorm.DB, cfg *config.Config, logger *zap.Logger) *Store {
	s := &Store{db: db, logger: logger, current: fromConfig(cfg)}
	p, found, err := model.LoadAgentPolicy(db)
	switch {
	case err != nil:
		logger.Warn("读取 agent 策略失败，暂按配置文件生效", zap.Error(err))
	case !found:
		if err := model.SaveAgentPolicy(db, s.current); err != nil {
			logger.Warn("初始化 agent 策略失败，暂按配置文件生效", zap.Error(err))
		} else {
			logger.Info("已用配置文件初始化 agent 策略，此后以控制台设置为准", zap.Any("policy", s.current))
		}
	default:
		s.current = p
	}
	s.loadedAt = time.Now()
	return s
}

// Get 返回当前策略；距上次读取超过 refreshInterval 时刷新。刷新失败保留上一次的值，不回落到默认。
func (s *Store) Get() model.AgentPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.loadedAt) < refreshInterval {
		return s.current
	}
	s.loadedAt = time.Now()
	p, found, err := model.LoadAgentPolicy(s.db)
	if err != nil || !found || p.Validate() != nil {
		if err != nil {
			s.logger.Warn("刷新 agent 策略失败，沿用上一次的值", zap.Error(err))
		}
		return s.current
	}
	if p != s.current {
		s.logger.Info("agent 策略已变更", zap.Any("from", s.current), zap.Any("to", p))
		s.current = p
	}
	return s.current
}

func fromConfig(cfg *config.Config) model.AgentPolicy {
	p := model.AgentPolicy{
		IdentityConflict:    model.IdentityConflictAlert,
		AutoUpdate:          cfg.Agent.AutoUpdate,
		AutoPluginBroadcast: cfg.Agent.AutoPluginBroadcast,
	}
	if cfg.MTLS.IdentityConflict == model.IdentityConflictReject {
		p.IdentityConflict = model.IdentityConflictReject
	}
	return p
}
