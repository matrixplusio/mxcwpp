package scheduler

import (
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PolicySource 提供控制台设置的 agent 运行时策略。
type PolicySource interface {
	Get() model.AgentPolicy
}

// policyOrConfig 有注入的策略就用策略，否则按配置文件（测试与早期启动路径）。
func policyOrConfig(p PolicySource, cfg *config.Config) model.AgentPolicy {
	if p != nil {
		return p.Get()
	}
	return model.AgentPolicy{AutoUpdate: cfg.Agent.AutoUpdate, AutoPluginBroadcast: cfg.Agent.AutoPluginBroadcast}
}

// SetPolicy 注入运行时策略。
func (s *AgentUpdateScheduler) SetPolicy(p PolicySource) { s.policy = p }

func (s *AgentUpdateScheduler) currentPolicy() model.AgentPolicy {
	return policyOrConfig(s.policy, s.cfg)
}

// SetPolicy 注入运行时策略。
func (s *PluginUpdateScheduler) SetPolicy(p PolicySource) { s.policy = p }

func (s *PluginUpdateScheduler) currentPolicy() model.AgentPolicy {
	return policyOrConfig(s.policy, s.cfg)
}
