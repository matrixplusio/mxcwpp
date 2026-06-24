package scheduler

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/transfer"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const canaryCheckInterval = 30 * time.Second

// CanaryScheduler manages staged (canary/grayscale) rollouts for Agent upgrades
// and rule pushes. It periodically checks active rollouts and advances stages
// when health criteria are met.
type CanaryScheduler struct {
	db          *gorm.DB
	transferSvc *transfer.Service
	updateSched *AgentUpdateScheduler
	ruleSched   *RuleSyncScheduler
	logger      *zap.Logger
}

// NewCanaryScheduler creates a canary rollout scheduler.
func NewCanaryScheduler(
	db *gorm.DB,
	transferSvc *transfer.Service,
	updateSched *AgentUpdateScheduler,
	ruleSched *RuleSyncScheduler,
	logger *zap.Logger,
) *CanaryScheduler {
	return &CanaryScheduler{
		db:          db,
		transferSvc: transferSvc,
		updateSched: updateSched,
		ruleSched:   ruleSched,
		logger:      logger,
	}
}

// Start runs the canary scheduler loop.
func (s *CanaryScheduler) Start(ctx context.Context) {
	s.logger.Info("灰度发布调度器已启动", zap.Duration("interval", canaryCheckInterval))

	ticker := time.NewTicker(canaryCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("灰度发布调度器已停止")
			return
		case <-ticker.C:
			s.processActiveRollouts(ctx)
		}
	}
}

// processActiveRollouts checks all active (rolling/pending) rollouts.
func (s *CanaryScheduler) processActiveRollouts(_ context.Context) {
	var rollouts []model.CanaryRollout
	if err := s.db.Where("status IN ?",
		[]model.RolloutStatus{model.RolloutStatusPending, model.RolloutStatusRolling}).
		Find(&rollouts).Error; err != nil {
		s.logger.Warn("查询灰度发布记录失败", zap.Error(err))
		return
	}

	for i := range rollouts {
		s.processRollout(&rollouts[i])
	}
}

func (s *CanaryScheduler) processRollout(rollout *model.CanaryRollout) {
	// Health check: auto-rollback if failure rate exceeds threshold.
	if rollout.PushedAgents > 0 && rollout.FailureRate() > rollout.FailureThreshold {
		s.rollback(rollout, fmt.Sprintf("失败率 %.1f%% 超过阈值 %.1f%%",
			rollout.FailureRate()*100, rollout.FailureThreshold*100))
		return
	}

	// Check if enough time has passed for stage advancement.
	if !rollout.ShouldAdvance() {
		return
	}

	// All stages complete.
	if rollout.IsComplete() {
		s.complete(rollout)
		return
	}

	// Advance to next batch.
	s.advanceStage(rollout)
}

func (s *CanaryScheduler) advanceStage(rollout *model.CanaryRollout) {
	percent := rollout.CurrentBatchPercent()

	// Get all online agent IDs.
	allAgents := s.transferSvc.GetOnlineAgentIDs()
	if len(allAgents) == 0 {
		return
	}

	rollout.TotalAgents = len(allAgents)

	// Calculate how many agents to push to in this stage.
	targetCount := (len(allAgents) * percent) / 100
	if targetCount == 0 {
		targetCount = 1 // At least 1 agent per stage.
	}
	if targetCount > len(allAgents) {
		targetCount = len(allAgents)
	}

	// Shuffle agents for random selection.
	shuffled := make([]string, len(allAgents))
	copy(shuffled, allAgents)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	targetAgents := shuffled[:targetCount]

	var pushed, failed int

	switch rollout.Type {
	case model.RolloutTypeAgent:
		pushed, failed = s.pushAgentUpdate(rollout, targetAgents)
	case model.RolloutTypeRule:
		pushed, failed = s.pushRuleUpdate(rollout, targetAgents)
	}

	// Update rollout state.
	now := model.ToLocalTime(time.Now())
	rollout.CurrentStage++
	rollout.PushedAgents += pushed
	rollout.FailedAgents += failed
	rollout.SuccessAgents += pushed - failed
	rollout.StageAdvancedAt = &now
	rollout.Status = model.RolloutStatusRolling

	s.db.Model(rollout).Updates(map[string]any{
		"current_stage":     rollout.CurrentStage,
		"pushed_agents":     rollout.PushedAgents,
		"failed_agents":     rollout.FailedAgents,
		"success_agents":    rollout.SuccessAgents,
		"total_agents":      rollout.TotalAgents,
		"status":            rollout.Status,
		"stage_advanced_at": rollout.StageAdvancedAt,
	})

	s.logger.Info("灰度发布阶段推进",
		zap.Uint("rollout_id", rollout.ID),
		zap.String("type", string(rollout.Type)),
		zap.Int("stage", rollout.CurrentStage),
		zap.Int("percent", percent),
		zap.Int("pushed", pushed),
		zap.Int("failed", failed))
}

func (s *CanaryScheduler) pushAgentUpdate(_ *model.CanaryRollout, agents []string) (pushed, failed int) {
	count, failedAgents, err := s.updateSched.TriggerUpdate(context.Background(), agents)
	if err != nil {
		s.logger.Warn("灰度 Agent 升级推送失败", zap.Error(err))
		return 0, len(agents)
	}
	return count, len(failedAgents)
}

func (s *CanaryScheduler) pushRuleUpdate(_ *model.CanaryRollout, agents []string) (pushed, failed int) {
	for _, agentID := range agents {
		s.ruleSched.PushToAgent(agentID)
		pushed++
	}
	return pushed, 0
}

func (s *CanaryScheduler) complete(rollout *model.CanaryRollout) {
	now := model.ToLocalTime(time.Now())
	s.db.Model(rollout).Updates(map[string]any{
		"status":       model.RolloutStatusCompleted,
		"completed_at": &now,
		"message":      fmt.Sprintf("灰度发布完成，共推送 %d 台", rollout.PushedAgents),
	})
	s.logger.Info("灰度发布完成",
		zap.Uint("rollout_id", rollout.ID),
		zap.Int("total_pushed", rollout.PushedAgents))
}

func (s *CanaryScheduler) rollback(rollout *model.CanaryRollout, reason string) {
	now := model.ToLocalTime(time.Now())
	s.db.Model(rollout).Updates(map[string]any{
		"status":       model.RolloutStatusRollback,
		"completed_at": &now,
		"message":      "自动回滚: " + reason,
	})
	s.logger.Warn("灰度发布自动回滚",
		zap.Uint("rollout_id", rollout.ID),
		zap.String("reason", reason))
}
