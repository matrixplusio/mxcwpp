// Package celengine - C1: 行为序列检测
// 使用滑动窗口 + 状态机检测多步攻击链
package celengine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// SequenceRule 序列检测规则
type SequenceRule struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Steps    []SequenceStep `json:"steps"`
	Window   time.Duration  `json:"window"` // 滑动窗口
	Severity string         `json:"severity"`
}

// SequenceStep 序列检测的单个步骤
type SequenceStep struct {
	Name       string `json:"name"`
	Expression string `json:"expression"` // CEL 表达式
	Order      int    `json:"order"`
}

// SequenceState 序列检测的中间状态
type SequenceState struct {
	RuleID       string    `json:"rule_id"`
	HostID       string    `json:"host_id"`
	CurrentStep  int       `json:"current_step"`
	StartTime    time.Time `json:"start_time"`
	MatchedSteps []int     `json:"matched_steps"`
}

// SequenceDetector 行为序列检测器
type SequenceDetector struct {
	rules       []SequenceRule
	redisClient *redis.Client
	engine      *Engine
	logger      *zap.Logger
	mu          sync.RWMutex
}

// NewSequenceDetector 创建序列检测器
func NewSequenceDetector(engine *Engine, redisClient *redis.Client, logger *zap.Logger) *SequenceDetector {
	return &SequenceDetector{
		engine:      engine,
		redisClient: redisClient,
		logger:      logger,
	}
}

// Evaluate 评估事件是否命中序列规则的某个步骤
func (d *SequenceDetector) Evaluate(hostID string, dataType int32, fields map[string]string) []SequenceRule {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var matched []SequenceRule
	ctx := context.Background()

	for _, rule := range d.rules {
		stateKey := fmt.Sprintf("mxsec:seq:%s:%s", rule.ID, hostID)

		// 获取当前状态
		state := d.getState(ctx, stateKey)

		if state == nil {
			// 检查是否匹配第一步
			if d.matchStep(rule.Steps[0], dataType, fields) {
				state = &SequenceState{
					RuleID:       rule.ID,
					HostID:       hostID,
					CurrentStep:  1,
					StartTime:    time.Now(),
					MatchedSteps: []int{0},
				}
				d.setState(ctx, stateKey, state, rule.Window)
			}
			continue
		}

		// 检查窗口是否过期
		if time.Since(state.StartTime) > rule.Window {
			d.delState(ctx, stateKey)
			continue
		}

		// 检查下一步
		nextStep := state.CurrentStep
		if nextStep >= len(rule.Steps) {
			continue
		}

		if d.matchStep(rule.Steps[nextStep], dataType, fields) {
			state.CurrentStep++
			state.MatchedSteps = append(state.MatchedSteps, nextStep)

			if state.CurrentStep >= len(rule.Steps) {
				// 完整序列匹配
				matched = append(matched, rule)
				d.delState(ctx, stateKey)
				d.logger.Info("序列规则命中",
					zap.String("rule_id", rule.ID),
					zap.String("host_id", hostID))
			} else {
				d.setState(ctx, stateKey, state, rule.Window)
			}
		}
	}

	return matched
}

// matchStep 检查事件是否匹配序列步骤
// 直接编译并评估步骤自身的 CEL 表达式，而非走全量规则评估
func (d *SequenceDetector) matchStep(step SequenceStep, dataType int32, fields map[string]string) bool {
	if step.Expression == "" {
		return false
	}

	program, err := d.engine.CompileExpression(step.Expression)
	if err != nil {
		d.logger.Debug("编译序列步骤表达式失败",
			zap.String("step_name", step.Name),
			zap.Error(err))
		return false
	}

	activation := buildActivation(dataType, fields)
	out, _, err := program.Eval(activation)
	if err != nil {
		return false
	}

	return out.Value() == true
}

// getState 从 Redis 获取序列状态
func (d *SequenceDetector) getState(ctx context.Context, key string) *SequenceState {
	if d.redisClient == nil {
		return nil
	}
	data, err := d.redisClient.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			d.logger.Warn("读取序列状态失败", zap.String("key", key), zap.Error(err))
		}
		return nil
	}
	var state SequenceState
	if err := json.Unmarshal(data, &state); err != nil {
		d.logger.Warn("解析序列状态失败", zap.String("key", key), zap.Error(err))
		return nil
	}
	return &state
}

// setState 将序列状态写入 Redis
func (d *SequenceDetector) setState(ctx context.Context, key string, state *SequenceState, ttl time.Duration) {
	if d.redisClient == nil {
		return
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	d.redisClient.Set(ctx, key, data, ttl)
}

// delState 删除 Redis 中的序列状态
func (d *SequenceDetector) delState(ctx context.Context, key string) {
	if d.redisClient == nil {
		return
	}
	d.redisClient.Del(ctx, key)
}
