// Package celengine - 行为序列检测
// 使用滑动窗口 + Redis 状态机检测多步攻击链
package celengine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// compiledSequenceRule 编译后的序列规则，步骤表达式已预编译
type compiledSequenceRule struct {
	rule     model.SequenceRule
	programs []cel.Program // 与 Steps 一一对应的预编译 Program
	window   time.Duration
}

// SequenceState 序列检测的中间状态（Redis 持久化）
type SequenceState struct {
	RuleID       uint      `json:"rule_id"`
	HostID       string    `json:"host_id"`
	CurrentStep  int       `json:"current_step"`
	StartTime    time.Time `json:"start_time"`
	MatchedSteps []int     `json:"matched_steps"`
}

// memStateEntry 内存状态项（redis 为 nil 时使用），带过期时间
type memStateEntry struct {
	state     *SequenceState
	expiresAt time.Time
}

// SequenceDetector 行为序列检测器
type SequenceDetector struct {
	mu          sync.RWMutex
	rules       []compiledSequenceRule
	db          *gorm.DB
	redisClient *redis.Client
	engine      *Engine
	logger      *zap.Logger

	// memState 内存状态兜底：engine 进程内无 redis 时使用（engine 单副本，
	// kafka 按 host 分区保证同主机事件落同一实例，进程内状态即可支撑顺序状态机）。
	memMu    sync.Mutex
	memState map[string]memStateEntry
}

// NewSequenceDetector 创建序列检测器
// db 可为 nil（测试场景），redisClient 为 nil 时使用进程内内存状态（单副本足够）
func NewSequenceDetector(engine *Engine, db *gorm.DB, redisClient *redis.Client, logger *zap.Logger) *SequenceDetector {
	return &SequenceDetector{
		engine:      engine,
		db:          db,
		redisClient: redisClient,
		logger:      logger,
		memState:    make(map[string]memStateEntry),
	}
}

// ReloadRules 从数据库加载启用的序列规则并预编译
func (d *SequenceDetector) ReloadRules() error {
	if d.db == nil {
		return nil
	}

	var dbRules []model.SequenceRule
	if err := d.db.Where("enabled = ?", true).Find(&dbRules).Error; err != nil {
		return fmt.Errorf("加载序列规则失败: %w", err)
	}

	compiled, compileErrors := d.compileRules(dbRules)

	d.mu.Lock()
	d.rules = compiled
	d.mu.Unlock()

	d.logger.Info("序列规则加载完成",
		zap.Int("total", len(dbRules)),
		zap.Int("compiled", len(compiled)),
		zap.Int("errors", compileErrors),
	)
	return nil
}

// StartReload 启动周期性规则重载，使新增/修改的序列规则无需重启即可生效
func (d *SequenceDetector) StartReload(ctx context.Context) {
	if d.db == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := d.ReloadRules(); err != nil {
					d.logger.Warn("序列规则周期重载失败", zap.Error(err))
				}
			}
		}
	}()
}

// SetRules 设置规则（用于测试，不依赖数据库）
func (d *SequenceDetector) SetRules(rules []model.SequenceRule) int {
	compiled, _ := d.compileRules(rules)
	d.mu.Lock()
	d.rules = compiled
	d.mu.Unlock()
	return len(compiled)
}

// compileRules 编译序列规则列表
func (d *SequenceDetector) compileRules(rules []model.SequenceRule) ([]compiledSequenceRule, int) {
	compiled := make([]compiledSequenceRule, 0, len(rules))
	var compileErrors int

	for _, rule := range rules {
		if len(rule.Steps) == 0 {
			continue
		}

		programs := make([]cel.Program, 0, len(rule.Steps))
		ok := true
		for _, step := range rule.Steps {
			program, err := d.engine.CompileExpression(step.Expression)
			if err != nil {
				compileErrors++
				d.logger.Error("编译序列步骤失败",
					zap.String("rule_name", rule.Name),
					zap.String("step_name", step.Name),
					zap.Error(err),
				)
				ok = false
				break
			}
			programs = append(programs, program)
		}
		if !ok {
			continue
		}

		compiled = append(compiled, compiledSequenceRule{
			rule:     rule,
			programs: programs,
			window:   time.Duration(rule.WindowSecs) * time.Second,
		})
	}

	return compiled, compileErrors
}

// RuleCount 返回当前加载的序列规则数量
func (d *SequenceDetector) RuleCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.rules)
}

// Evaluate 评估事件是否命中序列规则的某个步骤
// 返回完整匹配（所有步骤按序命中）的规则列表
func (d *SequenceDetector) Evaluate(hostID string, dataType int32, fields map[string]string) []model.SequenceRule {
	d.mu.RLock()
	rules := d.rules
	d.mu.RUnlock()

	var matched []model.SequenceRule
	ctx := context.Background()

	activation := buildActivation(dataType, fields)

	for i := range rules {
		cr := &rules[i]
		stateKey := fmt.Sprintf("mxcwpp:seq:%d:%s", cr.rule.ID, hostID)

		state := d.getState(ctx, stateKey)

		if state == nil {
			// 检查是否匹配第一步
			if d.evalProgram(cr.programs[0], activation) {
				state = &SequenceState{
					RuleID:       cr.rule.ID,
					HostID:       hostID,
					CurrentStep:  1,
					StartTime:    time.Now(),
					MatchedSteps: []int{0},
				}
				d.setState(ctx, stateKey, state, cr.window)
			}
			continue
		}

		// 窗口过期
		if time.Since(state.StartTime) > cr.window {
			d.delState(ctx, stateKey)
			continue
		}

		// 检查下一步
		nextStep := state.CurrentStep
		if nextStep >= len(cr.programs) {
			continue
		}

		if d.evalProgram(cr.programs[nextStep], activation) {
			state.CurrentStep++
			state.MatchedSteps = append(state.MatchedSteps, nextStep)

			if state.CurrentStep >= len(cr.programs) {
				matched = append(matched, cr.rule)
				d.delState(ctx, stateKey)
				d.logger.Info("序列规则命中",
					zap.Uint("rule_id", cr.rule.ID),
					zap.String("rule_name", cr.rule.Name),
					zap.String("host_id", hostID),
				)
			} else {
				d.setState(ctx, stateKey, state, cr.window)
			}
		}
	}

	return matched
}

// evalProgram 对预编译的 Program 求值
func (d *SequenceDetector) evalProgram(program cel.Program, activation map[string]any) bool {
	out, _, err := program.Eval(activation)
	if err != nil {
		return false
	}
	return out.Value() == true
}

// getState 从 Redis（或内存兜底）获取序列状态
func (d *SequenceDetector) getState(ctx context.Context, key string) *SequenceState {
	if d.redisClient == nil {
		d.memMu.Lock()
		defer d.memMu.Unlock()
		e, ok := d.memState[key]
		if !ok {
			return nil
		}
		if time.Now().After(e.expiresAt) {
			delete(d.memState, key)
			return nil
		}
		return e.state
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

// setState 将序列状态写入 Redis（或内存兜底）
func (d *SequenceDetector) setState(ctx context.Context, key string, state *SequenceState, ttl time.Duration) {
	if d.redisClient == nil {
		d.memMu.Lock()
		d.memState[key] = memStateEntry{state: state, expiresAt: time.Now().Add(ttl)}
		d.memMu.Unlock()
		return
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	d.redisClient.Set(ctx, key, data, ttl)
}

// delState 删除 Redis（或内存兜底）中的序列状态
func (d *SequenceDetector) delState(ctx context.Context, key string) {
	if d.redisClient == nil {
		d.memMu.Lock()
		delete(d.memState, key)
		d.memMu.Unlock()
		return
	}
	d.redisClient.Del(ctx, key)
}
