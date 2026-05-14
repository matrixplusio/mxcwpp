// Package celengine 实现基于 CEL-Go 的实时检测规则引擎
// 支持从数据库加载 CEL 表达式规则，对 Kafka 消费事件进行实时评估并生成告警
package celengine

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// compiledRule 编译后的规则，包含原始规则信息和 CEL Program
type compiledRule struct {
	rule    model.DetectionRule
	program cel.Program
}

// Engine CEL 规则引擎
// 负责维护 CEL 环境、编译规则、评估事件
type Engine struct {
	mu    sync.RWMutex
	env   *cel.Env
	rules []compiledRule
	db    *gorm.DB
	log   *zap.Logger
}

// New 创建 CEL 规则引擎实例
// 初始化 CEL 环境并从数据库加载规则
func New(db *gorm.DB, logger *zap.Logger) (*Engine, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("初始化 CEL 环境失败: %w", err)
	}

	e := &Engine{
		env: env,
		db:  db,
		log: logger,
	}

	// 首次加载规则
	if err := e.ReloadRules(); err != nil {
		return nil, fmt.Errorf("首次加载规则失败: %w", err)
	}

	return e, nil
}

// NewInMemory 创建内存 CEL 引擎（用于测试，不依赖数据库）
func NewInMemory(logger *zap.Logger, rules []model.DetectionRule) (*Engine, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("初始化 CEL 环境失败: %w", err)
	}

	e := &Engine{
		env: env,
		log: logger,
	}

	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		program, err := e.compile(rule.Expression)
		if err != nil {
			logger.Error("编译规则失败", zap.String("name", rule.Name), zap.Error(err))
			continue
		}
		compiled = append(compiled, compiledRule{rule: rule, program: program})
	}
	e.rules = compiled

	return e, nil
}

// newCELEnv 创建 CEL 环境，声明所有事件变量
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// 事件基础字段
		cel.Variable("data_type", cel.IntType),
		cel.Variable("agent_id", cel.StringType),
		cel.Variable("hostname", cel.StringType),

		// 进程相关
		cel.Variable("event_type", cel.StringType),
		cel.Variable("pid", cel.StringType),
		cel.Variable("ppid", cel.StringType),
		cel.Variable("exe", cel.StringType),
		cel.Variable("cmdline", cel.StringType),
		cel.Variable("parent_exe", cel.StringType),
		cel.Variable("uid", cel.StringType),
		cel.Variable("username", cel.StringType),

		// 文件相关
		cel.Variable("file_path", cel.StringType),
		cel.Variable("file_action", cel.StringType),

		// 网络相关
		cel.Variable("remote_addr", cel.StringType),
		cel.Variable("remote_port", cel.StringType),
		cel.Variable("local_addr", cel.StringType),
		cel.Variable("local_port", cel.StringType),
		cel.Variable("protocol", cel.StringType),

		// 安全相关
		cel.Variable("severity", cel.StringType),
		cel.Variable("threat_name", cel.StringType),

		// 性能相关
		cel.Variable("cpu_usage", cel.StringType),
		cel.Variable("mem_usage", cel.StringType),
	)
}

// ReloadRules 从数据库重新加载所有启用的规则并编译
// 支持热更新：在规则变更后调用此方法即可生效
func (e *Engine) ReloadRules() error {
	rules, err := LoadRulesFromDB(e.db)
	if err != nil {
		return fmt.Errorf("从数据库加载规则失败: %w", err)
	}

	compiled := make([]compiledRule, 0, len(rules))
	var compileErrors int

	for _, rule := range rules {
		program, err := e.compile(rule.Expression)
		if err != nil {
			compileErrors++
			e.log.Error("编译 CEL 规则失败",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("expression", rule.Expression),
				zap.Error(err),
			)
			continue
		}
		compiled = append(compiled, compiledRule{rule: rule, program: program})
	}

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()

	e.log.Info("CEL 规则加载完成",
		zap.Int("total", len(rules)),
		zap.Int("compiled", len(compiled)),
		zap.Int("errors", compileErrors),
	)

	return nil
}

// compile 将 CEL 表达式编译为 Program
func (e *Engine) compile(expression string) (cel.Program, error) {
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("编译错误: %w", issues.Err())
	}

	// 检查返回类型必须为 bool
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("表达式返回类型必须为 bool，实际为 %s", ast.OutputType())
	}

	program, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("创建 Program 失败: %w", err)
	}

	return program, nil
}

// Evaluate 对事件进行规则评估
// dataType: 事件类型（用于过滤适用规则）
// fields: 事件字段键值对
// 返回匹配的规则列表
func (e *Engine) Evaluate(dataType int32, fields map[string]string) []model.DetectionRule {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	// 构建 CEL 求值变量：将 fields 中的 string 值填充到 activation map
	// 未提供的变量默认为空字符串，data_type 单独处理为 int64
	activation := buildActivation(dataType, fields)

	var matched []model.DetectionRule

	for _, cr := range rules {
		// DataType 过滤：如果规则指定了 DataTypes，则只对匹配的事件求值
		if !cr.rule.MatchesDataType(dataType) {
			continue
		}

		out, _, err := cr.program.Eval(activation)
		if err != nil {
			// CEL 运行时错误（类型不匹配、字段缺失等），记录但不中断
			e.log.Debug("CEL 规则求值错误",
				zap.Uint("rule_id", cr.rule.ID),
				zap.String("rule_name", cr.rule.Name),
				zap.Error(err),
			)
			continue
		}

		// 结果为 true 表示规则命中
		if out.Value() == true {
			matched = append(matched, cr.rule)
		}
	}

	return matched
}

// CompileExpression 编译单个 CEL 表达式为 Program（供序列检测等外部模块使用）
func (e *Engine) CompileExpression(expression string) (cel.Program, error) {
	return e.compile(expression)
}

// RuleCount 返回当前加载的规则数量
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// buildActivation 将事件字段构建为 CEL 求值变量 map
// 所有在 CEL 环境中声明的 string 变量，如果 fields 中未提供则默认为空字符串
func buildActivation(dataType int32, fields map[string]string) map[string]interface{} {
	// 声明所有 CEL 环境中定义的 string 变量名
	stringVars := []string{
		"agent_id", "hostname",
		"event_type", "pid", "ppid", "exe", "cmdline", "parent_exe", "uid", "username",
		"file_path", "file_action",
		"remote_addr", "remote_port", "local_addr", "local_port", "protocol",
		"severity", "threat_name",
		"cpu_usage", "mem_usage",
	}

	activation := make(map[string]interface{}, len(stringVars)+1)

	// data_type 为 int 类型
	activation["data_type"] = int64(dataType)

	// 填充 string 变量
	for _, name := range stringVars {
		if v, ok := fields[name]; ok {
			activation[name] = v
		} else {
			activation[name] = ""
		}
	}

	return activation
}
