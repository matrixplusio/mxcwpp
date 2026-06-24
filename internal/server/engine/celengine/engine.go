// Package celengine 实现基于 CEL-Go 的实时检测规则引擎
// 支持从数据库加载 CEL 表达式规则，对 Kafka 消费事件进行实时评估并生成告警
package celengine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// defaultWorkers 默认并行 worker 数量
	defaultWorkers = 4
	// parallelThreshold 规则数达到此阈值时启用并行求值
	parallelThreshold = 20
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
	// P0-4: DataType → 适用规则索引, 替 Evaluate O(M) 线性扫为 O(1) 查找
	rulesByDataType map[int32][]compiledRule
	// 全 DataType 适用规则 (DataTypes 列表为空 → 任意 DataType 都用)
	rulesAnyDataType []compiledRule
	db               *gorm.DB
	log              *zap.Logger
	procTree         *ProcessTree  // 进程树（自动维护，用于祖先链查询）
	tracker          *EventTracker // 事件频率/首次出现追踪
	workers          int           // 并行 worker 数量
}

// New 创建 CEL 规则引擎实例
// 初始化 CEL 环境并从数据库加载规则
func New(db *gorm.DB, logger *zap.Logger) (*Engine, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("初始化 CEL 环境失败: %w", err)
	}

	e := &Engine{
		env:      env,
		db:       db,
		log:      logger,
		procTree: NewProcessTree(logger),
		tracker:  NewEventTracker(logger),
		workers:  defaultWorkers,
	}

	// 首次加载规则
	if err := e.ReloadRules(); err != nil {
		return nil, fmt.Errorf("首次加载规则失败: %w", err)
	}

	return e, nil
}

// SetWorkers 设置并行求值 worker 数量（1 = 禁用并行）
func (e *Engine) SetWorkers(n int) {
	if n < 1 {
		n = 1
	}
	e.workers = n
}

// NewInMemory 创建内存 CEL 引擎（用于测试，不依赖数据库）
func NewInMemory(logger *zap.Logger, rules []model.DetectionRule) (*Engine, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("初始化 CEL 环境失败: %w", err)
	}

	e := &Engine{
		env:      env,
		log:      logger,
		procTree: NewProcessTree(logger),
		tracker:  NewEventTracker(logger),
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
	e.rebuildDataTypeIndex()

	return e, nil
}

// rebuildDataTypeIndex 重建 DataType → 规则索引 (P0-4).
//
// 调用者必须持 e.mu.Lock(), 该函数内不再加锁.
func (e *Engine) rebuildDataTypeIndex() {
	byDT := make(map[int32][]compiledRule, 16)
	var anyDT []compiledRule
	for _, cr := range e.rules {
		if len(cr.rule.DataTypes) == 0 {
			anyDT = append(anyDT, cr)
			continue
		}
		seen := make(map[int32]bool, len(cr.rule.DataTypes))
		for _, dtStr := range cr.rule.DataTypes {
			var dt int32
			for _, c := range dtStr {
				if c < '0' || c > '9' {
					dt = -1
					break
				}
				dt = dt*10 + int32(c-'0')
			}
			if dt < 0 {
				continue
			}
			if seen[dt] {
				continue
			}
			seen[dt] = true
			byDT[dt] = append(byDT[dt], cr)
		}
	}
	e.rulesByDataType = byDT
	e.rulesAnyDataType = anyDT
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
		// comm: 进程 argv[0] / task->comm (16 字节内核字段).
		// kthread 伪装检测靠此字段 (exec -a '[kworker/...]' 改写 argv[0]).
		cel.Variable("comm", cel.StringType),
		cel.Variable("uid", cel.StringType),
		cel.Variable("username", cel.StringType),
		cel.Variable("cwd", cel.StringType),

		// 文件相关
		cel.Variable("file_path", cel.StringType),
		cel.Variable("file_action", cel.StringType),

		// 网络相关
		cel.Variable("remote_addr", cel.StringType),
		cel.Variable("remote_port", cel.StringType),
		cel.Variable("local_addr", cel.StringType),
		cel.Variable("local_port", cel.StringType),
		cel.Variable("protocol", cel.StringType),
		cel.Variable("dns_server", cel.StringType),

		// 安全相关
		cel.Variable("severity", cel.StringType),
		cel.Variable("threat_name", cel.StringType),

		// Agent 端 IOC 碰撞标注（由 Agent EDR 引擎在事件转发前写入）
		cel.Variable("ioc_match", cel.StringType),
		cel.Variable("ioc_type", cel.StringType),
		cel.Variable("ioc_value", cel.StringType),

		// Agent 端规则匹配标注
		cel.Variable("agent_match", cel.StringType),
		cel.Variable("agent_rule_id", cel.StringType),
		cel.Variable("agent_severity", cel.StringType),

		// 聚合标注
		cel.Variable("agg_count", cel.StringType),

		// 性能相关
		cel.Variable("cpu_usage", cel.StringType),
		cel.Variable("mem_usage", cel.StringType),

		// 进程树：祖先链 exe 列表（由 Engine 自动填充）
		cel.Variable("ancestor_exes", cel.ListType(cel.StringType)),

		// EventTracker 预计算变量：滑动窗口计数
		cel.Variable("recent_exe_count", cel.IntType),
		cel.Variable("recent_remote_addr_count", cel.IntType),
		cel.Variable("recent_file_path_count", cel.IntType),

		// EventTracker 预计算变量：首次出现标记
		cel.Variable("first_seen_exe", cel.BoolType),
		cel.Variable("first_seen_remote_addr", cel.BoolType),

		// 自定义函数：is_private_ip(string) -> bool
		cel.Function("is_private_ip",
			cel.Overload("is_private_ip_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					addr, ok := val.Value().(string)
					if !ok {
						return types.Bool(false)
					}
					return types.Bool(isPrivateIP(addr))
				}),
			),
		),
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
	e.rebuildDataTypeIndex()
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

	// CostLimit 限制单次求值成本，防规则作者提交资源耗尽型表达式拖垮 engine（DoS）。
	program, err := e.env.Program(ast, cel.CostLimit(1_000_000))
	if err != nil {
		return nil, fmt.Errorf("创建 Program 失败: %w", err)
	}

	return program, nil
}

// Evaluate 对事件进行规则评估
// dataType: 事件类型（用于过滤适用规则）
// fields: 事件字段键值对
// 返回匹配的规则列表
//
// 当适用规则数 >= parallelThreshold 且 workers > 1 时，自动切换为并行求值。
func (e *Engine) Evaluate(dataType int32, fields map[string]string) []model.DetectionRule {
	// 进程事件自动维护进程树
	if dataType == 3000 && e.procTree != nil {
		e.feedProcessTree(fields)
	}

	// P0-4: 用 DataType 索引取适用规则, 避免 O(M) 线性扫
	e.mu.RLock()
	indexed := e.rulesByDataType[dataType]
	anyIdx := e.rulesAnyDataType
	e.mu.RUnlock()

	// 构建 CEL 求值变量
	activation := buildActivation(dataType, fields)

	// 填充祖先链 exe 列表
	if e.procTree != nil && fields["pid"] != "" {
		chain := e.procTree.GetAncestorChain(fields["agent_id"], fields["pid"])
		if chain == nil {
			chain = []string{}
		}
		activation["ancestor_exes"] = chain
	} else {
		activation["ancestor_exes"] = []string{}
	}

	// EventTracker：计算滑动窗口计数和首次出现标记
	hostID := fields["agent_id"]
	if e.tracker != nil && hostID != "" {
		exeCount, exeFirst := e.tracker.Observe(hostID, "exe", fields["exe"])
		activation["recent_exe_count"] = exeCount
		activation["first_seen_exe"] = exeFirst

		addrCount, addrFirst := e.tracker.Observe(hostID, "remote_addr", fields["remote_addr"])
		activation["recent_remote_addr_count"] = addrCount
		activation["first_seen_remote_addr"] = addrFirst

		fpCount, _ := e.tracker.Observe(hostID, "file_path", fields["file_path"])
		activation["recent_file_path_count"] = fpCount
	} else {
		activation["recent_exe_count"] = int64(0)
		activation["recent_remote_addr_count"] = int64(0)
		activation["recent_file_path_count"] = int64(0)
		activation["first_seen_exe"] = false
		activation["first_seen_remote_addr"] = false
	}

	// P0-4: 直接拼索引 + any DataType 兜底, 无线性扫
	applicable := make([]compiledRule, 0, len(indexed)+len(anyIdx))
	applicable = append(applicable, indexed...)
	applicable = append(applicable, anyIdx...)

	if len(applicable) == 0 {
		return nil
	}

	// 规则数超过阈值时并行求值
	if len(applicable) >= parallelThreshold && e.workers > 1 {
		return e.evaluateParallel(applicable, activation)
	}

	return e.evaluateSequential(applicable, activation)
}

// evaluateSequential 顺序求值（规则数少时使用，避免 goroutine 开销）
func (e *Engine) evaluateSequential(rules []compiledRule, activation map[string]any) []model.DetectionRule {
	var matched []model.DetectionRule
	for _, cr := range rules {
		out, _, err := cr.program.Eval(activation)
		if err != nil {
			e.log.Debug("CEL 规则求值错误",
				zap.Uint("rule_id", cr.rule.ID),
				zap.String("rule_name", cr.rule.Name),
				zap.Error(err),
			)
			continue
		}
		if out.Value() == true {
			matched = append(matched, cr.rule)
		}
	}
	return matched
}

// evaluateParallel 将规则分片到多个 goroutine 并行求值
// activation 是只读的，cel.Program.Eval 是线程安全的。
func (e *Engine) evaluateParallel(rules []compiledRule, activation map[string]any) []model.DetectionRule {
	workers := min(e.workers, len(rules))
	chunkSize := (len(rules) + workers - 1) / workers

	var mu sync.Mutex
	var matched []model.DetectionRule
	var wg sync.WaitGroup

	for i := 0; i < len(rules); i += chunkSize {
		end := min(i+chunkSize, len(rules))
		batch := rules[i:end]

		wg.Add(1)
		go func(chunk []compiledRule) {
			defer wg.Done()
			var local []model.DetectionRule
			for _, cr := range chunk {
				out, _, err := cr.program.Eval(activation)
				if err != nil {
					continue
				}
				if out.Value() == true {
					local = append(local, cr.rule)
				}
			}
			if len(local) > 0 {
				mu.Lock()
				matched = append(matched, local...)
				mu.Unlock()
			}
		}(batch)
	}

	wg.Wait()
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
func buildActivation(dataType int32, fields map[string]string) map[string]any {
	// 声明所有 CEL 环境中定义的 string 变量名
	stringVars := []string{
		"agent_id", "hostname",
		"event_type", "pid", "ppid", "exe", "cmdline", "parent_exe", "comm", "uid", "username", "cwd",
		"file_path", "file_action",
		"remote_addr", "remote_port", "local_addr", "local_port", "protocol", "dns_server",
		"severity", "threat_name",
		"ioc_match", "ioc_type", "ioc_value",
		"agent_match", "agent_rule_id", "agent_severity",
		"agg_count",
		"cpu_usage", "mem_usage",
	}

	activation := make(map[string]any, len(stringVars)+1)

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

// feedProcessTree 将进程事件路由到进程树
func (e *Engine) feedProcessTree(fields map[string]string) {
	hostID := fields["agent_id"]
	if hostID == "" {
		return
	}
	switch fields["event_type"] {
	case "process_exec":
		e.procTree.HandleExec(hostID, fields)
	case "process_exit":
		e.procTree.HandleExit(hostID, fields)
	}
}

// StartCleanup 启动进程树和事件追踪器的定期清理协程
func (e *Engine) StartCleanup(ctx context.Context) {
	// 进程树清理
	if e.procTree != nil {
		go func() {
			ticker := time.NewTicker(processTreeCleanupInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					removed := e.procTree.Cleanup()
					if removed > 0 {
						hosts, nodes := e.procTree.Stats()
						e.log.Info("进程树定期清理",
							zap.Int("removed", removed),
							zap.Int("hosts", hosts),
							zap.Int("nodes", nodes),
						)
					}
				}
			}
		}()
	}

	// EventTracker 清理
	if e.tracker != nil {
		go func() {
			ticker := time.NewTicker(trackerWindowDuration)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					removed := e.tracker.Cleanup()
					if removed > 0 {
						hosts, wKeys, kKeys := e.tracker.Stats()
						e.log.Info("事件追踪器定期清理",
							zap.Int("removed", removed),
							zap.Int("hosts", hosts),
							zap.Int("window_keys", wKeys),
							zap.Int("known_keys", kKeys),
						)
					}
				}
			}
		}()
	}
}

// ProcessTreeStats 返回进程树统计信息
func (e *Engine) ProcessTreeStats() (hosts, nodes int) {
	if e.procTree == nil {
		return 0, 0
	}
	return e.procTree.Stats()
}

// TrackerStats 返回事件追踪器统计信息
func (e *Engine) TrackerStats() (hosts, windowKeys, knownKeys int) {
	if e.tracker == nil {
		return 0, 0, 0
	}
	return e.tracker.Stats()
}
