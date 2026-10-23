// Package engine 提供采集引擎的核心功能
package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	plugins "github.com/matrixplusio/mxcwpp/plugins/lib/go"
)

// Handler 是采集器接口
type Handler interface {
	// Collect 执行采集，返回资产数据列表
	Collect(ctx context.Context) ([]interface{}, error)
}

// HandlerConfig 是采集器配置
type HandlerConfig struct {
	Name     string        // 采集器名称
	Priority int           // 首轮采集顺序，越小越先；相同时按名称
	Interval time.Duration // 采集间隔
	Handler  Handler       // 采集器实现
}

// Engine 是采集引擎
type Engine struct {
	client   *plugins.Client
	logger   *zap.Logger
	handlers map[string]*HandlerConfig
	mu       sync.RWMutex
	// slot 让任意时刻只有一个采集器在跑。采集器各自全量遍历 /proc、软件包库、文件系统，
	// 并行时 CPU 与磁盘 IO 叠加，在进程多、IO 忙的业务机（数据库、监控机）上会和业务抢资源。
	slot chan struct{}
	// report 上报采集结果；测试替换为桩。
	report func(h *HandlerConfig, assets []interface{}) error
}

// NewEngine 创建新的采集引擎
func NewEngine(client *plugins.Client, logger *zap.Logger) *Engine {
	e := &Engine{
		client:   client,
		logger:   logger,
		handlers: make(map[string]*HandlerConfig),
		slot:     make(chan struct{}, 1),
	}
	e.report = e.send
	return e
}

// RegisterHandler 注册采集器
func (e *Engine) RegisterHandler(name string, priority int, interval time.Duration, handler Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.handlers[name] = &HandlerConfig{
		Name:     name,
		Priority: priority,
		Interval: interval,
		Handler:  handler,
	}

	e.logger.Info("registered collector handler",
		zap.String("name", name),
		zap.Int("priority", priority),
		zap.Duration("interval", interval))
}

// Run 启动采集引擎。
//
// 首轮按优先级逐个执行：安全相关、开销小的（进程、端口）先出数据，遍历文件系统的重型扫描排在最后。
// 每个采集器首轮完成后才开始它自己的周期；周期到点的采集同样排队，不与其它采集器并行。
func (e *Engine) Run(ctx context.Context) {
	e.mu.RLock()
	handlers := make([]*HandlerConfig, 0, len(e.handlers))
	for _, h := range e.handlers {
		handlers = append(handlers, h)
	}
	e.mu.RUnlock()

	sort.Slice(handlers, func(i, j int) bool {
		if handlers[i].Priority != handlers[j].Priority {
			return handlers[i].Priority < handlers[j].Priority
		}
		return handlers[i].Name < handlers[j].Name
	})

	for _, h := range handlers {
		if ctx.Err() != nil {
			return
		}
		e.collectLogged(ctx, h)
		go e.runPeriodic(ctx, h)
	}

	<-ctx.Done()
	e.logger.Info("collector engine stopped")
}

// runPeriodic 首轮之后按间隔重复采集。
func (e *Engine) runPeriodic(ctx context.Context, h *HandlerConfig) {
	ticker := time.NewTicker(h.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.collectLogged(ctx, h)
		}
	}
}

func (e *Engine) collectLogged(ctx context.Context, h *HandlerConfig) {
	if err := e.collectAndReport(ctx, h); err != nil && ctx.Err() == nil {
		e.logger.Error("failed to collect", zap.String("handler", h.Name), zap.Error(err))
	}
}

// CollectOnce 执行一次采集（用于任务触发）
func (e *Engine) CollectOnce(ctx context.Context, collectType string) error {
	e.mu.RLock()
	h, ok := e.handlers[collectType]
	e.mu.RUnlock()

	if !ok {
		return fmt.Errorf("handler not found: %s", collectType)
	}

	return e.collectAndReport(ctx, h)
}

// collectAndReport 占用采集槽位后执行采集并上报。
func (e *Engine) collectAndReport(ctx context.Context, h *HandlerConfig) error {
	select {
	case e.slot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-e.slot }()

	start := time.Now()
	assets, err := h.Handler.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect failed: %w", err)
	}
	// 每轮记录耗时：资源占用异常时，这是定位到具体采集器的唯一依据。
	e.logger.Info("collected",
		zap.String("handler", h.Name),
		zap.Int("count", len(assets)),
		zap.Duration("took", time.Since(start)))

	if len(assets) == 0 {
		return nil
	}
	return e.report(h, assets)
}

// send 序列化并上报一个采集器的结果。
func (e *Engine) send(h *HandlerConfig, assets []interface{}) error {
	// 序列化资产数据
	data, err := SerializeAssets(assets)
	if err != nil {
		return fmt.Errorf("failed to serialize assets: %w", err)
	}

	// 获取 data_type
	dataType := GetDataType(h.Name)
	if dataType == 0 {
		return fmt.Errorf("unknown collect type: %s", h.Name)
	}

	// 创建记录
	record := &bridge.Record{
		DataType:  dataType,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"data": string(data),
			},
		},
	}

	// 上报数据
	if err := e.client.SendRecord(record); err != nil {
		return fmt.Errorf("failed to send record: %w", err)
	}
	return nil
}

// GetHandlerNames 获取所有已注册的采集器名称
func (e *Engine) GetHandlerNames() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.handlers))
	for name := range e.handlers {
		names = append(names, name)
	}
	return names
}
