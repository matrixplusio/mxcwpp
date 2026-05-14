// Package engine 提供采集引擎的核心功能
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	plugins "github.com/imkerbos/mxsec-platform/plugins/lib/go"
)

// Handler 是采集器接口
type Handler interface {
	// Collect 执行采集，返回资产数据列表
	Collect(ctx context.Context) ([]interface{}, error)
}

// HandlerConfig 是采集器配置
type HandlerConfig struct {
	Name     string        // 采集器名称
	Interval time.Duration // 采集间隔
	Handler  Handler       // 采集器实现
}

// Engine 是采集引擎
type Engine struct {
	client   *plugins.Client
	logger   *zap.Logger
	handlers map[string]*HandlerConfig
	mu       sync.RWMutex
}

// NewEngine 创建新的采集引擎
func NewEngine(client *plugins.Client, logger *zap.Logger) *Engine {
	return &Engine{
		client:   client,
		logger:   logger,
		handlers: make(map[string]*HandlerConfig),
	}
}

// RegisterHandler 注册采集器
func (e *Engine) RegisterHandler(name string, interval time.Duration, handler Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.handlers[name] = &HandlerConfig{
		Name:     name,
		Interval: interval,
		Handler:  handler,
	}

	e.logger.Info("registered collector handler",
		zap.String("name", name),
		zap.Duration("interval", interval))
}

// Run 启动采集引擎，执行定时采集
func (e *Engine) Run(ctx context.Context) {
	e.mu.RLock()
	handlers := make([]*HandlerConfig, 0, len(e.handlers))
	for _, h := range e.handlers {
		handlers = append(handlers, h)
	}
	e.mu.RUnlock()

	// 为每个采集器启动独立的 goroutine
	for _, h := range handlers {
		go e.runHandler(ctx, h)
	}

	// 等待上下文取消
	<-ctx.Done()
	e.logger.Info("collector engine stopped")
}

// runHandler 运行单个采集器
func (e *Engine) runHandler(ctx context.Context, h *HandlerConfig) {
	ticker := time.NewTicker(h.Interval)
	defer ticker.Stop()

	// 立即执行一次
	if err := e.collectAndReport(ctx, h); err != nil {
		e.logger.Error("failed to collect",
			zap.String("handler", h.Name),
			zap.Error(err))
	}

	// 定时采集
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.collectAndReport(ctx, h); err != nil {
				e.logger.Error("failed to collect",
					zap.String("handler", h.Name),
					zap.Error(err))
			}
		}
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

// collectAndReport 执行采集并上报
func (e *Engine) collectAndReport(ctx context.Context, h *HandlerConfig) error {
	e.logger.Debug("collecting assets", zap.String("handler", h.Name))

	// 执行采集
	assets, err := h.Handler.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect failed: %w", err)
	}

	if len(assets) == 0 {
		e.logger.Debug("no assets collected", zap.String("handler", h.Name))
		return nil
	}

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

	e.logger.Info("assets collected and reported",
		zap.String("handler", h.Name),
		zap.Int("count", len(assets)))

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
