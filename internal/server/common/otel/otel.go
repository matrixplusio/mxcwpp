// Package otel — 5 微服务统一分布式追踪 + metrics 初始化 (B2).
//
// 设计:
//   - 单一 Init(serviceName, cfg) 接口给所有服务调
//   - traces: OTLP HTTP exporter → Jaeger/Tempo/任意 OTel collector
//   - metrics: Prometheus pull 模型 (沿用已有 /metrics endpoint)
//   - traces 走 batch span processor, 默认 sample rate 0.1 (10%)
//
// 不强依赖 OTel SDK 大依赖. 当 Cfg.Enabled=false 时返 nop tracer, 零 overhead.
//
// 后续 PR 在 cmd/server/{manager,agentcenter,consumer,engine,vulnsync,llmproxy}/main.go
// 调用 otel.Init() + defer otel.Shutdown().
package otel

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Config 配置.
type Config struct {
	Enabled       bool          // 总开关
	OTLPEndpoint  string        // OTel collector HTTP endpoint (e.g. http://otel-collector:4318)
	SampleRate    float64       // 0.0~1.0, 默认 0.1
	BatchTimeout  time.Duration // span batch flush (默认 5s)
	ExportTimeout time.Duration // export timeout (默认 30s)
	ServiceName   string        // 服务名 (mxcwpp-manager / mxcwpp-engine 等)
	ServiceVer    string        // 版本号
	Environment   string        // prod / staging / dev
}

// DefaultConfig 合理默认值.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		OTLPEndpoint:  "http://otel-collector:4318",
		SampleRate:    0.1,
		BatchTimeout:  5 * time.Second,
		ExportTimeout: 30 * time.Second,
		Environment:   "dev",
	}
}

// Span 抽象, 不暴露 OTel SDK 类型给业务侧.
type Span interface {
	End()
	SetAttribute(key string, value any)
	RecordError(err error)
	SetStatus(code int, description string)
}

// Tracer 抽象.
type Tracer interface {
	Start(ctx context.Context, name string) (context.Context, Span)
}

// 全局 tracer + shutdown.
var (
	gMu       sync.RWMutex
	gTracer   Tracer = nopTracer{}
	gShutdown func(context.Context) error
)

// Init 初始化 OTel pipeline. 服务启动时调一次.
//
// 失败 (collector 不可达) → fall back nop tracer, 不阻塞服务启动.
func Init(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.ServiceName == "" {
		return errors.New("otel: ServiceName required")
	}
	// 真实 OTel SDK 接入需引 go.opentelemetry.io/otel + exporter, 体积大,
	// 当前 stub 走 nop tracer + 写日志记录意图.
	// 后续 PR 真接入 (替换 nopTracer → otelTracer 实现).
	gMu.Lock()
	defer gMu.Unlock()
	gTracer = &loggingTracer{cfg: cfg}
	gShutdown = func(ctx context.Context) error {
		// 真 OTel SDK 会 flush + shutdown
		return nil
	}
	return nil
}

// Shutdown 优雅关闭 tracer (flush 剩余 span).
func Shutdown(ctx context.Context) error {
	gMu.RLock()
	fn := gShutdown
	gMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(ctx)
}

// T 取当前全局 tracer.
func T() Tracer {
	gMu.RLock()
	defer gMu.RUnlock()
	return gTracer
}

// StartSpan 简写.
func StartSpan(ctx context.Context, name string) (context.Context, Span) {
	return T().Start(ctx, name)
}

// ---- nop tracer (Enabled=false 默认) ----

type nopTracer struct{}

func (nopTracer) Start(ctx context.Context, _ string) (context.Context, Span) {
	return ctx, nopSpan{}
}

type nopSpan struct{}

func (nopSpan) End()                         {}
func (nopSpan) SetAttribute(_ string, _ any) {}
func (nopSpan) RecordError(_ error)          {}
func (nopSpan) SetStatus(_ int, _ string)    {}

// ---- logging tracer (轻量替代品, 用 zap 记录 span) ----

type loggingTracer struct {
	cfg Config
}

func (t *loggingTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	return ctx, &loggingSpan{name: name, startedAt: time.Now()}
}

type loggingSpan struct {
	name       string
	startedAt  time.Time
	attrs      map[string]any
	statusCode int
	statusDesc string
	err        error
}

func (s *loggingSpan) End() {
	// 实际生产用 OTel exporter; 此 stub 不做事.
	// 后续 PR 接 zap + 异步 batch flush.
}

func (s *loggingSpan) SetAttribute(key string, value any) {
	if s.attrs == nil {
		s.attrs = make(map[string]any)
	}
	s.attrs[key] = value
}

func (s *loggingSpan) RecordError(err error) {
	s.err = err
}

func (s *loggingSpan) SetStatus(code int, description string) {
	s.statusCode = code
	s.statusDesc = description
}
