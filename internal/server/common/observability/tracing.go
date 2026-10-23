// Package observability 提供 OpenTelemetry 追踪初始化与 Tracer 全局访问。
//
// v2.0 六微服务架构所有控制面 / 数据面服务统一使用该包初始化 OTel:
//
//	tp, err := observability.InitTracing(ctx, observability.Config{
//	    Enabled:     true,
//	    ServiceName: "engine",
//	    Endpoint:    "http://otel-collector:4318",
//	    SampleRate:  0.1,
//	})
//	if err != nil { ... }
//	defer tp.Shutdown(ctx)
//
//	tracer := observability.Tracer("engine.detection")
//	ctx, span := tracer.Start(ctx, "ProcessAlert")
//	defer span.End()
//
// 设计文档: docs/architecture.md §11 关键代码路径 / docs/configuration.md OTel.
package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config 是 OTel 追踪初始化配置。
type Config struct {
	// Enabled 是否启用 OTel 上报。
	// 关闭时所有 Tracer() 返回 noop Tracer (不产生 span,无性能开销)。
	Enabled bool

	// ServiceName 在 OTel 资源属性中标识服务名。
	// 必填,如 "manager" / "agentcenter" / "consumer" / "engine" / "vulnsync" / "llmproxy"。
	ServiceName string

	// ServiceVersion 服务语义化版本,如 "2.0.0"。可选。
	ServiceVersion string

	// Endpoint OTLP HTTP collector 端点,默认 "localhost:4318"。
	// 不需要带 scheme; Insecure=true 时走 HTTP,否则 HTTPS。
	Endpoint string

	// Insecure 是否走 HTTP (vs HTTPS)。默认 true (典型部署 collector 在内网)。
	Insecure bool

	// SampleRate 采样率,0.0~1.0。0=不采样(等价 Enabled=false),1=全量。
	// 推荐生产 0.05~0.1。
	SampleRate float64

	// Headers 附加给 collector 的认证头 (云托管 OTLP 用)。
	Headers map[string]string
}

// TracerProvider 包装 sdktrace.TracerProvider 与对应的 exporter,
// 提供统一 Shutdown 入口。
type TracerProvider struct {
	tp       *sdktrace.TracerProvider
	exporter *otlptrace.Exporter
}

// Shutdown 优雅关闭 (flush remaining spans)。
// 应在 main 退出前 defer 调用。
func (p *TracerProvider) Shutdown(ctx context.Context) error {
	if p == nil || p.tp == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := p.tp.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("tracer provider shutdown: %w", err)
	}
	return nil
}

// noopProvider 表示禁用 OTel 时的占位 TracerProvider。
var noopProvider = &TracerProvider{}

// InitTracing 初始化 OTel 全局 TracerProvider 与 Propagator。
//
// Enabled=false 或 SampleRate=0 时返回 noop provider,不创建 exporter。
// 调用方仍应 defer Shutdown,noop provider 的 Shutdown 是 no-op。
func InitTracing(ctx context.Context, cfg Config) (*TracerProvider, error) {
	if !cfg.Enabled || cfg.SampleRate <= 0 {
		otel.SetTracerProvider(noop.NewTracerProvider())
		setTextMapPropagator()
		return noopProvider, nil
	}
	if cfg.ServiceName == "" {
		return nil, fmt.Errorf("observability: ServiceName is required when Enabled=true")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "localhost:4318"
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlptracehttp.New: %w", err)
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))),
		sdktrace.WithResource(newResource(attrs...)),
	)
	otel.SetTracerProvider(tp)
	setTextMapPropagator()

	return &TracerProvider{tp: tp, exporter: exporter}, nil
}

// Tracer 返回指定 instrumentationName 的 OTel Tracer。
// 必须在 InitTracing 之后调用; 否则返回全局 noop Tracer (默认)。
func Tracer(instrumentationName string) trace.Tracer {
	return otel.Tracer(instrumentationName)
}

// setTextMapPropagator 注册标准 propagator (TraceContext + Baggage),
// 用于跨服务 trace_id 传播 (HTTP / gRPC / Kafka header)。
func setTextMapPropagator() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
}
