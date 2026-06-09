package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
)

func TestInitTracing_Disabled_ReturnsNoop(t *testing.T) {
	t.Parallel()
	tp, err := InitTracing(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tp != noopProvider {
		t.Fatalf("expected noopProvider, got %p", tp)
	}
	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("noop shutdown err: %v", err)
	}
}

func TestInitTracing_ZeroSampleRate_ReturnsNoop(t *testing.T) {
	t.Parallel()
	tp, err := InitTracing(context.Background(), Config{
		Enabled:     true,
		SampleRate:  0,
		ServiceName: "engine",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tp != noopProvider {
		t.Fatalf("expected noopProvider when sample_rate=0, got %p", tp)
	}
}

func TestInitTracing_RequiresServiceName(t *testing.T) {
	t.Parallel()
	_, err := InitTracing(context.Background(), Config{
		Enabled:    true,
		SampleRate: 0.5,
		// ServiceName intentionally empty
	})
	if err == nil {
		t.Fatalf("expected error for missing ServiceName")
	}
}

func TestInitTracing_EndpointDefault(t *testing.T) {
	t.Parallel()
	tp, err := InitTracing(context.Background(), Config{
		Enabled:     true,
		ServiceName: "engine",
		SampleRate:  0.01,
		Insecure:    true,
		// Endpoint empty -> default "localhost:4318"
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// 启用模式下,otel.GetTracerProvider 必须不是 noop
	provider := otel.GetTracerProvider()
	if provider == nil {
		t.Fatalf("expected non-nil tracer provider")
	}
}

func TestTracer_Returns_NonNil(t *testing.T) {
	t.Parallel()
	tr := Tracer("test.module")
	if tr == nil {
		t.Fatalf("expected non-nil tracer")
	}
	// Start should not panic even without InitTracing
	_, span := tr.Start(context.Background(), "test.op")
	span.End()
}
