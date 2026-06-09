package observability

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// newResource 构造 OTel resource 元数据 (附在每个 span 上)。
// 包含 telemetry.sdk.* + 调用方传入的属性。
func newResource(attrs ...attribute.KeyValue) *resource.Resource {
	base := []attribute.KeyValue{
		semconv.TelemetrySDKLanguageGo,
	}
	base = append(base, attrs...)
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		base...,
	)
}
