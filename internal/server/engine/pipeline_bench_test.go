package engine

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"

	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
)

// BenchmarkPipeline_NoStages 跑 pipeline 主路径无 stage 时的开销。
//
// 用途: 反映 Kafka 消息解析 + envelope 构造的基线成本。
func BenchmarkPipeline_NoStages(b *testing.B) {
	p := NewPipeline(nil, nil, nil, nil)
	h := p.Handler()
	msg := &sarama.ConsumerMessage{
		Topic: "mxcwpp.agent.process",
		Value: []byte(`{"tenant_id":"t1","host_id":"h1","data_type":1000}`),
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h(context.Background(), msg)
	}
}

// BenchmarkPipeline_OneStage 单 stage 产 1 个 alert 的开销。
func BenchmarkPipeline_OneStage(b *testing.B) {
	cfg := mocks.NewTestConfig()
	producer := mocks.NewAsyncProducer(b, cfg)
	for i := 0; i < b.N; i++ {
		producer.ExpectInputAndSucceed()
	}
	prod := &AlertProducer{producer: producer, topic: "test", stopCh: make(chan struct{})}
	resolver := mode.NewMemoryResolver(mode.Observe)
	stage := &stubStage{name: "bench", alerts: []Alert{{
		AlertID: "x", RuleID: "R1", Severity: "low",
		Payload: json.RawMessage(`{"k":"v"}`),
	}}}
	p := NewPipeline(prod, resolver, []Stage{stage}, nil)
	h := p.Handler()
	msg := &sarama.ConsumerMessage{
		Topic: "mxcwpp.agent.process",
		Value: []byte(`{"tenant_id":"t1","host_id":"h1","data_type":1000}`),
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h(context.Background(), msg)
	}
}

// BenchmarkPipeline_VaryingStages stage 数从 1 增长到 N, 看 stage 串扩展性。
func BenchmarkPipeline_VaryingStages(b *testing.B) {
	for _, n := range []int{1, 4, 8, 16} {
		b.Run("stages_"+strconv.Itoa(n), func(b *testing.B) {
			stages := make([]Stage, n)
			for i := 0; i < n; i++ {
				stages[i] = &stubStage{name: "s" + strconv.Itoa(i)}
			}
			p := NewPipeline(nil, mode.NewMemoryResolver(mode.Observe), stages, nil)
			h := p.Handler()
			msg := &sarama.ConsumerMessage{
				Topic: "mxcwpp.agent.process",
				Value: []byte(`{"tenant_id":"t1","host_id":"h1","data_type":1000}`),
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = h(context.Background(), msg)
			}
		})
	}
}
