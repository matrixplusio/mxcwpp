package consumer

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"

	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestChWriteCountsErrors 校验 2c：ClickHouse 写失败不再被 `_=` 静默吞掉，
// 而是计数到 ch_write_errors 指标（nil err 不计）。
func TestChWriteCountsErrors(t *testing.T) {
	r := &Router{logger: zap.NewNop()}
	m := consumermetrics.CHWriteErrorsTotal.WithLabelValues("test_op")

	before := counterValue(t, m)
	r.chWrite("test_op", nil)
	if got := counterValue(t, m); got != before {
		t.Errorf("nil err 不应计数：before=%v got=%v", before, got)
	}
	r.chWrite("test_op", errors.New("boom"))
	if got := counterValue(t, m); got != before+1 {
		t.Errorf("写失败应计数 +1：before=%v got=%v", before, got)
	}
}

// TestRecordUnknownDataType 校验未知 DataType 计数器可用（default 路由转 DLQ 时调用）。
func TestRecordUnknownDataType(t *testing.T) {
	m := consumermetrics.UnknownDataTypeTotal.WithLabelValues("4242")
	before := counterValue(t, m)
	consumermetrics.RecordUnknownDataType("4242")
	if got := counterValue(t, m); got != before+1 {
		t.Errorf("未知 DataType 应计数 +1：before=%v got=%v", before, got)
	}
}
