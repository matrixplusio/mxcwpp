package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// 定义在别的包里的指标必须能从 consumer 的 /metrics 抓到。
// consumer 用独立注册表，promauto 只登记到默认注册表——漏了显式登记，指标就只存在于代码里。
func TestRegistryExposesExternalCollectors(t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		got[mf.GetName()] = true
	}
	for _, name := range []string{
		"mxcwpp_precheck_result_stale_total",
		"mxcwpp_kafka_producer_fallback_len",
		// 本包用 promauto 定义、被 critical 告警引用的计数器：曾因漏登记在 /metrics 上缺席。
		// 标签已预置为 0，所以未发生过也会出现在抓取结果里。
		"mxcwpp_consumer_ch_write_errors_total",
		"mxcwpp_consumer_ch_rows_rejected_total",
		// 信号落库的指标定义在 signals 包里，告警规则引用它们。
		"mxcwpp_consumer_signals_messages_total",
		"mxcwpp_consumer_signals_rows_written_total",
		"mxcwpp_consumer_signals_write_failures_total",
		"mxcwpp_consumer_signals_pending_keys",
	} {
		if !got[name] {
			t.Errorf("consumer 注册表里没有 %s", name)
		}
	}
}

// 本包用 promauto 定义的指标会落到默认注册表，必须再显式登记到 consumer 的注册表，
// 否则只存在于代码里。标签值随事件出现的计数器（DLQ、未知类型）抓不到空序列，
// 这里改用重复登记来判断：已登记的会返回 AlreadyRegisteredError。
func TestPromautoCountersRegistered(t *testing.T) {
	for name, c := range map[string]prometheus.Collector{
		"CHWriteErrorsTotal":    CHWriteErrorsTotal,
		"CHRowsRejectedTotal":   CHRowsRejectedTotal,
		"UnknownDataTypeTotal":  UnknownDataTypeTotal,
		"DLQWriteFailuresTotal": DLQWriteFailuresTotal,
	} {
		err := registry.Register(c)
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			if err == nil {
				registry.Unregister(c)
			}
			t.Errorf("%s 没有登记到 consumer 的 /metrics 注册表", name)
		}
	}
}
