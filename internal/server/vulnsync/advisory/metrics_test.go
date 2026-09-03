package advisory

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRecordSyncFailure_DoesNotRefreshTimestamp 失败不得更新新鲜度时间戳。
//
// 这是整个指标的关键：若失败也刷新"上次成功"，漏洞库停更时告警永远不会触发——
// 界面上漏洞列表照常显示，只是内容停在最后一次真正成功的时刻，运维看不出区别。
func TestRecordSyncFailure_DoesNotRefreshTimestamp(t *testing.T) {
	const src = "test-source-failure"

	RecordSyncSuccess(src, 10)
	first := testutil.ToFloat64(lastSuccessTimestamp.WithLabelValues(src))
	if first <= 0 {
		t.Fatal("成功后应记录时间戳")
	}

	time.Sleep(1100 * time.Millisecond)
	RecordSyncFailure(src)
	after := testutil.ToFloat64(lastSuccessTimestamp.WithLabelValues(src))
	if after != first {
		t.Errorf("失败不得更新新鲜度时间戳: %v → %v", first, after)
	}
}

// TestRecordSyncSuccess_TracksFetchCount 拉到 0 条也算成功，但不增加计数。
//
// "成功但没数据"同样是停更，只是更隐蔽——靠 advisories_fetched 长期不增长暴露。
func TestRecordSyncSuccess_TracksFetchCount(t *testing.T) {
	const src = "test-source-count"

	RecordSyncSuccess(src, 0)
	if got := testutil.ToFloat64(advisoriesFetched.WithLabelValues(src)); got != 0 {
		t.Errorf("拉到 0 条不应增加计数，实际 %v", got)
	}
	RecordSyncSuccess(src, 5)
	if got := testutil.ToFloat64(advisoriesFetched.WithLabelValues(src)); got != 5 {
		t.Errorf("计数 = %v, want 5", got)
	}
}

// TestSyncOutcome_SeparatesSuccessFromFailure 成败必须分开计量，
// 否则"一直在跑"与"一直在成功"看起来一样。
func TestSyncOutcome_SeparatesSuccessFromFailure(t *testing.T) {
	const src = "test-source-outcome"

	RecordSyncSuccess(src, 1)
	RecordSyncFailure(src)
	RecordSyncFailure(src)

	if got := testutil.ToFloat64(syncOutcome.WithLabelValues(src, "success")); got != 1 {
		t.Errorf("success = %v, want 1", got)
	}
	if got := testutil.ToFloat64(syncOutcome.WithLabelValues(src, "failure")); got != 2 {
		t.Errorf("failure = %v, want 2", got)
	}
}
