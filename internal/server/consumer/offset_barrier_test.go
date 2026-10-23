package consumer

import (
	"testing"

	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus/testutil"

	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
)

// TestRecordProcessedTracksMaxOffset 校验 E：recordProcessed 按 (topic,partition) 记最高 offset
// （乱序/重复到达取最大），snapshotProcessed 返回独立副本。这是手动提交屏障的正确性基础：
// 提交的位点必须是"已处理的最高 offset"，且快照后继续处理不污染本轮提交集。
func TestRecordProcessedTracksMaxOffset(t *testing.T) {
	r := &Router{processed: make(map[topicPartition]int64)}

	msgs := []*sarama.ConsumerMessage{
		{Topic: "ebpf", Partition: 0, Offset: 5},
		{Topic: "ebpf", Partition: 0, Offset: 3}, // 低于已记录 → 忽略
		{Topic: "ebpf", Partition: 0, Offset: 8}, // 更高 → 取代
		{Topic: "ebpf", Partition: 1, Offset: 2},
		{Topic: "fim", Partition: 0, Offset: 100},
	}
	for _, m := range msgs {
		r.recordProcessed(m)
	}

	snap := r.snapshotProcessed()
	want := map[topicPartition]int64{
		{"ebpf", 0}: 8,
		{"ebpf", 1}: 2,
		{"fim", 0}:  100,
	}
	if len(snap) != len(want) {
		t.Fatalf("snapshot 大小=%d, 期望 %d", len(snap), len(want))
	}
	for tp, off := range want {
		if snap[tp] != off {
			t.Errorf("%v offset=%d, 期望 %d", tp, snap[tp], off)
		}
	}

	// 快照独立：快照后继续处理不改变已取快照。
	r.recordProcessed(&sarama.ConsumerMessage{Topic: "ebpf", Partition: 0, Offset: 20})
	if snap[topicPartition{"ebpf", 0}] != 8 {
		t.Errorf("快照被后续处理污染: %d", snap[topicPartition{"ebpf", 0}])
	}
	if r.snapshotProcessed()[topicPartition{"ebpf", 0}] != 20 {
		t.Error("后续处理未更新到最新")
	}
}

// 积压按"最新位置 − 已提交位置"算：ClickHouse 写不进去、offset 停住时积压要跟着涨，
// 而不是按拉取位置算出接近 0。
func TestPublishLagUsesCommittedPosition(t *testing.T) {
	tp := topicPartition{topic: "t-lag", partition: 3}
	r := &Router{
		processed:    make(map[topicPartition]int64),
		hwm:          map[topicPartition]int64{tp: 100},
		committedPos: map[topicPartition]int64{tp: 40},
	}
	r.publishLag()
	if got := testutil.ToFloat64(consumermetrics.ConsumerLag.WithLabelValues("t-lag", "3")); got != 60 {
		t.Errorf("积压应为 60，实际 %v", got)
	}
}
