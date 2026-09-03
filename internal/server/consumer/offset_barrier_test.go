package consumer

import (
	"testing"

	"github.com/IBM/sarama"
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
