package baseline

import (
	"testing"
	"time"
)

func TestTimeBucket(t *testing.T) {
	// NumTimeBuckets=4 → 每 6h 一桶
	cases := map[int]int{0: 0, 5: 0, 6: 1, 11: 1, 12: 2, 17: 2, 18: 3, 23: 3}
	for hour, want := range cases {
		ts := time.Date(2026, 6, 27, hour, 30, 0, 0, time.UTC)
		if got := timeBucket(ts); got != want {
			t.Errorf("timeBucket(hour=%d)=%d want %d", hour, got, want)
		}
	}
}

func TestStatFor_BucketWhenReadyElseFlat(t *testing.T) {
	bl := &HostBaseline{}
	// 扁平基线:mean=10
	bl.samples = 300
	bl.mean[0] = 10
	bl.m2[0] = 300 * 4 // sd≈sqrt(1200/299)
	// 桶1样本足(>=minBucketSamples),mean=50;桶0样本不足
	bl.bSamples[1] = minBucketSamples
	bl.bMean[1][0] = 50
	bl.bM2[1][0] = float64(minBucketSamples) * 9
	bl.bSamples[0] = minBucketSamples - 1
	bl.bMean[0][0] = 999 // 不应被采用(样本不足)

	if m, _ := bl.statFor(1, 0); m != 50 {
		t.Fatalf("bucket1 ready → mean=%v want 50", m)
	}
	if m, _ := bl.statFor(0, 0); m != 10 {
		t.Fatalf("bucket0 不足 → 应回退扁平 mean=%v want 10", m)
	}
	if m, _ := bl.statFor(2, 0); m != 10 {
		t.Fatalf("bucket2 空 → 应回退扁平 mean=%v want 10", m)
	}
}

func TestUpdate_PopulatesCurrentBucket(t *testing.T) {
	bl := &HostBaseline{phase: PhaseLearning}
	for range 10 {
		bl.Update([MetricCount]float64{1, 2, 3})
	}
	// 总样本 = 各桶样本之和;当前时段桶被填充
	sum := 0
	for _, n := range bl.bSamples {
		sum += n
	}
	if sum != bl.samples {
		t.Fatalf("bucket samples 之和=%d != total samples=%d", sum, bl.samples)
	}
	cur := timeBucket(time.Now())
	if bl.bSamples[cur] == 0 {
		t.Fatalf("当前桶 %d 应被填充", cur)
	}
}
