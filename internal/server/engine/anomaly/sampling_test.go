package anomaly

import "testing"

// 单台高频主机不能主导训练集。
//
// 原实现是一条全局 FIFO：谁上报得快谁就占得多。一台高频主机足以让"什么算正常"
// 变成"那台机器的正常"，其余主机的日常行为在模型眼里全成了异常——
// 表现出来是某几台机器一直报异常，看着像检测在工作，实际是训练集被带偏了。
func TestNoisyHostCannotDominateTrainingSet(t *testing.T) {
	b := newHostSampleBuffer()
	// 一台主机狂发 10000 条。
	for i := range 10000 {
		b.add("noisy", []float64{float64(i)})
	}
	// 另外 9 台各发 32 条。
	for h := range 9 {
		for range perHostSampleCap {
			b.add(string(rune('a'+h)), []float64{1})
		}
	}

	if got := len(b.samples["noisy"]); got != perHostSampleCap {
		t.Fatalf("单机样本应受配额限制为 %d，实际 %d", perHostSampleCap, got)
	}
	total := b.count()
	share := float64(perHostSampleCap) / float64(total)
	if share > 0.15 {
		t.Fatalf("单机在训练集中占比 %.1f%%，过高", share*100)
	}
}

// 保留的是最近的样本，不是最早的。
func TestBufferKeepsRecentSamples(t *testing.T) {
	b := newHostSampleBuffer()
	for i := range perHostSampleCap + 10 {
		b.add("h1", []float64{float64(i)})
	}
	rows := b.samples["h1"]
	if len(rows) != perHostSampleCap {
		t.Fatalf("应保留 %d 条，实际 %d", perHostSampleCap, len(rows))
	}
	// 最后一条必须是最新写入的。
	if rows[len(rows)-1][0] != float64(perHostSampleCap+9) {
		t.Fatalf("应保留最近样本，末条为 %v", rows[len(rows)-1][0])
	}
}

// 必须复制入参：调用方的切片可能被复用，存引用会让缓冲里的历史样本
// 随后续写入一起变化，训练集因而不再是它看起来的样子。
func TestBufferCopiesInput(t *testing.T) {
	b := newHostSampleBuffer()
	shared := []float64{1, 2, 3}
	b.add("h1", shared)
	shared[0] = 999

	if got := b.samples["h1"][0][0]; got != 1 {
		t.Fatalf("缓冲不该随调用方切片变化，实际 %v", got)
	}
}

// 主机数超上限后不再接纳新主机，且不驱逐已有主机。
//
// 驱逐会让训练集随主机上下线反复抖动，模型每轮学到的东西都不一样。
func TestHostLimitDoesNotEvict(t *testing.T) {
	b := newHostSampleBuffer()
	for i := range maxTrackedHosts {
		b.add(string(rune(i%128))+string(rune(i/128))+"x", []float64{1})
	}
	before := b.hosts()
	b.add("brand-new-host", []float64{1})
	if b.hosts() > maxTrackedHosts {
		t.Fatalf("主机数应受上限约束，实际 %d", b.hosts())
	}
	if b.hosts() < before {
		t.Fatal("超限时不该驱逐已有主机")
	}
}

// 空主机 ID 不入缓冲：它会把所有无法归属的样本堆成一个假主机。
func TestEmptyHostIDIgnored(t *testing.T) {
	b := newHostSampleBuffer()
	b.add("", []float64{1})
	if b.count() != 0 {
		t.Fatal("空主机 ID 不该进入训练集")
	}
}
