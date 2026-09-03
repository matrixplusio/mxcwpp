package anomaly

import (
	"math"
	"testing"
)

// makeWindow 生成一批围绕给定中心、带固定抖动的样本。
//
// 不用随机数：随机会让失败无法复现，而这里要断言的是阈值行为，
// 每次跑出不同结果的测试挡不住回归。
func makeWindow(n int, center float64, spread float64) [][]float64 {
	out := make([][]float64, n)
	for i := range out {
		row := make([]float64, featureCount)
		for j := range row {
			// 用下标产生确定性抖动，覆盖 [center-spread, center+spread]。
			row[j] = center + spread*math.Sin(float64(i*7+j))
		}
		out[i] = row
	}
	return out
}

// 参照基线样本不足时不建立。
//
// 用几十个样本算出来的均值和标准差不足以当作"长期正常"，
// 拿它去卡重训只会把正常波动判成投毒。
func TestReferenceNeedsEnoughSamples(t *testing.T) {
	if b := newReferenceBaseline(makeWindow(10, 50, 5)); b != nil {
		t.Fatal("样本不足时不该建立参照基线")
	}
	if b := newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5)); b == nil {
		t.Fatal("样本充足时应建立参照基线")
	}
}

// 正常波动不该被判成投毒——否则模型永远无法更新。
func TestNormalVariationIsNotRejected(t *testing.T) {
	ref := newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5))
	if ref == nil {
		t.Fatal("参照基线未建立")
	}
	rep := ref.evaluateDrift(makeWindow(200, 51, 5))
	if rep.Poisoned {
		t.Fatalf("正常波动被误判为投毒，最大偏移 %.2fσ", rep.MaxDrift)
	}
}

// 缓慢爬坡的训练投毒必须被拦下。
//
// 这是滑窗重训的固有弱点：攻击者把动作放慢到跨越多个训练窗口，每一窗都只比
// 上一窗高一点，逐窗比较永远看不出问题，最后攻击行为成为基线。
// 长期参照的意义就在于它不跟着窗口移动——累计偏移因而无处可藏。
func TestSlowRampPoisoningIsRejected(t *testing.T) {
	ref := newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5))
	if ref == nil {
		t.Fatal("参照基线未建立")
	}

	// 模拟连续 10 个窗口，每窗中心比上一窗抬高 3——单看相邻两窗几乎无差别。
	center := 50.0
	var rejectedAt int
	for round := 1; round <= 10; round++ {
		center += 3
		rep := ref.evaluateDrift(makeWindow(200, center, 5))
		if rep.Poisoned {
			rejectedAt = round
			break
		}
	}
	if rejectedAt == 0 {
		t.Fatal("缓慢爬坡的投毒始终未被拦下：攻击行为最终会成为基线")
	}
	t.Logf("第 %d 轮拦下（累计偏移 %.0f）", rejectedAt, float64(rejectedAt*3))
}

// 逐窗比较为什么不够——记录这个反例，避免以后有人把参照改成"跟上一次训练比"。
//
// 如果参照每轮都跟着更新，那么每一轮的偏移都很小，投毒永远不会触发阈值。
func TestSlidingReferenceWouldMissPoisoning(t *testing.T) {
	center := 50.0
	prev := newReferenceBaseline(makeWindow(minReferenceSamples, center, 5))
	caught := false
	for range 10 {
		center += 3
		window := makeWindow(minReferenceSamples, center, 5)
		if prev.evaluateDrift(window).Poisoned {
			caught = true
			break
		}
		// 参照跟着窗口走——这正是不能这么做的原因。
		prev = newReferenceBaseline(window)
	}
	if caught {
		t.Fatal("前提失效：本用例存在的意义是证明滑动参照抓不到缓慢投毒")
	}
}

// 常量维度不该把闸门卡死。
//
// 采集缺失会让某个维度恒为 0，标准差为 0。若把它当成无穷大偏移，
// 一个空字段就能让所有重训被永久拒绝——模型从此再不更新，而表面上只是"在保护"。
func TestConstantFeatureDoesNotBlockRetrain(t *testing.T) {
	data := makeWindow(minReferenceSamples, 50, 5)
	for i := range data {
		data[i][0] = 0 // 该维度恒为 0，模拟采集缺失
	}
	ref := newReferenceBaseline(data)
	if ref == nil {
		t.Fatal("参照基线未建立")
	}

	window := makeWindow(200, 50, 5)
	for i := range window {
		window[i][0] = 7 // 该维度突然有值了
	}
	if rep := ref.evaluateDrift(window); rep.Poisoned {
		t.Fatalf("常量维度不该导致拒绝重训，最大偏移 %.2fσ", rep.MaxDrift)
	}
}

// 剔除极端值不应把样本剔光。
//
// 参照为空比参照有噪声更糟：没有参照就没有任何投毒防护，而且不会有人发现。
func TestTrimOutliersKeepsEnoughSamples(t *testing.T) {
	data := makeWindow(minReferenceSamples*2, 50, 5)
	trimmed := trimOutliers(data)
	if len(trimmed) < minReferenceSamples/2 {
		t.Fatalf("剔除极端值后样本剩余 %d，过少", len(trimmed))
	}
	if newReferenceBaseline(trimmed) == nil {
		t.Fatal("剔除后应仍能建立参照基线")
	}
}

// 极端离群点不应把参照拉偏。
func TestTrimOutliersRemovesExtremes(t *testing.T) {
	data := makeWindow(minReferenceSamples*2, 50, 2)
	// 掺入少量极端点，模拟建立参照时环境里已有异常行为。
	for i := 0; i < 20; i++ {
		row := make([]float64, featureCount)
		for j := range row {
			row[j] = 10000
		}
		data = append(data, row)
	}
	dirty := newReferenceBaseline(data)
	clean := newReferenceBaseline(trimOutliers(data))
	if dirty == nil || clean == nil {
		t.Fatal("参照基线未建立")
	}
	if clean.mean[0] >= dirty.mean[0] {
		t.Fatalf("剔除极端值后均值应更接近真实中心，clean=%.1f dirty=%.1f",
			clean.mean[0], dirty.mean[0])
	}
}
