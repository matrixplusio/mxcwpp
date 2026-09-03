package baseline

import (
	"math"
	"testing"
)

// TestEWMA_ConvergesOnSustainedShift 校验 1e 的核心目标：均值/方差改指数加权后，
// 基线跟随业务常态漂移——持续的稳态偏移在若干样本后被吸收，偏离回落到阈值内（收敛）。
//
// 对照旧 Welford：mean += delta/n，n 增大后 delta/n→0，均值冻结在学习期水位，
// 稳态偏移永远落在 Nσ 外 → 每窗口无限复发告警（本会话实测 67 万/周不收敛的病根）。
func TestEWMA_ConvergesOnSustainedShift(t *testing.T) {
	old := ewmaAlpha
	ewmaAlpha = 0.02 // 测试用快半衰期(~34 样本)，避免喂 2880 个；仍够小使单样本不吞尖峰
	defer func() { ewmaAlpha = old }()

	bl := &HostBaseline{phase: PhaseActive}

	// 阶段1：稳态在 10 附近（带小噪声），建立基线。
	for i := range 500 {
		var m [MetricCount]float64
		m[0] = 10 + float64(i%3) // 10/11/12
		bl.Update(m)
	}

	// 偏移刚发生：值跳到 100，应是显著偏离（证明检测仍有效，不是被一味压平）。
	var shifted [MetricCount]float64
	shifted[0] = 100
	bl.Update(shifted)
	mean0, sd0 := bl.statFor(-1, 0) // bucket=-1 强制走扁平基线
	if sd0 < 0.001 {
		t.Fatal("阶段1 后 stddev 不应为 0")
	}
	if z0 := math.Abs((100 - mean0) / sd0); z0 < deviationThreshold {
		t.Errorf("偏移刚发生应触发偏离：z=%.2f < 阈值 %.1f", z0, deviationThreshold)
	}

	// 阶段2：偏移持续（100 附近带小噪声），基线应逐步吸收到新常态。
	for i := range 800 {
		var m [MetricCount]float64
		m[0] = 100 + float64(i%3)
		bl.Update(m)
	}

	meanN, sdN := bl.statFor(-1, 0)
	// 均值应跟随到新常态 ~100（旧 Welford 会仍冻结在 ~11）。
	if meanN < 90 {
		t.Errorf("EWMA 均值未跟随新常态：%.2f，期望 ≈100", meanN)
	}
	// 处于新常态的值不再越阈值（收敛）。
	if sdN > 0.001 {
		if zN := math.Abs((101 - meanN) / sdN); zN >= deviationThreshold {
			t.Errorf("EWMA 未收敛：新常态值 z=%.2f 仍 >= 阈值 %.1f (mean=%.2f sd=%.2f)", zN, deviationThreshold, meanN, sdN)
		}
	}
}

// TestEWMA_StillDetectsTransientSpike 校验自适应不至于压平瞬时尖峰：
// 稳态基线上单个远离值仍触发偏离。
func TestEWMA_StillDetectsTransientSpike(t *testing.T) {
	old := ewmaAlpha
	ewmaAlpha = 0.05
	defer func() { ewmaAlpha = old }()

	bl := &HostBaseline{phase: PhaseActive}
	for i := range 500 {
		var m [MetricCount]float64
		m[0] = 20 + float64(i%5) // 20..24
		bl.Update(m)
	}
	mean, sd := bl.statFor(-1, 0)
	if sd < 0.001 {
		t.Fatal("stddev 不应为 0")
	}
	// 单个尖峰 500 远离常态 ~22，应为强偏离。
	if z := math.Abs((500 - mean) / sd); z < deviationThreshold {
		t.Errorf("瞬时尖峰应触发偏离：z=%.2f < %.1f", z, deviationThreshold)
	}
}
