package baseline

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 反馈闭环参数。
const (
	// minTuningSamples 某指标近窗内 (ignored+resolved) 样本不足此数则不调阈值（统计不稳）。
	minTuningSamples = 50
	// tuningRaiseRate ignored 率 ≥ 此值 → analyst 持续标误报，抬高该指标阈值抑制。
	tuningRaiseRate = 0.8
	// tuningLowerRate ignored 率 ≤ 此值 → 误报少，缓降阈值恢复灵敏。
	tuningLowerRate = 0.3
	// maxTuningMult 动态倍率上限，防止把真异常也抬没。
	maxTuningMult = 4.0
	// tuningWindow 统计 ignored 率的回看窗。
	tuningWindow = 14 * 24 * time.Hour
	// tuningReloadInterval 反馈重算周期。
	tuningReloadInterval = 1 * time.Hour
)

// nextTuningMult 由历史 ignored 率计算某指标的下一个动态阈值倍率。
//   - 样本不足：保持不变（统计不稳，不冒进）。
//   - ignored 率高：×1.5 抬高（上限 maxTuningMult），抑制持续误报。
//   - ignored 率低：×0.8 缓降（下限 1.0），恢复灵敏。
//   - 中间：保持。
//
// 敏感指标(file_sensitive_hits)由调用方跳过，恒 1.0。
func nextTuningMult(current, ignoredRate float64, samples int) float64 {
	if samples < minTuningSamples {
		return current
	}
	switch {
	case ignoredRate >= tuningRaiseRate:
		n := current * 1.5
		if n > maxTuningMult {
			n = maxTuningMult
		}
		return n
	case ignoredRate <= tuningLowerRate:
		n := current * 0.8
		if n < 1.0 {
			n = 1.0
		}
		return n
	default:
		return current
	}
}

// metricIndexByName 指标名 → 维度下标（-1 表示未知）。
func metricIndexByName(name string) int {
	for i, n := range MetricNames {
		if n == name {
			return i
		}
	}
	return -1
}

// tuningExemptMetric 敏感指标不参与自动抬阈值（保持灵敏）。
func tuningExemptMetric(i int) bool {
	return i == MetricFileSensitiveHits
}

// StartTuningReload 启动反馈闭环：立即重算一次并每 tuningReloadInterval 周期重算。db=nil 时空转。
func (e *Engine) StartTuningReload(ctx context.Context) {
	if e.db == nil {
		return
	}
	e.reloadTuning()
	go func() {
		t := time.NewTicker(tuningReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.reloadTuning()
			}
		}
	}()
}

// reloadTuning 统计各指标近窗 ignored 率，算动态倍率，upsert bde_metric_tunings 并刷新内存快照。
func (e *Engine) reloadTuning() {
	if e.db == nil {
		return
	}
	// 各指标近窗 ignored / resolved 计数（open 的还没处置，不计入率）。
	type row struct {
		Metric   string
		Ignored  int
		Resolved int
	}
	var rows []row
	since := time.Now().Add(-tuningWindow)
	if err := e.db.Model(&model.BehaviorAlert{}).
		Select("metric, "+
			"SUM(CASE WHEN status = 'ignored' THEN 1 ELSE 0 END) AS ignored, "+
			"SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved").
		Where("updated_at >= ?", since).
		Group("metric").
		Scan(&rows).Error; err != nil {
		e.logger.Warn("BDE 反馈：统计 ignored 率失败", zap.Error(err))
		return
	}

	// 现有倍率。
	var existing []model.BDEMetricTuning
	e.db.Find(&existing)
	curByMetric := make(map[string]float64, len(existing))
	for _, t := range existing {
		curByMetric[t.Metric] = t.ThresholdMult
	}

	var mult [MetricCount]float64
	for i := range mult {
		mult[i] = 1.0
	}
	now := model.ToLocalTime(time.Now())
	for _, r := range rows {
		idx := metricIndexByName(r.Metric)
		if idx < 0 || tuningExemptMetric(idx) {
			continue
		}
		samples := r.Ignored + r.Resolved
		rate := 0.0
		if samples > 0 {
			rate = float64(r.Ignored) / float64(samples)
		}
		cur := curByMetric[r.Metric]
		if cur < 1.0 {
			cur = 1.0
		}
		next := nextTuningMult(cur, rate, samples)
		mult[idx] = next
		// 仅在样本足(真正参与计算)时落库，避免样本不足的噪声写表。
		if samples >= minTuningSamples {
			_ = e.db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "metric"}},
				DoUpdates: clause.AssignmentColumns([]string{"threshold_mult", "ignored_rate", "samples", "updated_at"}),
			}).Create(&model.BDEMetricTuning{
				Metric: r.Metric, ThresholdMult: next, IgnoredRate: rate, Samples: samples, UpdatedAt: now,
			}).Error
		}
	}

	e.tuning.Store(&mult)
}
