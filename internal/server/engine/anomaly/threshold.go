package anomaly

import (
	"strconv"
	"sync/atomic"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 异常分阈值可配。
//
// 原实现把 0.65 写死在常量里。不同环境的"正常"离散程度差别很大——
// 一个负载平稳的数据库集群和一个每天扩缩容的 K8s 节点池，同一个阈值不可能都合适。
// 写死一个数意味着某些环境必然长期误报，另一些必然长期漏报，而运维除了改代码没有别的办法。

// FlagAnomalyScoreThreshold 是阈值开关的 flag_key。
const FlagAnomalyScoreThreshold = "anomaly.score_threshold"

const (
	// minAnomalyThreshold 允许配置的下限。
	//
	// 低于 0.5 等于把大半样本判成异常：IForest 的分数天然在 0.5 附近，
	// 阈值压到那里会让告警量爆炸，而看起来像是"检测变敏感了"。
	minAnomalyThreshold = 0.5
	// maxAnomalyThreshold 允许配置的上限。
	//
	// 高于 0.95 实际等同于关闭检测，但外表仍是"已启用"。
	// 要关就用 mode=off，别用一个高得永远触发不了的阈值假装在跑。
	maxAnomalyThreshold = 0.95
)

// scoreThreshold 返回当前生效阈值。
func (d *Detector) scoreThreshold() float64 {
	if v := d.threshold.Load(); v != nil {
		return *v
	}
	return defaultAnomalyThreshold
}

// LoadScoreThreshold 从 feature_flags 读取阈值。
//
// 缺配置 / 非法值 / 越界一律回落默认值并留日志——绝不因为一个写错的配置
// 把检测调成永远不响或永远刷屏。
func (d *Detector) LoadScoreThreshold(db *gorm.DB) {
	if db == nil {
		return
	}
	var f model.FeatureFlag
	if err := db.Where("flag_key = ?", FlagAnomalyScoreThreshold).First(&f).Error; err != nil {
		return // 未配置：用默认值，不算异常
	}
	v, err := strconv.ParseFloat(f.Value, 64)
	if err != nil {
		d.logger.Warn("异常分阈值配置非法，回落默认值",
			zap.String("raw", f.Value), zap.Float64("default", defaultAnomalyThreshold))
		return
	}
	if v < minAnomalyThreshold || v > maxAnomalyThreshold {
		d.logger.Warn("异常分阈值超出允许区间，回落默认值",
			zap.Float64("configured", v),
			zap.Float64("min", minAnomalyThreshold),
			zap.Float64("max", maxAnomalyThreshold),
			zap.Float64("default", defaultAnomalyThreshold))
		return
	}
	d.threshold.Store(&v)
	d.logger.Info("异常分阈值已生效", zap.Float64("threshold", v))
}

// thresholdHolder 让阈值可在运行期原子替换（热路径每事件读一次）。
type thresholdHolder = atomic.Pointer[float64]
