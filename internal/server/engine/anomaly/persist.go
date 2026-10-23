package anomaly

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// modelStateName 当前唯一的模型标识。
const modelStateName = "iforest_host_metrics"

// referenceLoaded 参照基线是否已就绪（1/0）。
//
// 没有参照就没有投毒防护。这件事必须能在监控上直接看到，
// 否则"防护未生效"和"防护生效且一切正常"在外部表现完全一样。
var anomalyReferenceLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "mxcwpp_anomaly_reference_baseline_ready",
	Help: "Whether the long-term reference baseline used for drift and poisoning detection is loaded",
})

// LoadState 从库中恢复模型状态。
//
// 恢复失败不阻断启动：异常检测不该因为读不到一行状态就让整个 engine 起不来。
// 但必须留下明确日志与指标——静默地以"无参照"启动，等于悄悄关掉投毒防护。
func (d *Detector) LoadState() {
	if d.db == nil {
		return
	}
	var st model.AnomalyModelState
	err := d.db.Where("model_name = ?", modelStateName).First(&st).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		d.logger.Info("未找到异常检测模型状态，将在样本积累后新建参照基线")
		anomalyReferenceLoaded.Set(0)
		return
	}
	if err != nil {
		d.logger.Warn("读取异常检测模型状态失败，本次以无参照启动（投毒防护未生效）",
			zap.Error(err))
		anomalyReferenceLoaded.Set(0)
		return
	}

	// 长度不符说明特征维度变过。此时旧参照已无意义，宁可重建也不能错位比较——
	// 用错位的参照做漂移判断，得到的结论比没有结论更糟。
	if len(st.ReferenceMean) != featureCount || len(st.ReferenceStdev) != featureCount {
		d.logger.Warn("已存参照基线维度与当前特征不符，将重建",
			zap.Int("stored_dims", len(st.ReferenceMean)),
			zap.Int("expected_dims", featureCount))
		anomalyReferenceLoaded.Set(0)
		return
	}

	d.mu.Lock()
	d.reference = &referenceBaseline{
		mean:    append([]float64(nil), st.ReferenceMean...),
		stdev:   append([]float64(nil), st.ReferenceStdev...),
		samples: st.ReferenceSamples,
	}
	if st.LastTrainedAt != nil {
		d.lastTrainedAt = st.LastTrainedAt.Time()
	}
	d.mu.Unlock()

	anomalyReferenceLoaded.Set(1)
	d.logger.Info("已恢复异常检测参照基线",
		zap.Int("reference_samples", st.ReferenceSamples),
		zap.Int("rejected_retrains", st.RejectedRetrains))
}

// SaveState 落库当前模型状态。
//
// 只在参照基线建立或训练成功时调用，不做周期性全量写：这张表一行一模型，
// 高频写入没有收益，反而会把一次数据库抖动放大成检测链路的问题。
func (d *Detector) SaveState() {
	if d.db == nil {
		return
	}
	d.mu.Lock()
	ref := d.reference
	last := d.lastTrainedAt
	d.mu.Unlock()

	if ref == nil {
		return
	}
	now := model.Now()
	st := model.AnomalyModelState{
		ModelName:        modelStateName,
		ReferenceMean:    append(model.FloatArray(nil), ref.mean...),
		ReferenceStdev:   append(model.FloatArray(nil), ref.stdev...),
		ReferenceSamples: ref.samples,
		ReferenceBuiltAt: &now,
	}
	if !last.IsZero() {
		lt := model.ToLocalTime(last)
		st.LastTrainedAt = &lt
	}

	// 按 model_name upsert：参照基线一旦建立就不再变，重复写入是幂等的。
	err := d.db.Where("model_name = ?", modelStateName).
		Assign(map[string]any{
			"reference_mean":     st.ReferenceMean,
			"reference_stdev":    st.ReferenceStdev,
			"reference_samples":  st.ReferenceSamples,
			"reference_built_at": st.ReferenceBuiltAt,
			"last_trained_at":    st.LastTrainedAt,
		}).
		FirstOrCreate(&st).Error
	if err != nil {
		// 落库失败只影响下次重启的恢复速度，不影响当前检测，
		// 因此告警而不中断。
		d.logger.Warn("保存异常检测模型状态失败（重启后参照基线需重建）", zap.Error(err))
		return
	}
	anomalyReferenceLoaded.Set(1)
}

// recordRejectedRetrain 累加被拒绝的重训次数。
//
// 单独一条 UPDATE 而不是走 SaveState：拒绝重训时参照没有变化，
// 没必要把整行重写一遍。
func (d *Detector) recordRejectedRetrain() {
	if d.db == nil {
		return
	}
	err := d.db.Model(&model.AnomalyModelState{}).
		Where("model_name = ?", modelStateName).
		UpdateColumn("rejected_retrains", gorm.Expr("rejected_retrains + 1")).Error
	if err != nil {
		d.logger.Warn("累加拒绝重训计数失败", zap.Error(err))
	}
}

// StaleModelAge 超过该时长未成功训练即视为模型陈旧。
//
// 重训周期是 30 分钟，连续 8 次都没训成才到这个时长——那已经不是偶发，
// 而是环境持续偏离参照，需要人来判断是业务变了还是真出了事。
const StaleModelAge = 4 * time.Hour

// ModelStale 报告模型是否已陈旧。
func (d *Detector) ModelStale() bool {
	d.mu.Lock()
	last := d.lastTrainedAt
	d.mu.Unlock()
	if last.IsZero() {
		// 从未训练过不算"陈旧"——那是冷启动，由 Trained() 表达。
		// 两者混为一谈会让刚启动的实例一直报陈旧告警，最后没人再看它。
		return false
	}
	return time.Since(last) > StaleModelAge
}

// HasReference 报告参照基线是否已就绪。
//
// 没有参照时检测器照常工作，只是漂移与投毒防护不生效——这个区别
// 必须能从外部看出来，否则"防护没生效"和"防护生效且一切正常"表现一样。
func (d *Detector) HasReference() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reference != nil
}
