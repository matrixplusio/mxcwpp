package anomaly

import (
	"math"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

// 模型漂移与训练投毒。
//
// IForest 每 30 分钟用最近的滑动窗口重训一次，"什么算正常"由最近看到的数据决定。
// 这带来两个此前无人观测的问题：
//
//  1. 环境漂移：业务变更后基线整体偏移，模型要么开始刷屏，要么把新常态学进去
//     从此对该维度失明——两种都没有任何东西会提示。
//  2. 训练投毒：攻击者只要把动作放慢到跨越多个训练窗口，每次都只比上一窗口高一点，
//     每一窗都算"正常"，最后攻击行为成为基线。这不是理论问题，是滑窗重训的固有性质。
//
// 应对不是让模型更聪明，而是留一份不随滑窗移动的长期参照，并在偏离过大时
// **拒绝用这批数据重训**——宁可用旧模型，也不要学一个被污染的新模型。

var (
	// driftScore 当前训练窗口相对长期基线的偏移程度。
	anomalyDriftScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_feature_drift",
		Help: "Per-feature drift of the current training window versus the long-term reference",
	}, []string{"feature"})

	// retrainRejected 因漂移过大被拒绝的重训次数。
	//
	// 用 Counter：这类事件必须留下历史痕迹。只看当前状态会漏掉
	// "半夜拒了 20 次、早上恢复正常"这种最需要复盘的情况。
	anomalyRetrainRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_anomaly_retrain_rejected_total",
		Help: "Retrains rejected because the training window drifted too far from the reference baseline",
	}, []string{"reason"})

	// modelAgeSeconds 当前模型自上次成功训练以来的时长。
	//
	// 拒绝重训会让模型变旧。旧模型仍然工作，但"上次学习是什么时候"必须可见，
	// 否则连续拒绝会表现为"一切正常"。
	anomalyModelAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_anomaly_model_age_seconds",
		Help: "Seconds since the anomaly model was last successfully trained",
	})
)

// featureName 返回维度名，越界时给出可辨认的占位而不是 panic。
//
// 漂移日志是出问题时才会被读的东西，不该因为一个下标越界把检测器打挂。
func featureName(i int) string {
	if i < 0 || i >= len(MetricNames) {
		return "unknown"
	}
	return MetricNames[i]
}

// driftThreshold 单维度允许的最大偏移（以长期基线的标准差为单位）。
//
// 3 个标准差：正常业务波动很难持续越过这条线，而缓慢投毒要想有效，
// 累计偏移必然远超它。取值偏松是有意的——这道闸的作用是拦住离谱的情况，
// 不是替代检测本身。误拒一次重训的代价只是模型晚半小时更新。
const driftThreshold = 3.0

// minReferenceSamples 建立长期基线所需的最少样本数。
const minReferenceSamples = 256

// referenceBaseline 是不随滑动窗口移动的长期参照。
//
// 关键在于它**不跟着每次重训更新**。一旦它也跟着滑动，就和被它监督的对象
// 一起漂走了，等于没有参照。
type referenceBaseline struct {
	mean  []float64
	stdev []float64
	// samples 建立该基线时使用的样本数，用于判断参照本身是否足够可信。
	samples int
}

// newReferenceBaseline 从一批样本建立长期参照。
func newReferenceBaseline(data [][]float64) *referenceBaseline {
	if len(data) < minReferenceSamples {
		return nil
	}
	dims := len(data[0])
	b := &referenceBaseline{
		mean:    make([]float64, dims),
		stdev:   make([]float64, dims),
		samples: len(data),
	}
	for _, row := range data {
		for i := range row {
			if i < dims {
				b.mean[i] += row[i]
			}
		}
	}
	for i := range b.mean {
		b.mean[i] /= float64(len(data))
	}
	for _, row := range data {
		for i := range row {
			if i < dims {
				d := row[i] - b.mean[i]
				b.stdev[i] += d * d
			}
		}
	}
	for i := range b.stdev {
		b.stdev[i] = math.Sqrt(b.stdev[i] / float64(len(data)))
	}
	return b
}

// driftReport 描述一次漂移评估的结果。
type driftReport struct {
	// MaxDrift 所有维度中最大的偏移量（以基线标准差为单位）。
	MaxDrift float64
	// WorstFeature 偏移最大的维度下标。
	WorstFeature int
	// PerFeature 每个维度的偏移量。
	PerFeature []float64
	// Poisoned 是否判定为不可用于训练。
	Poisoned bool
}

// evaluateDrift 比较训练窗口与长期参照。
//
// 只比较均值偏移，不比较分布形状：形状变化需要更多样本才能可靠判断，
// 而在样本不足时给出一个看似精确的判断，比不判断更危险。
func (b *referenceBaseline) evaluateDrift(window [][]float64) driftReport {
	rep := driftReport{WorstFeature: -1}
	if b == nil || len(window) == 0 {
		return rep
	}
	dims := len(b.mean)
	rep.PerFeature = make([]float64, dims)

	mean := make([]float64, dims)
	for _, row := range window {
		for i := range row {
			if i < dims {
				mean[i] += row[i]
			}
		}
	}
	for i := range mean {
		mean[i] /= float64(len(window))
	}

	for i := range mean {
		sd := b.stdev[i]
		if sd <= 0 {
			// 该维度在基线期内是常量。此时任何变化都无法用标准差衡量，
			// 跳过而不是当成无穷大偏移——常量维度往往是采集缺失，
			// 把它判成投毒会让整个闸门被一个空字段卡死。
			continue
		}
		d := math.Abs(mean[i]-b.mean[i]) / sd
		rep.PerFeature[i] = d
		if d > rep.MaxDrift {
			rep.MaxDrift = d
			rep.WorstFeature = i
		}
	}
	rep.Poisoned = rep.MaxDrift > driftThreshold
	return rep
}

// trimOutliers 去掉每个维度上最极端的样本后再建参照。
//
// 建立长期参照的那一刻如果环境里已经有攻击，参照本身就是脏的。
// 去掉两端各 5% 不能解决"从一开始就被入侵"，但能挡住少数极端点把参照拉偏——
// 这是能力边界，写在这里以免后来的人以为参照是可信的。
func trimOutliers(data [][]float64) [][]float64 {
	if len(data) < minReferenceSamples {
		return data
	}
	dims := len(data[0])

	// 先按整行的偏离程度排序，再整体去掉最极端的 5%。
	//
	// 不逐维度各剔 5%：13 个维度各自标记的行往往不同，叠加后能剔掉大半样本，
	// 反而剩不下足够的数据建参照——那样得到的是"没有参照"，也就是没有任何投毒防护。
	mean := make([]float64, dims)
	for _, row := range data {
		for i := range row {
			if i < dims {
				mean[i] += row[i]
			}
		}
	}
	for i := range mean {
		mean[i] /= float64(len(data))
	}
	sd := make([]float64, dims)
	for _, row := range data {
		for i := range row {
			if i < dims {
				d := row[i] - mean[i]
				sd[i] += d * d
			}
		}
	}
	for i := range sd {
		sd[i] = math.Sqrt(sd[i] / float64(len(data)))
	}

	// 每行取各维度中最大的标准化偏离作为该行的极端程度。
	type scored struct {
		idx  int
		dist float64
	}
	rows := make([]scored, len(data))
	for i, row := range data {
		worst := 0.0
		for j := range row {
			if j >= dims || sd[j] <= 0 {
				continue
			}
			if d := math.Abs(row[j]-mean[j]) / sd[j]; d > worst {
				worst = d
			}
		}
		rows[i] = scored{idx: i, dist: worst}
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].dist < rows[b].dist })

	keep := len(rows) - len(rows)/20 // 去掉最极端的 5%
	// 参照建不起来就等于没有投毒防护，且不会有人发现。
	// 剩余样本不足以建参照时，宁可用带噪声的全量数据。
	if keep < minReferenceSamples {
		return data
	}
	out := make([][]float64, 0, keep)
	for _, r := range rows[:keep] {
		out = append(out, data[r.idx])
	}
	return out
}
