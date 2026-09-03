package anomaly

import (
	"github.com/prometheus/client_golang/prometheus"
)

// 训练样本的按主机配额。
//
// 原实现是一条全局 FIFO（2000 条）：谁上报得快，谁就在训练集里占得多。
// 一台高频主机足以让"什么算正常"变成"那台机器的正常"，其余主机的行为
// 在模型眼里全都成了异常——而这恰恰会表现为"某几台机器一直报异常"，
// 看起来像检测在工作，实际是训练集被一台机器带偏了。
//
// 改为每台主机各自保留最近 N 条，训练时合并。这样一台主机再吵，
// 在训练集里也只占 N 条。

const (
	// perHostSampleCap 单台主机在训练集中的最大样本数。
	//
	// 32 条足以刻画一台主机的常态，又小到让任何单机都无法主导训练集：
	// 100 台主机各 32 条即 3200 条，远超训练所需的下限。
	perHostSampleCap = 32

	// maxTrackedHosts 参与训练的最大主机数，用于给内存兜底。
	//
	// 超出后不再接纳新主机（而不是驱逐旧主机）：驱逐会让训练集随主机上下线
	// 反复抖动，模型每轮学到的东西都不一样。
	maxTrackedHosts = 5000
)

// trainingSampleHosts 当前参与训练的主机数。
//
// 这个数字掉下来意味着训练集变窄了——模型正在向少数主机的行为收敛。
var trainingSampleHosts = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "mxcwpp_anomaly_training_hosts",
	Help: "Number of hosts contributing samples to anomaly model training",
})

// hostSampleBuffer 是按主机分组的训练样本缓冲。
type hostSampleBuffer struct {
	samples map[string][][]float64
}

func newHostSampleBuffer() *hostSampleBuffer {
	return &hostSampleBuffer{samples: make(map[string][][]float64)}
}

// add 记录一台主机的样本，超出配额时丢弃最旧的一条。
func (b *hostSampleBuffer) add(hostID string, metrics []float64) {
	if hostID == "" {
		return
	}
	cur, known := b.samples[hostID]
	if !known && len(b.samples) >= maxTrackedHosts {
		return
	}
	// 复制一份：调用方的切片可能被复用，直接存引用会让缓冲里的历史样本
	// 随后续写入一起变化，训练集因而不再是它看起来的样子。
	cp := make([]float64, len(metrics))
	copy(cp, metrics)

	cur = append(cur, cp)
	if len(cur) > perHostSampleCap {
		cur = cur[len(cur)-perHostSampleCap:]
	}
	b.samples[hostID] = cur
	trainingSampleHosts.Set(float64(len(b.samples)))
}

// flatten 合并所有主机的样本作为训练集。
func (b *hostSampleBuffer) flatten() [][]float64 {
	total := 0
	for _, rows := range b.samples {
		total += len(rows)
	}
	out := make([][]float64, 0, total)
	for _, rows := range b.samples {
		out = append(out, rows...)
	}
	return out
}

// count 返回样本总数。
func (b *hostSampleBuffer) count() int {
	n := 0
	for _, rows := range b.samples {
		n += len(rows)
	}
	return n
}

// hosts 返回参与训练的主机数。
func (b *hostSampleBuffer) hosts() int { return len(b.samples) }
