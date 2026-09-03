package intrusion

import "github.com/prometheus/client_golang/prometheus"

// 异常登录检测的学习期指标。
//
// 学习期的行为是「静默不告警」，它和「检测根本没生效」在告警面上一模一样：
// 两种情况下界面都是零条。没有指标就分不清这两者，也就没人会发现检测挂了。
var (
	hostsLearningDesc = prometheus.NewDesc(
		"mxcwpp_engine_abnormal_login_hosts_learning",
		"Hosts whose login profile is still inside the learning window (detection silent)",
		nil, nil)
	hostsGraduatedDesc = prometheus.NewDesc(
		"mxcwpp_engine_abnormal_login_hosts_graduated",
		"Hosts that finished the learning window (detection active)",
		nil, nil)
	suppressedDesc = prometheus.NewDesc(
		"mxcwpp_engine_abnormal_login_suppressed_total",
		"Alerts suppressed because the host was still in its learning window",
		nil, nil)
)

// learningCollector 每次抓取取一次快照。
// 用 Collector 而不是三个 GaugeFunc: 三次 GaugeFunc 会各锁一次、各扫一遍画像，
// 且三个数来自三个时刻，加起来对不上。
type learningCollector struct {
	d *AbnormalLoginDetector
}

func (c learningCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- hostsLearningDesc
	ch <- hostsGraduatedDesc
	ch <- suppressedDesc
}

func (c learningCollector) Collect(ch chan<- prometheus.Metric) {
	st := c.d.Stats()
	ch <- prometheus.MustNewConstMetric(hostsLearningDesc, prometheus.GaugeValue, float64(st.HostsLearning))
	ch <- prometheus.MustNewConstMetric(hostsGraduatedDesc, prometheus.GaugeValue, float64(st.HostsGraduated))
	ch <- prometheus.MustNewConstMetric(suppressedDesc, prometheus.CounterValue, float64(st.SuppressedTotal))
}

// RegisterMetrics 把学习期快照注册成指标。reg 为 nil 时用默认注册表。
// 重复注册返回 error 由调用方决定是否致命——engine 里只注册一次。
func (d *AbnormalLoginDetector) RegisterMetrics(reg prometheus.Registerer) error {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	return reg.Register(learningCollector{d: d})
}
