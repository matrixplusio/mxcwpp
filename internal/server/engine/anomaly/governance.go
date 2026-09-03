package anomaly

import (
	"strings"
	"sync"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 误报治理：绝对下限 + 证据分级 + 抑制缓存 + 反馈闭环。
// 与 EDR(celengine 白名单/保真分级)、BDE(baseline tuning 反馈)对齐，补齐 ML 异常引擎此前的裸奔状态。

// metricFloor 各指标"算作 elevated"的绝对下限（对齐 MetricNames 索引）。
//
// 根因：correlation 只看 值/主机均值 的比值，空闲主机基线趋近 0（如 net_connect 均值 0.06），
// 做 1 个连接比值就 16 倍爆表 → 基础设施偶发流量误报洪水。加绝对下限后，
// 指标绝对值本身不够高就不计入 elevated，从源头掐掉"除以极小基线"的假阳性。
// 计数类给有意义的量级；比率类(net_external_ratio/dns_nx_ratio)给 0.3。
var metricFloor = [featureCount]float64{
	10,  // 0 proc_exec_count
	5,   // 1 proc_unique_exe
	5,   // 2 proc_fork_rate
	20,  // 3 file_write_count
	10,  // 4 file_unique_path
	3,   // 5 file_sensitive_hits（敏感，下限低）
	20,  // 6 net_connect_count
	10,  // 7 net_unique_ip
	10,  // 8 net_unique_port
	0.3, // 9 net_external_ratio（比率）
	20,  // 10 dns_query_count
	10,  // 11 dns_unique_domain
	0.3, // 12 dns_nx_ratio（比率）
}

// --- M0 DNS 可信性闸 ---
//
// 背景：agent 侧尚未采集真实 DNS 的 domain / rcode，dns_unique_domain / dns_nx_ratio 两维不可信：
//   - dns_unique_domain：无 domain 字段，恒近 0；
//   - dns_nx_ratio：无 rcode，无法判 NXDOMAIN，恒为 0。
// 且 c2_beacon 回查 ebpf_events 的 dns_query 事件拿到的 remote_addr 是 resolver IP，不是被查询域名，
// 把它当 SuspiciousDomains 就是"把 resolver IP 称 domain"。M0 一律禁用依赖这两维的检测/富化，
// 待 M1 接通真实 domain/rcode 字段后再放开（见 Detector.dnsValid）。

// dnsInvalidIndices 是 M0 不可信的 DNS 指标索引集合（dns_unique_domain=11 / dns_nx_ratio=12）。
// dns_query_count(10) 只是查询计数、不依赖 domain/rcode，仍可信，不在此列。
var dnsInvalidIndices = map[int]struct{}{11: {}, 12: {}}

// dnsFieldInvalidIndex 判断某指标索引是否属于 M0 不可信的 DNS 维（domain/rcode 未接通）。
func dnsFieldInvalidIndex(idx int) bool {
	_, ok := dnsInvalidIndices[idx]
	return ok
}

// patternRequiresDNSFields 判断某 correlation pattern 是否本质依赖不可信的 DNS 维而应在 M0 整体禁用。
// reconnaissance 的核心信号是 dns_nx_ratio（DNS 枚举/NXDOMAIN），domain/rcode 未接通前它既不可达、
// 又会把 resolver IP 误当域名 IOC，故整体禁用；c2_beacon 剔除不可信维后仍有充分的 proc/net 信号，不禁用。
func patternRequiresDNSFields(name string) bool {
	return name == "reconnaissance"
}

// severityRank 用于取严重度上限（数值大=更严重）。
var severityRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

func capSeverity(band, ceiling string) string {
	if severityRank[band] > severityRank[ceiling] {
		return ceiling
	}
	return band
}

// correlationSeverity 按证据强度给 correlation 告警定级，不再一律 pattern 硬编码。
// 覆盖率(命中指标占比) + 平均比值 决定档位，且以 pattern 声明的 severity 为上限。
// → 直接消除 c2_beacon 一律 critical 的假 critical 洪水。
func correlationSeverity(ceiling string, elevated []model.ElevatedMetric, total int) string {
	if total == 0 || len(elevated) == 0 {
		return "low"
	}
	coverage := float64(len(elevated)) / float64(total)
	var sum float64
	for _, e := range elevated {
		sum += e.Ratio
	}
	avg := sum / float64(len(elevated))

	band := "medium"
	switch {
	case coverage >= 0.99 && avg >= 8:
		band = "critical"
	case coverage >= 0.8 && avg >= 5:
		band = "high"
	}
	return capSeverity(band, ceiling)
}

// forestSeverity 重校准 IForest 严重度，并封顶 high。
// IForest 是舰队级粗粒度联合离群信号，与更成熟的 BDE 行为引擎同源重叠（P2 收敛），
// 单独不足以判 critical；作为补充信号封顶 high，避免与 BDE 冗余刷 critical。
func forestSeverity(score float64) string {
	if score >= 0.85 {
		return "high"
	}
	return "medium"
}

// suppressCache 周期性刷新的抑制集合：DB 白名单主机 + 反馈自动抑制的 (host|pattern)。
// 热路径零 DB 查询（对齐 celengine 白名单 reload 模式）。
type suppressCache struct {
	mu       sync.RWMutex
	hosts    map[string]struct{} // alert_whitelists 里配置的豁免主机
	autoSupp map[string]struct{} // 反馈闭环：被反复标 false_positive 的 host|pattern
}

func newSuppressCache() *suppressCache {
	return &suppressCache{hosts: map[string]struct{}{}, autoSupp: map[string]struct{}{}}
}

// autoSuppressFPThreshold 同 (host,pattern) 被标 false_positive 达此次数 → 自动抑制后续告警。
const autoSuppressFPThreshold = 3

// reload 从 DB 重建抑制集合。db=nil 空转。
func (s *suppressCache) reload(db *gorm.DB, logger *zap.Logger) {
	if db == nil {
		return
	}
	// 1. 运维配置的白名单主机（复用 alert_whitelists.host_id）。
	var hostRows []string
	if err := db.Model(&model.AlertWhitelist{}).
		Where("host_id <> ''").Distinct().Pluck("host_id", &hostRows).Error; err != nil {
		logger.Warn("anomaly 抑制：加载白名单主机失败", zap.Error(err))
	}
	hosts := make(map[string]struct{}, len(hostRows))
	for _, h := range hostRows {
		hosts[h] = struct{}{}
	}

	// 2. 反馈闭环：analyst 反复标 false_positive 的 (host,pattern) 自动抑制。
	//    处置结果不再是死数据 —— 对齐 BDE reloadTuning 的反馈精神。
	type fpRow struct {
		HostID      string `gorm:"column:host_id"`
		PatternName string `gorm:"column:pattern_name"`
		AlertType   string `gorm:"column:alert_type"`
		C           int64
	}
	var fps []fpRow
	if err := db.Model(&model.AnomalyAlert{}).
		Select("host_id, pattern_name, alert_type, count(*) as c").
		Where("status = ?", "false_positive").
		Group("host_id, pattern_name, alert_type").
		Having("count(*) >= ?", autoSuppressFPThreshold).
		Scan(&fps).Error; err != nil {
		logger.Warn("anomaly 抑制：加载反馈 false_positive 失败", zap.Error(err))
	}
	auto := make(map[string]struct{}, len(fps))
	for _, f := range fps {
		auto[suppressKey(f.HostID, f.AlertType, f.PatternName)] = struct{}{}
	}

	s.mu.Lock()
	s.hosts = hosts
	s.autoSupp = auto
	s.mu.Unlock()
	logger.Debug("anomaly 抑制集合已刷新",
		zap.Int("whitelist_hosts", len(hosts)), zap.Int("auto_suppressed", len(auto)))
}

func suppressKey(hostID, alertType, pattern string) string {
	return hostID + "|" + alertType + "|" + pattern
}

// suppressed 判断该告警是否应被抑制（白名单主机 或 反馈自动抑制）。
func (s *suppressCache) suppressed(hostID, alertType, pattern string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.hosts[hostID]; ok {
		return true
	}
	_, ok := s.autoSupp[suppressKey(hostID, alertType, pattern)]
	return ok
}

// isInfraHostname 识别典型基础设施主机名（CDN/ZK/大数据/消息队列/数据库），
// 这类主机有合法周期性流量，是 correlation 误报大户，命中则降级不消音（仍入库可查）。
func isInfraHostname(hostname string) bool {
	h := strings.ToLower(hostname)
	for _, kw := range []string{"cdn", "zookeeper", "-zk-", "kafka", "rocketmq", "bigdata", "cdh", "hadoop", "datasvr", "-db-", "mysql", "redis", "mongo", "clickhouse"} {
		if strings.Contains(h, kw) {
			return true
		}
	}
	return false
}

// downgradeForInfra 基础设施主机的告警降一级（不消音，保留内网横向可见性）。
func downgradeForInfra(sev string) string {
	switch sev {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return sev
	}
}
