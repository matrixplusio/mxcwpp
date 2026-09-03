package anomaly

import (
	"context"
	"fmt"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// MetricNames maps metric indices to names (matching BDE profiler output).
var MetricNames = [featureCount]string{
	"proc_exec_count", "proc_unique_exe", "proc_fork_rate",
	"file_write_count", "file_unique_path", "file_sensitive_hits",
	"net_connect_count", "net_unique_ip", "net_unique_port", "net_external_ratio",
	"dns_query_count", "dns_unique_domain", "dns_nx_ratio",
}

// Correlation patterns: multi-metric signatures that indicate specific attack types.
//
// MinActive 在 2026-06-04 全面收紧:prod 7d 累积 134k correlation open alert,99.6% 主机命中
// privilege_escalation(221/226),说明阈值过松,把正常业务服务(db/mq/zookeeper 大网络+DNS)
// 误标为 c2_beacon / privilege_escalation。
// 配合 correlationThreshold 2.0 → 3.0 + 24h dedup 大幅压制 false positive。
var correlationPatterns = []correlationPattern{
	{
		// pattern_name 保留 "c2_beacon" 兼容既有 UI/查询/反馈数据；但语义并非已证实的 C2 信标。
		// M0 仅有 proc/net/DNS-volume 的量级联合升高，无周期性(beaconing)特征，故 Description 明确为
		// 待研判的 process/network/DNS-volume correlation、未验证 C2 周期性；Severity 上限 high(绝不 critical)。
		Name:        "c2_beacon",
		Description: "Process/network/DNS-volume correlation pending triage — joint volume elevation across process/network/DNS activity. NOT confirmed C2 beaconing: no periodicity/jitter analysis performed; requires analyst verification.",
		Indices:     []int{0, 6, 7, 10, 11}, // proc_exec, net_connect, net_unique_ip, dns_query, dns_unique_domain
		MinActive:   4,                      // 5 个指标至少 4 个 elevated(原 3,误报太多)
		Severity:    "high",                 // 上限 high：仅量级联合升高不足以判 critical(无周期性证据)
	},
	{
		Name:        "data_exfiltration",
		Description: "Possible data exfiltration: file access + external network",
		Indices:     []int{3, 4, 6, 9}, // file_write, file_unique_path, net_connect, net_external_ratio
		MinActive:   4,                 // 4 个全 elevated(原 3 — 4/4 严格匹配)
		Severity:    "high",
	},
	{
		Name:        "privilege_escalation",
		Description: "Possible privilege escalation: sensitive file access + process forking",
		Indices:     []int{0, 2, 5}, // proc_exec, proc_fork_rate, file_sensitive_hits
		MinActive:   3,              // 3 个全 elevated(原 2 — 太松,99.6% 主机中招)
		Severity:    "high",
	},
	{
		Name:        "reconnaissance",
		Description: "Possible reconnaissance: port scanning + DNS enumeration",
		Indices:     []int{6, 8, 10, 12}, // net_connect, net_unique_port, dns_query, dns_nx_ratio
		MinActive:   4,                   // 4 个全 elevated(原 3)
		Severity:    "medium",
	},
}

type correlationPattern struct {
	Name        string
	Description string
	Indices     []int // metric indices to check
	MinActive   int   // minimum number of elevated metrics
	Severity    string
}

const (
	// retrainInterval is how often the forest is retrained from recent data.
	retrainInterval = 30 * time.Minute

	// defaultAnomalyThreshold is the default score above which a sample is flagged.
	// 可经 feature flag anomaly.score_threshold 覆盖（见 threshold.go）——
	// 不同环境的"正常"离散程度差别很大，写死一个数意味着某些环境必然长期误报或长期漏报。
	defaultAnomalyThreshold = 0.65

	// correlationThreshold is ratio threshold for a metric to be "elevated".
	// 调整 2.0 → 3.0:prod 实际正常业务服务(db/mq)波动经常 >2x 均值,但 <3x。
	// 配合 MinActive 收紧,大幅减少 false positive。
	correlationThreshold = 3.0

	// enrichWindow 决定回查 ebpf_events 提取 IOC 时回看多久。
	// 5 分钟覆盖大多数攻击短链；过长会引入无关 noise。
	enrichWindow = 5 * time.Minute

	// enrichTopN 控制每类 IOC 最多带回 N 个，避免 trigger_context JSON 膨胀。
	enrichTopN = 10

	// enrichQueryTimeout 回查 CH 的硬上限；命中 proj_time_desc projection 时通常 <100ms。
	enrichQueryTimeout = 3 * time.Second
)

// Detector is the server-side ML anomaly detection engine.
// It wraps an Isolation Forest with periodic retraining and
// multi-metric correlation detection.
type Detector struct {
	logger *zap.Logger
	db     *gorm.DB
	chConn chdriver.Conn // 可为 nil；nil 时跳过 IOC 回查，仅写入 metric_snapshot
	forest *IForest

	mu sync.Mutex
	// sampleBuffer 按主机分组的训练样本，每台主机配额受限（详见 sampling.go）。
	// 原为一条全局 FIFO，高频主机会按样本数主导"什么算正常"。
	sampleBuffer *hostSampleBuffer
	hostMeans    map[string][]float64 // per-host running mean for z-score
	hostCounts   map[string]int       // sample count per host
	// reference 是不随滑动窗口移动的长期参照，用于识别环境漂移与训练投毒。
	// 一经建立不再更新（见 drift.go）。
	reference *referenceBaseline
	// lastTrainedAt 上次成功训练的时间。拒绝重训不更新它，模型年龄因而能反映真实情况。
	lastTrainedAt time.Time
	// scores 累积每台主机的异常分供 ranking 档排序使用，周期落库（见 ranking.go）。
	scores *scoreRecorder
	// threshold 是可配置的异常分阈值（见 threshold.go）；未配置时用默认值。
	threshold thresholdHolder
	// persistMu synchronizes safety-mode/schema transitions with anomaly_alerts writes.
	// A writer holds RLock through the DB upsert; SetMode/VerifySchema take Lock, so once
	// a transition to off/shadow returns, no write admitted under the previous mode can remain in flight.
	persistMu sync.RWMutex

	suppress *suppressCache // 白名单主机 + 反馈自动抑制（周期 reload，热路径零 DB）

	// M0 安全模式（读写受 mu 保护）。默认 ModeShadow + schema/DNS 未就绪：
	// 只观测不落库，直到显式配置 context/alert 且 schema gate 通过；alert 还需 schema 就绪才允许 critical。
	mode        Mode
	schemaReady bool // anomaly_alerts 必需列 + 去重唯一索引齐备（VerifySchema 设置）
	dnsValid    bool // DNS domain/rcode 字段可信；M0 恒 false → 禁用依赖 domain/NX 的检测
}

// NewDetector creates a new anomaly detection engine.
// chConn 用于告警生成时回查 ebpf_events 拿攻击链 IOC；可为 nil（ClickHouse 未启用时降级，
// 告警仍生成但 trigger_context 只含 metric_snapshot/elevated_metrics）。
func NewDetector(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) *Detector {
	d := &Detector{
		logger:     logger,
		db:         db,
		chConn:     chConn,
		forest:     NewIForest(),
		hostMeans:  make(map[string][]float64),
		hostCounts: make(map[string]int),
		suppress:   newSuppressCache(),
		// 安全默认：shadow 模式（只观测不落库）+ schema/DNS 未就绪。
		// 调用方须显式 SetMode(LoadMode 结果) / VerifySchema 才能改变。
		mode:        ModeShadow,
		schemaReady: false,
		dnsValid:    false,
	}
	d.sampleBuffer = newHostSampleBuffer()
	d.scores = newScoreRecorder(db, logger)
	d.suppress.reload(db, logger) // 启动即加载一次白名单 + 反馈抑制
	return d
}

// SetMode 设置检测器安全模式（规整非法值为 shadow 安全默认）。
func (d *Detector) SetMode(m Mode) {
	d.persistMu.Lock()
	defer d.persistMu.Unlock()
	d.mu.Lock()
	d.mode = normalizeMode(string(m))
	d.mu.Unlock()
}

// anomalyAlertDedupIndex 是 anomaly_alerts 去重唯一索引名（与 migration 包保持一致）。
// upsert 去重依赖它才能生效；缺失则 schema gate 判定未就绪、禁止 alert 官方模式。
const anomalyAlertDedupIndex = "ux_anomaly_alerts_dedup"

// VerifySchema 校验 anomaly_alerts 的必需列（hit_count/last_seen_at）与去重唯一索引是否齐备，
// 设置并返回 schemaReady。缺失时清晰记录原因：不 fatal 整个进程（服务保持存活、其余功能不受影响），
// 仅令一切会落库的模式（context/alert）fail-closed 降级为 shadow（只观测不落库，见 EffectiveMode）；
// 就绪状态通过 Status() 暴露给 /readyz 与 Prometheus。
func (d *Detector) VerifySchema() bool {
	ready := true
	if d.db == nil {
		d.persistMu.Lock()
		d.mu.Lock()
		d.schemaReady = false
		d.mu.Unlock()
		d.persistMu.Unlock()
		d.logger.Warn("anomaly schema gate：db 为空，判定未就绪")
		return false
	}
	mig := d.db.Migrator()
	var missing []string
	for _, col := range []string{"hit_count", "last_seen_at"} {
		if !mig.HasColumn(&model.AnomalyAlert{}, col) {
			missing = append(missing, "column:"+col)
			ready = false
		}
	}
	if !mig.HasIndex(&model.AnomalyAlert{}, anomalyAlertDedupIndex) {
		missing = append(missing, "index:"+anomalyAlertDedupIndex)
		ready = false
	}
	d.persistMu.Lock()
	d.mu.Lock()
	d.schemaReady = ready
	d.mu.Unlock()
	d.persistMu.Unlock()
	if ready {
		d.logger.Info("anomaly schema gate 通过：必需列 + 去重唯一索引齐备")
	} else {
		d.logger.Error("anomaly schema gate 未通过：缺失关键 schema，落库模式已 fail-closed 降级为 shadow（只观测不落库）",
			zap.Strings("missing", missing))
	}
	return ready
}

// EffectiveMode 返回生效模式（fail-closed）：schema 未就绪时，一切会落库的模式（context/alert）
// 降级为 shadow（只观测不落库）；off 保持 off。
func (d *Detector) EffectiveMode() Mode {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.effectiveModeLocked()
}

func (d *Detector) effectiveModeLocked() Mode {
	if d.mode == ModeOff {
		return ModeOff
	}
	// fail-closed：缺 hit_count/last_seen_at/去重唯一索引时绝不写 anomaly_alerts —— 无去重索引会让
	// upsert 退化成"每次触发新建一行"刷屏。context/alert 一律降为 shadow（只观测不落库）。
	if !d.schemaReady {
		return ModeShadow
	}
	return d.mode
}

// officialCeilingLocked 返回当前允许的最高严重度：仅生效 alert 模式才允许 critical，
// 其余（off/shadow/context/ranking 及降级）封顶 high —— 结构性禁止 ML 信号被当作正式高危定罪。
//
// ranking 档同样封顶 high：它只改变告警被看到的顺序，不改变告警的严重程度。
func (d *Detector) officialCeilingLocked() string {
	if d.effectiveModeLocked() == ModeAlert {
		return "critical"
	}
	return "high"
}

// persistEligibleLocked 判断当前是否允许落库 anomaly_alerts：仅生效 context/alert 两种模式为真。
// off/shadow 及任何降级/未知模式一律为假。调用方必须持 d.mu；真正写入必须经
// persistAnomalyIfEligible，在 persistMu 保护下做最终检查，不能依赖早先的模式快照。
func (d *Detector) persistEligibleLocked() bool {
	em := d.effectiveModeLocked()
	return em == ModeContext || em == ModeRanking || em == ModeAlert
}

// rankingEligibleLocked 判断异常分是否参与已有告警的排序。
//
// 仅 ranking / alert 两档为真。排序不新建告警，只改已存在告警的 risk_score——
// 让分析师在异常主机上的告警先被看到。调用方必须持 d.mu。
func (d *Detector) rankingEligibleLocked() bool {
	em := d.effectiveModeLocked()
	return em == ModeRanking || em == ModeAlert
}

// RankingEligible 报告异常分当前是否参与告警排序。
func (d *Detector) RankingEligible() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rankingEligibleLocked()
}

// persistAnomalyIfEligible 在真正写库前再次检查生效模式，并把检查与 upsert 放在同一个
// persistMu 读临界区内。SetMode/VerifySchema 使用写锁，因此不会出现“已切到 off/shadow，
// 旧协程仍按 context/alert 快照落库”的竞态。
func (d *Detector) persistAnomalyIfEligible(alert *model.AnomalyAlert) (Mode, bool) {
	d.persistMu.RLock()
	defer d.persistMu.RUnlock()

	d.mu.Lock()
	em := d.effectiveModeLocked()
	eligible := d.persistEligibleLocked()
	// 模式可能在前面的检测/富化期间从 alert 切到 context；最终写入前按当前模式再次封顶，
	// 避免旧的 critical 快照在 context 下落库。
	alert.Severity = capSeverity(alert.Severity, d.officialCeilingLocked())
	d.mu.Unlock()
	if !eligible {
		return em, false
	}
	d.upsertAnomaly(alert)
	return em, true
}

// Status 返回检测器运行时状态快照（供 /readyz 与 Prometheus 指标）。
func (d *Detector) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{
		Mode:          d.mode,
		EffectiveMode: d.effectiveModeLocked(),
		SchemaReady:   d.schemaReady,
		DNSFieldReady: d.dnsValid,
		Trained:       d.forest.Trained(),
		SampleCount:   d.sampleBuffer.count(),
		HostCount:     len(d.hostMeans),
	}
}

// StartRetrain begins periodic retraining in the background.
// Call after Consumer startup.
func (d *Detector) StartRetrain(stop <-chan struct{}) {
	// 异常分落库与重训同一处启动：两者都是检测器的后台循环，
	// 分开启动容易出现"重训在跑但分数没人落库"的半启动状态。
	if d.scores != nil {
		d.scores.StartScoreFlush(stop)
	}
	go func() {
		ticker := time.NewTicker(retrainInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				d.retrain()
				d.suppress.reload(d.db, d.logger) // 周期刷新白名单 + 反馈抑制（反馈闭环）
			}
		}
	}()
}

// Ingest processes a BDE snapshot from a host.
// Returns anomaly alerts if any are generated.
func (d *Detector) Ingest(hostID, hostname string, metrics []float64) {
	if len(metrics) != featureCount {
		return
	}

	d.mu.Lock()
	// off 模式完全空转：不缓冲、不打分、不产信号。
	if d.mode == ModeOff {
		d.mu.Unlock()
		return
	}
	// Add to sample buffer（按主机配额，单机无法主导训练集）。
	d.sampleBuffer.add(hostID, metrics)

	// Update per-host running mean (for correlation z-score).
	d.updateHostMean(hostID, metrics)
	hostMean := d.hostMeans[hostID]
	hostCount := d.hostCounts[hostID]
	d.mu.Unlock()

	// Skip detection during warm-up phase (need sufficient history).
	if hostCount < 50 {
		return
	}

	// 1. Isolation Forest scoring.
	if d.forest.Trained() {
		score := d.forest.Score(metrics)
		// ranking 档：记录分数供已有告警排序。**所有评分都记**，不只是超阈值的——
		// 排序需要知道"这台主机现在多正常"，只记异常的那些会让正常主机没有分数，
		// 从而无法与异常主机比较。
		d.mu.Lock()
		rank := d.rankingEligibleLocked()
		d.mu.Unlock()
		if rank && d.scores != nil {
			d.scores.record(hostID, score, time.Now())
		}
		if score >= d.scoreThreshold() {
			d.emitForestAlert(hostID, hostname, metrics, score)
		}
	}

	// 2. Multi-metric correlation detection.
	if hostMean != nil {
		d.checkCorrelations(hostID, hostname, metrics, hostMean)
	}
}

// Trained returns whether the forest has been trained.
func (d *Detector) Trained() bool {
	return d.forest.Trained()
}

// SampleCount returns the number of samples in the training buffer.
func (d *Detector) SampleCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sampleBuffer.count()
}

// HostCount returns the number of unique hosts tracked.
func (d *Detector) HostCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.hostMeans)
}

// --- Internal methods ---

func (d *Detector) retrain() {
	d.mu.Lock()
	data := d.sampleBuffer.flatten()
	trainHosts := d.sampleBuffer.hosts()
	d.mu.Unlock()

	if len(data) < 64 {
		d.logger.Debug("insufficient samples for IForest training",
			zap.Int("samples", len(data)))
		return
	}

	// 首次积够样本时固定一份长期参照。它此后不再跟随滑动窗口移动——
	// 一旦参照也跟着漂，就和被它监督的对象一起漂走了。
	newRef := false
	d.mu.Lock()
	if d.reference == nil {
		if ref := newReferenceBaseline(trimOutliers(data)); ref != nil {
			d.reference = ref
			d.logger.Info("已建立异常检测长期参照基线",
				zap.Int("samples", ref.samples))
			newRef = true
		}
	}
	ref := d.reference
	d.mu.Unlock()
	if newRef {
		// 参照一建立就落库：它必须来自一段未被污染的历史，丢了就再也长不回来。
		d.SaveState()
	}

	driftSigma := 0.0
	if ref != nil {
		rep := ref.evaluateDrift(data)
		driftSigma = rep.MaxDrift
		for i, v := range rep.PerFeature {
			anomalyDriftScore.WithLabelValues(featureName(i)).Set(v)
		}
		if rep.Poisoned {
			// 拒绝用这批数据重训，继续使用旧模型。
			//
			// 滑窗重训的固有弱点是：攻击者只要把动作放慢到跨越多个窗口，
			// 每一窗都只比上一窗高一点，最后攻击行为会成为基线。
			// 这里宁可让模型变旧，也不要学一个可能已被污染的新模型。
			anomalyRetrainRejected.WithLabelValues("drift").Inc()
			d.recordRejectedRetrain()
			d.logger.Warn("训练窗口偏离长期基线过大，已拒绝本轮重训（继续使用旧模型）",
				zap.Float64("max_drift_sigma", rep.MaxDrift),
				zap.String("worst_feature", featureName(rep.WorstFeature)),
				zap.Float64("threshold_sigma", driftThreshold),
				zap.Int("samples", len(data)))
			d.publishModelAge()
			return
		}
	}

	d.forest.Train(data)
	d.mu.Lock()
	d.lastTrainedAt = time.Now()
	d.mu.Unlock()
	d.publishModelAge()
	d.SaveState()
	// 每次成功训练留一个可回滚版本。没有版本就没有退路：
	// 某轮学坏了只能等下一个 30 分钟周期，而在那之前检测一直在用坏模型打分。
	d.saveModelVersion(len(data), driftSigma)
	d.logger.Info("IForest retrained",
		zap.Int("samples", len(data)),
		zap.Int("hosts", trainHosts),
		zap.Bool("trained", d.forest.Trained()))
}

// publishModelAge 上报模型自上次成功训练以来的时长。
//
// 连续拒绝重训会让模型悄悄变旧，而"拒绝"本身在指标上表现为一个计数器增长，
// 不看历史就看不出来。模型年龄让这件事随时可见。
func (d *Detector) publishModelAge() {
	d.mu.Lock()
	last := d.lastTrainedAt
	d.mu.Unlock()
	if last.IsZero() {
		return
	}
	anomalyModelAge.Set(time.Since(last).Seconds())
}

func (d *Detector) updateHostMean(hostID string, metrics []float64) {
	mean, ok := d.hostMeans[hostID]
	if !ok {
		mean = make([]float64, featureCount)
		d.hostMeans[hostID] = mean
		d.hostCounts[hostID] = 0
	}

	d.hostCounts[hostID]++
	n := float64(d.hostCounts[hostID])

	// Online mean update: mean = mean + (x - mean) / n
	for i, v := range metrics {
		mean[i] += (v - mean[i]) / n
	}
}

// metricSnapshot 把 13 维 metrics 转成 name→value 映射，供 SOC 在 UI 上看。
func metricSnapshot(metrics []float64) map[string]float64 {
	out := make(map[string]float64, featureCount)
	for i, v := range metrics {
		out[MetricNames[i]] = v
	}
	return out
}

func (d *Detector) emitForestAlert(hostID, hostname string, metrics []float64, score float64) {
	// Find the metric with the largest deviation from mean.
	d.mu.Lock()
	mean := d.hostMeans[hostID]
	d.mu.Unlock()

	topMetric := ""
	topValue := 0.0
	if mean != nil {
		maxDev := 0.0
		for i, v := range metrics {
			dev := v - mean[i]
			if dev < 0 {
				dev = -dev
			}
			if dev > maxDev {
				maxDev = dev
				topMetric = MetricNames[i]
				topValue = v
			}
		}
	}

	// 抑制：白名单主机 / 反馈自动抑制直接跳过（IForest 路径也纳入治理）。
	if d.suppress.suppressed(hostID, "isolation_forest", "") {
		return
	}

	// severity 重校准并封顶 high（IForest 是与 BDE 同源重叠的粗粒度信号，不单独判 critical）。
	severity := forestSeverity(score)
	if topMetric != "" && isInfraHostname(hostname) {
		severity = downgradeForInfra(severity)
	}
	// M0 安全模式：非生效 alert 一律封顶 high。落库资格在真正 upsert 前再次检查。
	d.mu.Lock()
	severity = capSeverity(severity, d.officialCeilingLocked())
	d.mu.Unlock()

	// 拼描述：让 UI drawer 至少有一行有意义内容，避免 v-if 空白
	description := fmt.Sprintf("Isolation Forest 异常评分 %.2f（>=%.2f 触发告警）", score, d.scoreThreshold())
	if topMetric != "" {
		description = fmt.Sprintf("指标 %s 偏离主机历史均值，当前值 %.2f；Isolation Forest 异常评分 %.2f",
			topMetric, topValue, score)
	}

	// Forest 路径：以 Top 偏离指标 + 全量 snapshot 作 trigger_context
	// （IForest 全维度异常，无明确 pattern 子集，跳过攻击链 IOC 回查）
	trigger := model.AnomalyTriggerContext{
		MetricSnapshot: metricSnapshot(metrics),
	}
	if mean != nil {
		// 列出 top 3 偏离最大的指标作 elevated
		trigger.ElevatedMetrics = topDeviations(metrics, mean, 3)
	}

	alert := model.AnomalyAlert{
		HostID:         hostID,
		Hostname:       hostname,
		AlertType:      "isolation_forest",
		Severity:       severity,
		AnomalyScore:   score,
		TopMetric:      topMetric,
		TopValue:       topValue,
		Description:    description,
		TriggerContext: trigger,
		Status:         "open",
	}

	// 只有生效 context/alert 才落库；off/shadow 及并发降级一律只观测不落库
	// （零业务影响地观察模型行为，且防止 SetMode 并发切 off 后仍 upsert）。
	if em, persisted := d.persistAnomalyIfEligible(&alert); !persisted {
		d.logger.Info("IForest anomaly detected (not persisted)",
			zap.String("host_id", hostID),
			zap.String("effective_mode", string(em)),
			zap.Float64("score", score),
			zap.String("top_metric", topMetric),
			zap.String("severity", severity))
		return
	}

	d.logger.Warn("IForest anomaly detected",
		zap.String("host_id", hostID),
		zap.Float64("score", score),
		zap.String("top_metric", topMetric),
		zap.String("severity", severity))

	// 已落库的异常发往通知出口。anomaly_alerts 此前没有任何通知链路——检测跑了、
	// 写进表了、值班不知道。默认类别未开启时这里只计量不发送。
	// 抑制身份取 (host, 指标)：同一主机同一指标持续异常不重复打扰。
	alertbus.Publish(alertbus.Event{
		Category:    model.NotifyCategoryAnomalyAlert,
		Source:      "anomaly",
		HostID:      hostID,
		Hostname:    hostname,
		Severity:    severity,
		Title:       "主机指标异常：" + topMetric,
		Description: description,
		DedupKey:    "anomaly|" + hostID + "|" + topMetric,
		RefTable:    "anomaly_alerts",
	})
}

// topDeviations 返回 metrics 与 mean 差异最大的 N 个指标。
func topDeviations(metrics, mean []float64, n int) []model.ElevatedMetric {
	type devItem struct {
		idx   int
		ratio float64
	}
	items := make([]devItem, 0, len(metrics))
	for i, v := range metrics {
		if mean[i] == 0 {
			continue
		}
		ratio := v / mean[i]
		if ratio <= 1 {
			continue // 严格超出均值才算偏离；ratio=1 等于历史均值，不是异常信号
		}
		items = append(items, devItem{idx: i, ratio: ratio})
	}
	// 简单 selection sort 取 top N（N 小，O(N×M) 足够）
	out := make([]model.ElevatedMetric, 0, n)
	for k := 0; k < n && len(items) > 0; k++ {
		maxIdx := 0
		for i := 1; i < len(items); i++ {
			if items[i].ratio > items[maxIdx].ratio {
				maxIdx = i
			}
		}
		it := items[maxIdx]
		out = append(out, model.ElevatedMetric{
			Name:     MetricNames[it.idx],
			Current:  metrics[it.idx],
			Baseline: mean[it.idx],
			Ratio:    it.ratio,
		})
		items = append(items[:maxIdx], items[maxIdx+1:]...)
	}
	return out
}

func (d *Detector) checkCorrelations(hostID, hostname string, metrics, mean []float64) {
	d.mu.Lock()
	ceiling := d.officialCeilingLocked()
	dnsValid := d.dnsValid
	d.mu.Unlock()

	for _, pattern := range correlationPatterns {
		// M0：DNS domain/rcode 未接生产前，禁用依赖 domain/NX 的侦察检测——它靠 dns_nx_ratio，
		// 而该字段恒为 0（无 rcode），既不可达又会把 resolver IP 误当域名 IOC。M1 修好 DNS 后放开。
		if patternRequiresDNSFields(pattern.Name) && !dnsValid {
			continue
		}
		elevatedCount := 0
		validTotal := 0 // 参与判定的有效指标数（剔除 M0 不可信的 DNS 域名/NX 指标）
		elevated := make([]model.ElevatedMetric, 0, len(pattern.Indices))
		for _, idx := range pattern.Indices {
			// M0：dns_unique_domain / dns_nx_ratio 依赖未采集的 domain/rcode，不可信，
			// 不计入判定，避免无效 DNS 字段推高覆盖率/severity 产生 critical。
			if !dnsValid && dnsFieldInvalidIndex(idx) {
				continue
			}
			validTotal++
			if mean[idx] == 0 {
				continue
			}
			// 绝对下限：指标当前值本身不够高就不算 elevated，
			// 掐掉"空闲主机基线趋近 0 → 做 1 个连接比值就爆表"的假阳性。
			if metrics[idx] < metricFloor[idx] {
				continue
			}
			// Simple ratio-based elevation check (current/mean > threshold).
			ratio := metrics[idx] / mean[idx]
			if ratio > correlationThreshold {
				elevatedCount++
				elevated = append(elevated, model.ElevatedMetric{
					Name:     MetricNames[idx],
					Current:  metrics[idx],
					Baseline: mean[idx],
					Ratio:    ratio,
				})
			}
		}

		if elevatedCount < pattern.MinActive {
			continue
		}

		// 抑制：白名单主机 / 反馈闭环自动抑制的 (host,pattern) 直接跳过。
		if d.suppress.suppressed(hostID, "correlation", pattern.Name) {
			continue
		}

		// severity 按证据强度分级（覆盖率+平均比值），以 pattern 声明值为上限，
		// 替代此前一律硬编码 → 消除 c2_beacon 假 critical 洪水。
		severity := correlationSeverity(pattern.Severity, elevated, validTotal)
		// 基础设施主机（CDN/ZK/大数据/DB/MQ）有合法周期流量，降一级但不消音（保留可见性）。
		if isInfraHostname(hostname) {
			severity = downgradeForInfra(severity)
		}
		// M0 安全模式：官方严重度上限（非生效 alert 一律封顶 high，禁止 ML 正式判 critical）。
		severity = capSeverity(severity, ceiling)

		// Correlation 路径：补充攻击链 IOC（按 pattern 类型回查 ebpf_events）。
		// 回查失败不阻塞告警生成，只是 trigger_context 字段缺失。
		now := time.Now()
		windowStart := now.Add(-enrichWindow)
		trigger := model.AnomalyTriggerContext{
			ElevatedMetrics: elevated,
			MetricSnapshot:  metricSnapshot(metrics),
			WindowStart:     windowStart.Format("2006-01-02 15:04:05"),
			WindowEnd:       now.Format("2006-01-02 15:04:05"),
		}
		d.enrichTriggerContext(&trigger, pattern.Name, hostID, dnsValid, windowStart, now)

		score := 0.0
		if validTotal > 0 {
			score = float64(elevatedCount) / float64(validTotal)
		}
		alert := model.AnomalyAlert{
			HostID:         hostID,
			Hostname:       hostname,
			AlertType:      "correlation",
			PatternName:    pattern.Name,
			Severity:       severity,
			AnomalyScore:   score,
			Description:    pattern.Description,
			TriggerContext: trigger,
			Status:         "open",
		}

		// 只有生效 context/alert 才落库；off/shadow 及并发降级一律只观测不落库
		// （防止 SetMode 在 Ingest 后并发切 off/shadow 时快照仍 upsert）。
		if em, persisted := d.persistAnomalyIfEligible(&alert); !persisted {
			d.logger.Info("correlation pattern detected (not persisted)",
				zap.String("host_id", hostID),
				zap.String("effective_mode", string(em)),
				zap.String("pattern", pattern.Name),
				zap.Int("elevated_metrics", elevatedCount),
				zap.String("severity", severity))
			continue
		}

		d.logger.Warn("correlation pattern detected",
			zap.String("host_id", hostID),
			zap.String("pattern", pattern.Name),
			zap.Int("elevated_metrics", elevatedCount),
			zap.String("severity", severity),
			zap.Int("suspicious_ips", len(trigger.SuspiciousIPs)),
			zap.Int("suspicious_domains", len(trigger.SuspiciousDomains)),
			zap.Int("sensitive_files", len(trigger.SensitiveFiles)),
		)
	}
}

// upsertAnomaly 按唯一键 (tenant_id, host_id, alert_type, pattern_name, top_metric) 去重落库：
// 首次插入，复发则累加 hit_count + 刷新 last_seen/score，绝不新建行、绝不覆盖已处置 status。
// 结构性根治此前"每次触发新建一行"刷屏，并修掉旧 dedup"标 false_positive 反被解封重报"的缺陷。
func (d *Detector) upsertAnomaly(alert *model.AnomalyAlert) {
	now := model.Now()
	alert.LastSeenAt = now
	if alert.HitCount == 0 {
		alert.HitCount = 1
	}
	err := d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "tenant_id"}, {Name: "host_id"}, {Name: "alert_type"},
			{Name: "pattern_name"}, {Name: "top_metric"},
		},
		DoUpdates: clause.Assignments(map[string]any{
			"hit_count":     gorm.Expr("hit_count + 1"),
			"anomaly_score": alert.AnomalyScore,
			"last_seen_at":  now,
			"updated_at":    now,
		}),
	}).Create(alert).Error
	if err != nil {
		d.logger.Error("failed to upsert anomaly alert", zap.Error(err))
	}
}

// enrichTriggerContext 根据 pattern 类型回查 ebpf_events 拿 IOC。
// 失败不返回错误，只是 trigger_context 对应字段为空（已记日志）。
//
// 查询都走 proj_time_desc projection + (host_id, timestamp) 过滤，P99 < 200ms。
// 整体硬上限 enrichQueryTimeout=3s，避免单次告警拖累 BDE 主流程。
func (d *Detector) enrichTriggerContext(trigger *model.AnomalyTriggerContext, patternName, hostID string, dnsValid bool, start, end time.Time) {
	if d.chConn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), enrichQueryTimeout)
	defer cancel()

	switch patternName {
	case "c2_beacon":
		trigger.SuspiciousIPs = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('tcp_connect','udp_send') AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
		// M0：dns_query 事件的 remote_addr 是 resolver IP、不是被查询域名。DNS domain 字段接通前
		// 绝不把 resolver IP 当 SuspiciousDomains 富化（否则就是"把 resolver IP 称 domain"）。M1 放开。
		if dnsValid {
			trigger.SuspiciousDomains = d.queryTopStrings(ctx, hostID, start, end,
				"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type = 'dns_query' AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
		}
		trigger.ProcessChain = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT exe FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type = 'process_exec' AND exe != '' GROUP BY exe ORDER BY count() DESC LIMIT ?")
	case "data_exfiltration":
		trigger.SensitiveFiles = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT file_path FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('file_open','file_read','file_write') AND file_path != '' GROUP BY file_path ORDER BY count() DESC LIMIT ?")
		trigger.SuspiciousIPs = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('tcp_connect','udp_send') AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
	case "privilege_escalation":
		trigger.SensitiveFiles = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT file_path FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('file_open','file_chmod','file_read') AND file_path != '' AND (file_path LIKE '/etc/%' OR file_path LIKE '/root/%' OR file_path LIKE '%/.ssh/%' OR file_path LIKE '%/shadow' OR file_path LIKE '%/sudoers%') GROUP BY file_path ORDER BY count() DESC LIMIT ?")
		trigger.ProcessChain = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT exe FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type = 'process_exec' AND exe != '' GROUP BY exe ORDER BY count() DESC LIMIT ?")
	case "reconnaissance":
		// recon 在 M0 已被 patternRequiresDNSFields 整体禁用，此分支仅在 DNS 就绪后可达；
		// SuspiciousDomains 同样只在 dnsValid 时富化，避免 resolver IP 被当域名。
		trigger.ScannedPorts = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_port FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('tcp_connect','udp_send') AND remote_port != '' GROUP BY remote_port ORDER BY count() DESC LIMIT ?")
		if dnsValid {
			trigger.SuspiciousDomains = d.queryTopStrings(ctx, hostID, start, end,
				"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type = 'dns_query' AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
		}
	}
}

// queryTopStrings 是 enrichTriggerContext 内部辅助：执行单列 string 查询返回 Top N。
// 失败/超时仅 Warn 日志，不向上抛错。
func (d *Detector) queryTopStrings(ctx context.Context, hostID string, start, end time.Time, sqlStr string) []string {
	rows, err := d.chConn.Query(ctx, sqlStr, hostID, start, end, enrichTopN)
	if err != nil {
		d.logger.Warn("trigger context CH query failed",
			zap.String("host_id", hostID),
			zap.Error(err))
		return nil
	}
	defer rows.Close()
	out := make([]string, 0, enrichTopN)
	for rows.Next() {
		var s string
		if scanErr := rows.Scan(&s); scanErr == nil && s != "" {
			out = append(out, s)
		}
	}
	if err := rows.Err(); err != nil {
		d.logger.Warn("trigger context CH rows iteration failed",
			zap.String("host_id", hostID),
			zap.Error(err))
	}
	return out
}
