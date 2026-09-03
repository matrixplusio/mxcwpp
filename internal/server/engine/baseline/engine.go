// Package baseline implements the Server-side Behavior Detection Engine (BDE)
// baseline. It consumes behavior profile snapshots from Agents, maintains
// per-host running statistics (mean + stddev), computes deviation scores,
// and generates alerts when risk_score exceeds thresholds.
//
// Features:
//   - Welford's online algorithm for incremental mean + variance
//   - Per-host learning phase (7 days + 100 samples) before alerting
//   - Global baseline for cold-start anomaly detection (dampened 5σ)
//   - Periodic checkpoint to MySQL for crash recovery
package baseline

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	// learningPeriod is the minimum duration before alerting on deviations.
	learningPeriod = 7 * 24 * time.Hour
	// minSamples is the minimum number of snapshots before baseline is valid.
	minSamples = 100
	// deviationThreshold is the number of standard deviations to trigger an alert.
	deviationThreshold = 3.0
	// coldStartThreshold is the deviation threshold for cold-start global baseline.
	coldStartThreshold = 5.0
	// checkpointInterval controls how often baselines are persisted to DB.
	checkpointInterval = 5 * time.Minute
	// MetricCount is the number of BDE metrics tracked.
	MetricCount = 13
	// NumTimeBuckets 时段分桶数(必须整除 24)。按 hour-of-day 分桶,叠加在扁平基线之上,
	// 让评估对比"同时段"的正常水位,消除夜间批处理等周期性负载的误报。默认 4 桶(每 6h)。
	NumTimeBuckets = 4
	// minBucketSamples 桶基线启用所需最小样本;不足则回退扁平基线(=分桶前行为)。
	minBucketSamples = 50
	// ewmaHalfLifeSamples EWMA 半衰期(快照数)。agent 每 60s 推一份快照 → 2880 ≈ 2 天。
	// 均值/方差改指数加权后，基线跟随业务常态漂移：稳态偏离在约 1 个半衰期内自然回落到
	// 阈值内，根治旧 Welford 等权聚合(样本量大后 delta/n→0)导致基线冻结、稳态偏离永不收敛。
	ewmaHalfLifeSamples = 2880
)

// ewmaAlpha 是 EWMA 平滑系数，由半衰期推得：alpha = 1 - 2^(-1/H)。
// var(非 const) 以便测试压缩半衰期加速收敛验证。
var ewmaAlpha = 1 - math.Pow(2, -1.0/float64(ewmaHalfLifeSamples))

// Phase constants for host baseline learning state.
const (
	PhaseLearning = "learning"
	PhaseActive   = "active"
)

// Metric indices (must match SnapshotToMetrics ordering).
const (
	MetricProcExecCount = iota
	MetricProcUniqueExe
	MetricProcForkRate
	MetricFileWriteCount
	MetricFileUniquePath
	MetricFileSensitiveHits
	MetricNetConnectCount
	MetricNetUniqueIP
	MetricNetUniquePort
	MetricNetExternalRatio
	MetricDNSQueryCount
	MetricDNSUniqueDomain
	MetricDNSNXRatio
)

// MetricNames maps metric index to human-readable name.
var MetricNames = [MetricCount]string{
	"proc_exec_count", "proc_unique_exe", "proc_fork_rate",
	"file_write_count", "file_unique_path", "file_sensitive_hits",
	"net_connect_count", "net_unique_ip", "net_unique_port", "net_external_ratio",
	"dns_query_count", "dns_unique_domain", "dns_nx_ratio",
}

// Dimension weight for risk_score calculation.
var metricWeights = [MetricCount]float64{
	0.8, 1.0, 1.2, // process
	0.6, 0.8, 1.5, // file (sensitive hits weighted higher)
	0.7, 1.0, 0.8, 1.3, // network (external ratio weighted higher)
	0.5, 0.8, 1.5, // DNS (NX ratio weighted higher)
}

// metricThresholdMult 各指标的偏离阈值倍率（叠加在基础 deviationThreshold 上）。
// 计数/速率型指标（proc_exec/fork_rate/net_connect/dns_query 等）重尾非高斯，3σ 的
// "0.3% 尾部"假设不成立 → 正常业务波动天天越界，抬高倍率减少误报；比率型([0,1] 有界)
// 与敏感指标(file_sensitive_hits)保持基础灵敏度。
var metricThresholdMult = [MetricCount]float64{
	1.7, 1.3, 1.7, // proc: exec_count / unique_exe / fork_rate
	1.5, 1.3, 1.0, // file: write_count / unique_path / sensitive_hits(敏感,保灵敏)
	1.7, 1.5, 1.5, 1.0, // net: connect_count / unique_ip / unique_port / external_ratio(比率)
	1.7, 1.5, 1.0, // dns: query_count / unique_domain / nx_ratio(比率)
}

// HostBaseline holds running statistics for a single host.
type HostBaseline struct {
	mu        sync.Mutex
	firstSeen time.Time
	samples   int
	phase     string // learning/active
	dirty     bool   // true if updated since last checkpoint
	// EWMA/EWMV 指数加权均值与方差（扁平基线，全时段聚合）。
	// variance 直接是指数加权方差，不再是 Welford 的 sum-of-squared-deviations。
	mean     [MetricCount]float64
	variance [MetricCount]float64
	// 时段分桶基线（叠加层）：按 hour-of-day 分桶各维 EWMA/EWMV 统计。
	// 桶样本足时评估用桶基线（同时段精准），不足回退扁平 mean/variance。
	bMean    [NumTimeBuckets][MetricCount]float64
	bVar     [NumTimeBuckets][MetricCount]float64
	bSamples [NumTimeBuckets]int
}

// ewmaUpdate 用指数加权递推更新单维 (mean, variance)：
//
//	delta = x - mean
//	mean += alpha * delta
//	variance = (1-alpha) * (variance + alpha * delta * delta)
//
// 相比 Welford 等权聚合，老样本按 (1-alpha) 指数衰减，基线随负载迁移自适应，
// 稳态偏离不再永久落在陈旧均值的 Nσ 外。
func ewmaUpdate(mean, variance *float64, x float64) {
	delta := x - *mean
	*mean += ewmaAlpha * delta
	*variance = (1 - ewmaAlpha) * (*variance + ewmaAlpha*delta*delta)
}

// timeBucket 把时刻映射到 [0,NumTimeBuckets) 的时段桶（按 hour-of-day 均分）。
func timeBucket(t time.Time) int {
	return t.Hour() / (24 / NumTimeBuckets)
}

// Update ingests a new metric vector and updates running statistics.
func (b *HostBaseline) Update(metrics [MetricCount]float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.samples == 0 {
		b.firstSeen = time.Now()
	}
	b.samples++
	b.dirty = true

	// 首样本用观测值播种 mean、variance=0；此后 EWMA 递推（老样本指数衰减）。
	for i := range MetricCount {
		if b.samples == 1 {
			b.mean[i] = metrics[i]
			b.variance[i] = 0
			continue
		}
		ewmaUpdate(&b.mean[i], &b.variance[i], metrics[i])
	}

	// 叠加更新当前时段桶（EWMA，独立于扁平基线）。
	bk := timeBucket(time.Now())
	if bk >= 0 && bk < NumTimeBuckets {
		b.bSamples[bk]++
		for i := range MetricCount {
			if b.bSamples[bk] == 1 {
				b.bMean[bk][i] = metrics[i]
				b.bVar[bk][i] = 0
				continue
			}
			ewmaUpdate(&b.bMean[bk][i], &b.bVar[bk][i], metrics[i])
		}
	}

	// Phase transition: learning → active.
	if b.phase == PhaseLearning && b.samples >= minSamples && time.Since(b.firstSeen) >= learningPeriod {
		b.phase = PhaseActive
	}
}

// statFor 返回评估某时段桶时第 i 维的 (mean, stddev)。
// 桶样本足(≥minBucketSamples)→ 用桶基线(同时段精准)；否则回退扁平基线(=分桶前行为)。
func (b *HostBaseline) statFor(bucket, i int) (mean, stddev float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bucket >= 0 && bucket < NumTimeBuckets && b.bSamples[bucket] >= minBucketSamples {
		mean = b.bMean[bucket][i]
		stddev = math.Sqrt(b.bVar[bucket][i])
		return
	}
	mean = b.mean[i]
	stddev = math.Sqrt(b.variance[i])
	return
}

// Stddev returns the standard deviation for metric i.
func (b *HostBaseline) Stddev(i int) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return math.Sqrt(b.variance[i])
}

// Mean returns the mean for metric i.
func (b *HostBaseline) Mean(i int) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mean[i]
}

// IsReady returns true if baseline has enough data for alerting.
func (b *HostBaseline) IsReady() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.phase == PhaseActive
}

// Deviation represents a metric that deviated beyond threshold.
type Deviation struct {
	Metric string  // metric name
	Value  float64 // observed value
	Mean   float64 // baseline mean
	Stddev float64 // baseline stddev
	ZScore float64 // (value - mean) / stddev
}

// EvalResult is the output of evaluating metrics against a baseline.
type EvalResult struct {
	HostID     string
	RiskScore  float64     // weighted aggregate deviation score (0-100)
	Deviations []Deviation // individual metric deviations
	ColdStart  bool        // true if evaluated against global baseline
}

// HostStatus exposes baseline learning progress for API queries.
type HostStatus struct {
	HostID       string               `json:"host_id"`
	Phase        string               `json:"phase"`
	Samples      int                  `json:"samples"`
	RequiredMin  int                  `json:"required_min"`
	FirstSeen    time.Time            `json:"first_seen"`
	LearningEnds time.Time            `json:"learning_ends"`
	ProgressPct  float64              `json:"progress_pct"` // 0-100
	Mean         [MetricCount]float64 `json:"mean"`
}

// Engine is the Server-side BDE baseline engine.
type Engine struct {
	mu        sync.RWMutex
	baselines map[string]*HostBaseline // hostID → baseline
	global    *HostBaseline            // cross-host aggregate baseline
	db        *gorm.DB                 // persistence layer (nil = memory-only)
	logger    *zap.Logger
	// tuning 各指标动态阈值倍率（反馈闭环 M1），由 StartTuningReload 周期从 bde_metric_tunings
	// 刷新的原子快照；evaluate 读之叠加在静态 metricThresholdMult 上。nil=全 1.0（无动态调整）。
	tuning atomic.Pointer[[MetricCount]float64]
}

// tuningMult 返回第 i 维当前动态阈值倍率（无快照/未调整时为 1.0）。
func (e *Engine) tuningMult(i int) float64 {
	snap := e.tuning.Load()
	if snap == nil {
		return 1.0
	}
	return snap[i]
}

// NewEngine creates a baseline engine. Pass db=nil for memory-only mode.
func NewEngine(db *gorm.DB, logger *zap.Logger) *Engine {
	e := &Engine{
		baselines: make(map[string]*HostBaseline),
		global:    &HostBaseline{phase: PhaseActive},
		db:        db,
		logger:    logger,
	}
	if db != nil {
		e.loadFromDB()
	}
	return e
}

// Ingest processes a behavior profile snapshot from an agent.
// Returns an EvalResult if deviations are found; nil otherwise.
// During learning phase, uses global baseline with dampened threshold for cold-start detection.
func (e *Engine) Ingest(hostID string, metrics [MetricCount]float64) *EvalResult {
	bl := e.getOrCreate(hostID)
	bl.Update(metrics)
	e.global.Update(metrics)

	if bl.IsReady() {
		return e.evaluate(hostID, bl, metrics, deviationThreshold, false)
	}

	// Cold-start: use global baseline with dampened threshold.
	if e.global.IsReady() {
		return e.evaluate(hostID, e.global, metrics, coldStartThreshold, true)
	}

	return nil
}

// evaluate computes deviations and risk_score for a set of metrics against a baseline.
func (e *Engine) evaluate(hostID string, bl *HostBaseline, metrics [MetricCount]float64, threshold float64, coldStart bool) *EvalResult {
	var deviations []Deviation
	var weightedSum float64
	var totalWeight float64

	// 按当前时段桶取基线(桶样本足用桶,否则回退扁平),消除周期性负载误报。
	bucket := timeBucket(time.Now())
	for i := range MetricCount {
		mean, sd := bl.statFor(bucket, i)
		if sd < 0.001 {
			continue
		}

		z := (metrics[i] - mean) / sd
		absZ := math.Abs(z)
		totalWeight += metricWeights[i]

		// per-metric 阈值：静态倍率(计数型重尾抬高) × 动态倍率(反馈闭环按 ignored 率自调)。
		if absZ > threshold*metricThresholdMult[i]*e.tuningMult(i) {
			deviations = append(deviations, Deviation{
				Metric: MetricNames[i],
				Value:  metrics[i],
				Mean:   mean,
				Stddev: sd,
				ZScore: z,
			})
			if absZ > 10 {
				absZ = 10
			}
			weightedSum += absZ * metricWeights[i]
		}
	}

	if len(deviations) == 0 {
		return nil
	}

	maxPossible := totalWeight * 10
	riskScore := 0.0
	if maxPossible > 0 {
		riskScore = (weightedSum / maxPossible) * 100
	}
	if riskScore > 100 {
		riskScore = 100
	}

	return &EvalResult{
		HostID:     hostID,
		RiskScore:  math.Round(riskScore*10) / 10,
		Deviations: deviations,
		ColdStart:  coldStart,
	}
}

func (e *Engine) getOrCreate(hostID string) *HostBaseline {
	e.mu.RLock()
	bl, ok := e.baselines[hostID]
	e.mu.RUnlock()
	if ok {
		return bl
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if bl, ok = e.baselines[hostID]; ok {
		return bl
	}
	bl = &HostBaseline{phase: PhaseLearning}
	e.baselines[hostID] = bl
	return bl
}

// Stats returns engine statistics.
func (e *Engine) Stats() (hosts, globalSamples int) {
	e.mu.RLock()
	hosts = len(e.baselines)
	e.mu.RUnlock()
	e.global.mu.Lock()
	globalSamples = e.global.samples
	e.global.mu.Unlock()
	return
}

// HostStatuses returns learning progress for all tracked hosts.
func (e *Engine) HostStatuses() []HostStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	statuses := make([]HostStatus, 0, len(e.baselines))
	for hostID, bl := range e.baselines {
		bl.mu.Lock()
		learningEnds := bl.firstSeen.Add(learningPeriod)
		samplePct := float64(bl.samples) / float64(minSamples) * 100
		timePct := 0.0
		if !bl.firstSeen.IsZero() {
			timePct = float64(time.Since(bl.firstSeen)) / float64(learningPeriod) * 100
		}
		progressPct := math.Min(samplePct, timePct)
		if progressPct > 100 {
			progressPct = 100
		}

		status := HostStatus{
			HostID:       hostID,
			Phase:        bl.phase,
			Samples:      bl.samples,
			RequiredMin:  minSamples,
			FirstSeen:    bl.firstSeen,
			LearningEnds: learningEnds,
			ProgressPct:  math.Round(progressPct*10) / 10,
			Mean:         bl.mean,
		}
		bl.mu.Unlock()
		statuses = append(statuses, status)
	}
	return statuses
}

// GlobalMean returns the global baseline mean for a metric.
func (e *Engine) GlobalMean(metric int) float64 {
	return e.global.Mean(metric)
}

// GlobalStddev returns the global baseline stddev for a metric.
func (e *Engine) GlobalStddev(metric int) float64 {
	return e.global.Stddev(metric)
}

// StartCheckpoint starts a background goroutine that periodically saves baselines to DB.
func (e *Engine) StartCheckpoint(done <-chan struct{}) {
	if e.db == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(checkpointInterval)
		defer ticker.Stop()
		e.sweepGraduations() // 启动即扫一次，毕业重启前已满足条件但无新快照的主机
		e.checkpoint()       // 立即落库，避免毕业结果等到首个 5 分钟 ticker 才持久化
		for {
			select {
			case <-done:
				e.checkpoint()
				return
			case <-ticker.C:
				e.sweepGraduations()
				e.checkpoint()
			}
		}
	}()
}

// sweepGraduations 定时把已满足毕业条件（samples≥minSamples 且 学习期已满）的学习中主机
// 转为 active。毕业转换原本仅在新快照到达时触发；主机停发快照（离线/低活跃）会导致
// 已达标主机永久停留在学习中。本扫描使毕业改为时间驱动，不再依赖增量事件。
func (e *Engine) sweepGraduations() {
	e.mu.RLock()
	baselines := make([]*HostBaseline, 0, len(e.baselines))
	for _, b := range e.baselines {
		baselines = append(baselines, b)
	}
	e.mu.RUnlock()

	now := time.Now()
	graduated := 0
	for _, b := range baselines {
		b.mu.Lock()
		if b.phase == PhaseLearning && b.samples >= minSamples && now.Sub(b.firstSeen) >= learningPeriod {
			b.phase = PhaseActive
			b.dirty = true
			graduated++
		}
		b.mu.Unlock()
	}
	if graduated > 0 {
		e.logger.Info("行为基线定时毕业", zap.Int("graduated", graduated))
	}
}
