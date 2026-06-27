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
)

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

// HostBaseline holds running statistics for a single host.
type HostBaseline struct {
	mu        sync.Mutex
	firstSeen time.Time
	samples   int
	phase     string // learning/active
	dirty     bool   // true if updated since last checkpoint
	// Welford's online algorithm for mean and variance（扁平基线，全时段聚合）。
	mean [MetricCount]float64
	m2   [MetricCount]float64 // sum of squared deviations
	// 时段分桶基线（叠加层）：按 hour-of-day 分桶各维 Welford 统计。
	// 桶样本足时评估用桶基线（同时段精准），不足回退扁平 mean/m2。
	bMean    [NumTimeBuckets][MetricCount]float64
	bM2      [NumTimeBuckets][MetricCount]float64
	bSamples [NumTimeBuckets]int
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
	n := float64(b.samples)

	for i := range MetricCount {
		delta := metrics[i] - b.mean[i]
		b.mean[i] += delta / n
		delta2 := metrics[i] - b.mean[i]
		b.m2[i] += delta * delta2
	}

	// 叠加更新当前时段桶（Welford，独立于扁平基线）。
	bk := timeBucket(time.Now())
	if bk >= 0 && bk < NumTimeBuckets {
		b.bSamples[bk]++
		bn := float64(b.bSamples[bk])
		for i := range MetricCount {
			delta := metrics[i] - b.bMean[bk][i]
			b.bMean[bk][i] += delta / bn
			delta2 := metrics[i] - b.bMean[bk][i]
			b.bM2[bk][i] += delta * delta2
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
		if b.bSamples[bucket] >= 2 {
			stddev = math.Sqrt(b.bM2[bucket][i] / float64(b.bSamples[bucket]-1))
		}
		return
	}
	mean = b.mean[i]
	if b.samples >= 2 {
		stddev = math.Sqrt(b.m2[i] / float64(b.samples-1))
	}
	return
}

// Stddev returns the standard deviation for metric i.
func (b *HostBaseline) Stddev(i int) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.samples < 2 {
		return 0
	}
	return math.Sqrt(b.m2[i] / float64(b.samples-1))
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

		if absZ > threshold {
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
		for {
			select {
			case <-done:
				e.checkpoint()
				return
			case <-ticker.C:
				e.checkpoint()
			}
		}
	}()
}
