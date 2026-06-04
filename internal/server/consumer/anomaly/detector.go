package anomaly

import (
	"context"
	"fmt"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// MetricNames maps metric indices to names (matching BDE profiler output).
var MetricNames = [featureCount]string{
	"proc_exec_count", "proc_unique_exe", "proc_fork_rate",
	"file_write_count", "file_unique_path", "file_sensitive_hits",
	"net_connect_count", "net_unique_ip", "net_unique_port", "net_external_ratio",
	"dns_query_count", "dns_unique_domain", "dns_nx_ratio",
}

// Correlation patterns: multi-metric signatures that indicate specific attack types.
var correlationPatterns = []correlationPattern{
	{
		Name:        "c2_beacon",
		Description: "Possible C2 beaconing: high network + DNS activity with process execution",
		Indices:     []int{0, 6, 7, 10, 11}, // proc_exec, net_connect, net_unique_ip, dns_query, dns_unique_domain
		MinActive:   3,                      // at least 3 of 5 metrics elevated
		Severity:    "critical",
	},
	{
		Name:        "data_exfiltration",
		Description: "Possible data exfiltration: file access + external network",
		Indices:     []int{3, 4, 6, 9}, // file_write, file_unique_path, net_connect, net_external_ratio
		MinActive:   3,
		Severity:    "high",
	},
	{
		Name:        "privilege_escalation",
		Description: "Possible privilege escalation: sensitive file access + process forking",
		Indices:     []int{0, 2, 5}, // proc_exec, proc_fork_rate, file_sensitive_hits
		MinActive:   2,
		Severity:    "high",
	},
	{
		Name:        "reconnaissance",
		Description: "Possible reconnaissance: port scanning + DNS enumeration",
		Indices:     []int{6, 8, 10, 12}, // net_connect, net_unique_port, dns_query, dns_nx_ratio
		MinActive:   3,
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

	// sampleWindowSize is the max number of recent samples kept for training.
	sampleWindowSize = 2000

	// anomalyThreshold is the score above which a sample is flagged.
	anomalyThreshold = 0.65

	// correlationThreshold is z-score threshold for a metric to be "elevated".
	correlationThreshold = 2.0

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

	mu           sync.Mutex
	sampleBuffer [][]float64          // recent samples for training
	hostMeans    map[string][]float64 // per-host running mean for z-score
	hostCounts   map[string]int       // sample count per host
}

// NewDetector creates a new anomaly detection engine.
// chConn 用于告警生成时回查 ebpf_events 拿攻击链 IOC；可为 nil（ClickHouse 未启用时降级，
// 告警仍生成但 trigger_context 只含 metric_snapshot/elevated_metrics）。
func NewDetector(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) *Detector {
	return &Detector{
		logger:     logger,
		db:         db,
		chConn:     chConn,
		forest:     NewIForest(),
		hostMeans:  make(map[string][]float64),
		hostCounts: make(map[string]int),
	}
}

// StartRetrain begins periodic retraining in the background.
// Call after Consumer startup.
func (d *Detector) StartRetrain(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(retrainInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				d.retrain()
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
	// Add to sample buffer.
	d.sampleBuffer = append(d.sampleBuffer, metrics)
	if len(d.sampleBuffer) > sampleWindowSize {
		d.sampleBuffer = d.sampleBuffer[len(d.sampleBuffer)-sampleWindowSize:]
	}

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
		if score >= anomalyThreshold {
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
	return len(d.sampleBuffer)
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
	data := make([][]float64, len(d.sampleBuffer))
	copy(data, d.sampleBuffer)
	d.mu.Unlock()

	if len(data) < 64 {
		d.logger.Debug("insufficient samples for IForest training",
			zap.Int("samples", len(data)))
		return
	}

	d.forest.Train(data)
	d.logger.Info("IForest retrained",
		zap.Int("samples", len(data)),
		zap.Bool("trained", d.forest.Trained()))
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

	severity := "medium"
	if score >= 0.80 {
		severity = "critical"
	} else if score >= 0.70 {
		severity = "high"
	}

	// 拼描述：让 UI drawer 至少有一行有意义内容，避免 v-if 空白
	description := fmt.Sprintf("Isolation Forest 异常评分 %.2f（>=0.6 触发告警）", score)
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

	if err := d.db.Create(&alert).Error; err != nil {
		d.logger.Error("failed to save anomaly alert", zap.Error(err))
	}

	d.logger.Warn("IForest anomaly detected",
		zap.String("host_id", hostID),
		zap.Float64("score", score),
		zap.String("top_metric", topMetric),
		zap.String("severity", severity))
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
	for _, pattern := range correlationPatterns {
		elevatedCount := 0
		elevated := make([]model.ElevatedMetric, 0, len(pattern.Indices))
		for _, idx := range pattern.Indices {
			if mean[idx] == 0 {
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
		d.enrichTriggerContext(&trigger, pattern.Name, hostID, windowStart, now)

		alert := model.AnomalyAlert{
			HostID:         hostID,
			Hostname:       hostname,
			AlertType:      "correlation",
			PatternName:    pattern.Name,
			Severity:       pattern.Severity,
			AnomalyScore:   float64(elevatedCount) / float64(len(pattern.Indices)),
			Description:    pattern.Description,
			TriggerContext: trigger,
			Status:         "open",
		}

		if err := d.db.Create(&alert).Error; err != nil {
			d.logger.Error("failed to save correlation alert", zap.Error(err))
		}

		d.logger.Warn("correlation pattern detected",
			zap.String("host_id", hostID),
			zap.String("pattern", pattern.Name),
			zap.Int("elevated_metrics", elevatedCount),
			zap.String("severity", pattern.Severity),
			zap.Int("suspicious_ips", len(trigger.SuspiciousIPs)),
			zap.Int("suspicious_domains", len(trigger.SuspiciousDomains)),
			zap.Int("sensitive_files", len(trigger.SensitiveFiles)),
		)
	}
}

// enrichTriggerContext 根据 pattern 类型回查 ebpf_events 拿 IOC。
// 失败不返回错误，只是 trigger_context 对应字段为空（已记日志）。
//
// 查询都走 proj_time_desc projection + (host_id, timestamp) 过滤，P99 < 200ms。
// 整体硬上限 enrichQueryTimeout=3s，避免单次告警拖累 BDE 主流程。
func (d *Detector) enrichTriggerContext(trigger *model.AnomalyTriggerContext, patternName, hostID string, start, end time.Time) {
	if d.chConn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), enrichQueryTimeout)
	defer cancel()

	switch patternName {
	case "c2_beacon":
		trigger.SuspiciousIPs = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('tcp_connect','udp_send') AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
		trigger.SuspiciousDomains = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type = 'dns_query' AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
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
		trigger.ScannedPorts = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_port FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type IN ('tcp_connect','udp_send') AND remote_port != '' GROUP BY remote_port ORDER BY count() DESC LIMIT ?")
		trigger.SuspiciousDomains = d.queryTopStrings(ctx, hostID, start, end,
			"SELECT remote_addr FROM ebpf_events WHERE host_id = ? AND timestamp >= ? AND timestamp <= ? AND event_type = 'dns_query' AND remote_addr != '' GROUP BY remote_addr ORDER BY count() DESC LIMIT ?")
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
