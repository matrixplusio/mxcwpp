package engine

import (
	"context"
	"strconv"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"
)

// AnomalyStage 接入 anomaly.Detector (IForest 异常检测)。
//
// 把 host_metrics 类事件喂给 Detector.Ingest, Detector 内部累积训练 +
// 触发告警 (异步写 anomaly_alerts 表 + 通过自有通道告警),
// 因此 Stage.Process 返回空 Alert 数组。
//
// 后续 PR 可改造 Detector 暴露 Alert chan,
// 让 Pipeline 也能拿到异常告警走统一 Producer 链路。
type AnomalyStage struct {
	detector *anomaly.Detector
	logger   *zap.Logger
}

// NewAnomalyStage 构造 anomaly stage。
func NewAnomalyStage(d *anomaly.Detector, logger *zap.Logger) *AnomalyStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AnomalyStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *AnomalyStage) Name() string { return "anomaly" }

// Process 把 ev 喂给 anomaly.Detector。仅处理 host_metrics 类事件。
func (s *AnomalyStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil || ev.HostID == "" {
		return nil, nil
	}
	// 只处理 host_metrics 类 (DataType 1000-1099 心跳 / 5050-5060 资产指标)
	if ev.DataType < 1000 || ev.DataType > 5099 {
		return nil, nil
	}

	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}

	// 把已知 13 维 metrics 字段提取为 float64 切片
	metricKeys := []string{
		"cpu_usage", "mem_usage", "disk_usage", "net_in", "net_out",
		"load_1", "load_5", "load_15",
		"process_count", "fd_count", "syscall_rate",
		"net_conns", "tcp_estab",
	}
	metrics := make([]float64, len(metricKeys))
	for i, k := range metricKeys {
		v, _ := strconv.ParseFloat(fields[k], 64)
		metrics[i] = v
	}

	hostname := fields["hostname"]
	s.detector.Ingest(ev.HostID, hostname, metrics)
	return nil, nil
}

var _ Stage = (*AnomalyStage)(nil)
