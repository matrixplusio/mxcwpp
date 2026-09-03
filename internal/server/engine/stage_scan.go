package engine

import (
	"context"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
)

// ScanStage 入站端口扫描聚合检测：对 tcp_accept(入站)网络事件按"源 IP × 时间窗 × 去重端口"
// 聚合判定扫描，替代旧"单入站连接即告警"的 network_scan 规则（每次合法连接刷屏）。
// 尊重 alert_whitelists 的合法扫描源白名单（k8s/GKE 探测等）。
//
// 此前 ScanDetector 已实现但从未装配进 Pipeline（死代码）；本 stage 将其接入运行路径。
type ScanStage struct {
	detector *celengine.ScanDetector
	logger   *zap.Logger
}

// NewScanStage 构造
func NewScanStage(d *celengine.ScanDetector, logger *zap.Logger) *ScanStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ScanStage{detector: d, logger: logger}
}

// Name 返回 stage 名
func (s *ScanStage) Name() string { return "scan" }

// Process 对入站 tcp_accept 事件做扫描聚合检测（命中由 detector 内部落告警，本 stage 无返回）。
func (s *ScanStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil || ev.HostID == "" {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	if !shouldCheckScan(fields) {
		return nil, nil
	}
	s.detector.CheckIncomingConnection(ev.HostID, fields["remote_addr"], fields["local_port"], fields)
	return nil, nil
}

// shouldCheckScan 判断事件是否应走入站扫描检测：
// 仅入站连接参与（出站不是被扫描）；方向缺失(旧内核降级)时以 event_type=tcp_accept 兜底。
func shouldCheckScan(fields map[string]string) bool {
	return fields["direction"] == "inbound" || fields["event_type"] == "tcp_accept"
}

var _ Stage = (*ScanStage)(nil)
