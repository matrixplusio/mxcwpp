package alertbus

import (
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/consumer/siem"
)

// NewSIEMEgress 由 SIEM 配置构造外发出口，未启用时返回 nil。
//
// 三个进程（engine / consumer / manager）共用本构造函数：外发接线若各写一套，
// 迟早会出现"某个进程的告警没导出去"而无人察觉——正是本项目反复出现的分叉。
//
// 底层 Forwarder.SendAlert 是同步的：持锁写 socket、写超时 5 秒。直接挂在检测
// 热路径上，一个不可达的 SIEM 就能拖住整条流水线，因此统一包成有界异步队列。
func NewSIEMEgress(logger *zap.Logger, enabled bool, protocol, address string, facility int, queueSize int) (Egress, func()) {
	fwd := siem.NewForwarder(logger, siem.Config{
		Enabled:  enabled,
		Protocol: protocol,
		Address:  address,
		Facility: facility,
	})
	if fwd == nil {
		return nil, func() {}
	}
	async := NewAsyncEgress(logger, queueSize, func(e Event) {
		fwd.SendAlert(siem.AlertEvent{
			EventID:  "alert",
			Name:     e.Title,
			Severity: e.Severity,
			HostID:   e.HostID,
			Hostname: e.Hostname,
			SourceIP: e.IP,
			RuleID:   e.RefID,
			Extra: map[string]string{
				"source":      e.Source,
				"category":    string(e.Category),
				"description": e.Description,
				"ref_table":   e.RefTable,
			},
		})
	})
	logger.Info("SIEM 外发出口已接线",
		zap.String("address", address),
		zap.String("protocol", protocol))
	return async, func() {
		async.Close()
		fwd.Close()
	}
}
