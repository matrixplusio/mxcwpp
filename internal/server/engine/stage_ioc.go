package engine

import (
	"context"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
)

// IOCStage 服务端威胁情报匹配:网络事件的外联 IP、进程 hash、URL 对 IOC 集匹配。
// 事件本就全量流到 engine,匹配放服务端,不依赖给 agent 下发 IOC。
type IOCStage struct {
	matcher  *celengine.IOCMatcher
	alertGen *celengine.AlertGenerator
	logger   *zap.Logger
}

// NewIOCStage 构造
func NewIOCStage(m *celengine.IOCMatcher, g *celengine.AlertGenerator, logger *zap.Logger) *IOCStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &IOCStage{matcher: m, alertGen: g, logger: logger}
}

// Name 返回 stage 名
func (s *IOCStage) Name() string { return "ioc" }

// Process 对事件做 IOC 匹配,命中生成 ioc_hit 告警
func (s *IOCStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.matcher == nil || s.alertGen == nil || ev.HostID == "" {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}

	// 外联 IP(网络事件)
	if addr := fields["remote_addr"]; addr != "" && s.matcher.CheckIP(addr) {
		s.alertGen.GenerateFromIOC(ev.HostID, "ip", addr, fields)
		return nil, nil
	}
	// 进程可执行文件 hash
	if h := fields["exe_hash"]; h != "" && s.matcher.CheckHash(h) {
		s.alertGen.GenerateFromIOC(ev.HostID, "hash", h, fields)
		return nil, nil
	}
	// URL(DNS/HTTP 等携带)
	if u := fields["url"]; u != "" && s.matcher.CheckURL(u) {
		s.alertGen.GenerateFromIOC(ev.HostID, "url", u, fields)
	}
	return nil, nil
}

var _ Stage = (*IOCStage)(nil)
