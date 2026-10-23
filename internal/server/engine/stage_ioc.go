package engine

import (
	"context"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
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

	// 已确认攻击源连入：先于通用匹配判断，不受"入站情报命中是背景噪声"那条抑制的影响。
	if addr := fields["remote_addr"]; addr != "" && shouldCheckScan(fields) && s.matcher.CheckConfirmedIP(addr) {
		s.alertGen.GenerateFromConfirmedSource(ev.HostID, addr, fields)
		return iocHit(celengine.ConfirmedSourceRuleID, "critical", "TA0001"), nil
	}
	// 已确认攻击源登录或尝试登录本机。认证事件的来源在 source_ip 里，不走上面的 remote_addr。
	if ev.DataType == DataTypeAuthEvent {
		if addr := fields["source_ip"]; addr != "" && isLoginEvent(fields["event_type"]) && s.matcher.CheckConfirmedIP(addr) {
			s.alertGen.GenerateFromConfirmedSource(ev.HostID, addr, fields)
			return iocHit(celengine.ConfirmedSourceRuleID, "critical", "TA0001"), nil
		}
		return nil, nil
	}
	// 外联 IP(网络事件)
	if addr := fields["remote_addr"]; addr != "" && s.matcher.CheckIP(addr) {
		s.alertGen.GenerateFromIOC(ev.HostID, "ip", addr, fields)
		// 入站命中是公网服务被情报库里的地址扫描，不是本机外联 C2（告警路径同样不产生）。
		// 计进风险会让每台公网主机长期挂着一个高危的「命令与控制」战术。
		// 方向字段在旧内核的降级采集里会缺失，与扫描检测一样按连接类型兜底。
		if shouldCheckScan(fields) {
			return nil, nil
		}
		return iocHit("ioc-ip", "high", "TA0011"), nil
	}
	// 进程可执行文件 hash
	if h := fields["exe_hash"]; h != "" && s.matcher.CheckHash(h) {
		s.alertGen.GenerateFromIOC(ev.HostID, "hash", h, fields)
		return iocHit("ioc-hash", "critical", "TA0002"), nil
	}
	// URL(DNS/HTTP 等携带)
	if u := fields["url"]; u != "" && s.matcher.CheckURL(u) {
		s.alertGen.GenerateFromIOC(ev.HostID, "url", u, fields)
		return iocHit("ioc-url", "high", "TA0011"), nil
	}
	return nil, nil
}

// iocHit 把情报命中也交给流水线：告警已由 AlertGenerator 落库（流水线对自行落库的阶段不再写），
// 返回它是为了让风险累积与信号看得到——情报命中是最强的外联与初始访问信号，缺了它们，
// 组合判断的分值会系统性偏低。
func iocHit(ruleID, severity, tactic string) []Alert {
	return []Alert{{RuleID: ruleID, Severity: severity, ATTCKTactic: tactic, RuleName: ruleID}}
}

func isLoginEvent(eventType string) bool {
	return eventType == intrusion.AuthEventLoginSuccess || eventType == intrusion.AuthEventLoginFailed
}

var _ Stage = (*IOCStage)(nil)

// PersistsOwnAlerts 表明本 Stage 通过 AlertGenerator 自行把告警写进 alerts 表，
// 流水线不应再统一落库一次，否则同一次命中会在界面上出现两条。
func (s *IOCStage) PersistsOwnAlerts() bool { return s.alertGen != nil }
