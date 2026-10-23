package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
)

// PersistenceFileDropRuleID 是「往 cron / systemd 目录落文件」的规则 ID。
const PersistenceFileDropRuleID = "PERSISTENCE_FILE_DROP"

// RootkitStage Rootkit/后门检测。
type RootkitStage struct {
	detector *intrusion.RootkitDetector
	logger   *zap.Logger
}

// NewRootkitStage 构造。
func NewRootkitStage(d *intrusion.RootkitDetector, logger *zap.Logger) *RootkitStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if d == nil {
		d = intrusion.NewRootkitDetector()
	}
	return &RootkitStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *RootkitStage) Name() string { return "intrusion_rootkit" }

// Process 处理多种事件类型 (process_exec / file_create / kernel_module_load)。
func (s *RootkitStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}

	// 探测内容: 文件路径 / kernel module 名 / 进程 cmdline。
	//
	// 按事件本身是什么来定，不按「cmdline 是不是空的」来猜：文件事件现在会被补上
	// 发起进程的命令行，照旧先看 cmdline 的话，文件事件会被当成进程事件，
	// 被改的路径反而不再参与判断。
	var content, source string
	switch {
	case fields["file_path"] != "":
		content, source = fields["file_path"], intrusion.SourceFile
	case fields["module_name"] != "":
		content, source = fields["module_name"], intrusion.SourceKernelModule
	default:
		content, source = fields["cmdline"], intrusion.SourceProcess
	}
	if content == "" {
		return nil, nil
	}

	ie := intrusion.IndicatorEvent{
		HostID:  ev.HostID,
		Source:  source,
		Content: content,
		UID:     atoi32(fields["uid"]),
		// 必须带上执行体：detector 靠它排除包管理器写 systemd 单元 / cron
		// 这类常规行为。不传的话排除逻辑形同虚设，每次装包都会报持久化后门。
		ExePath: fields["exe"],
	}
	payload, categories, hit := s.detector.ScanDetail(ctx, ie)
	if !hit {
		return nil, nil
	}
	// 只落了 cron / systemd 文件的命中单独成一条规则。并在同一条规则下的话，
	// 一台主机先有一条开着的持久化告警，之后真出现内核模块命中也只会并进去、不再升级。
	ruleID, severity := "ROOTKIT_BACKDOOR", "critical"
	if intrusion.PersistenceOnly(categories) {
		ruleID, severity = PersistenceFileDropRuleID, "high"
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-rootkit-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         ruleID,
			Severity:       severity,
			ATTCKTactic:    "TA0003", // Persistence (含 LKM rootkit 持久化)
			ATTCKTechnique: "T1547",  // Boot or Logon Autostart Execution
			Payload:        payload,
			WouldAction:    payload,
		},
	}, nil
}

// atoi32 是 stage_rootkit 用的私有 helper。
func atoi32(s string) int32 {
	var n int32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int32(c-'0')
	}
	return n
}

var _ Stage = (*RootkitStage)(nil)
