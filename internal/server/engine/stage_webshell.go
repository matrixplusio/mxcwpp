package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/engine/intrusion"
)

// WebshellStage 检测文件落地/修改事件中的 Web 后门启发式特征。
type WebshellStage struct {
	detector *intrusion.WebshellDetector
	logger   *zap.Logger
}

// NewWebshellStage 构造。
func NewWebshellStage(d *intrusion.WebshellDetector, logger *zap.Logger) *WebshellStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	if d == nil {
		d = intrusion.NewWebshellDetector()
	}
	return &WebshellStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *WebshellStage) Name() string { return "intrusion_webshell" }

// Process 处理 FIM 文件事件 (DataType 6001 FIM)。
func (s *WebshellStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	if ev.DataType < 6001 || ev.DataType > 6019 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	fe := intrusion.FileSampleEvent{
		HostID:   ev.HostID,
		FilePath: fields["file_path"],
		Content:  fields["content"], // 前 4KB,Agent 端只对 web 目录文件采样
		Action:   fields["action"],
	}
	payload, hit := s.detector.Scan(ctx, fe)
	if !hit {
		return nil, nil
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-webshell-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "WEBSHELL_HEURISTIC",
			Severity:       "critical",
			ATTCKTactic:    "TA0003",    // Persistence
			ATTCKTechnique: "T1505.003", // Server Software Component: Web Shell
			Payload:        payload,
			WouldAction:    payload,
		},
	}, nil
}

var _ Stage = (*WebshellStage)(nil)
