package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/engine/intrusion"
)

// BruteForceStage 接入入侵检测六件套之"暴力破解"。
//
// 仅处理 syslog / journal_watcher 类事件 (DataType 6010-6019 预留)。
// 命中阈值后产 Alert,其中 would_action 含 ip_block 建议。
type BruteForceStage struct {
	detector *intrusion.BruteForceDetector
	logger   *zap.Logger
}

// NewBruteForceStage 构造。
func NewBruteForceStage(d *intrusion.BruteForceDetector, logger *zap.Logger) *BruteForceStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &BruteForceStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *BruteForceStage) Name() string { return "intrusion_brute_force" }

// Process 解析 sshd 失败登录事件并喂给 detector。
func (s *BruteForceStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	att := intrusion.ParseSSHFailedFromFields(ev.HostID, fields)
	if att == nil {
		return nil, nil
	}

	payload, hit := s.detector.Ingest(ctx, *att)
	if !hit {
		return nil, nil
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-brute-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "BRUTE_FORCE_SSH",
			Severity:       "high",
			ATTCKTactic:    "TA0006",    // Credential Access
			ATTCKTechnique: "T1110.001", // Brute Force: Password Guessing
			Payload:        payload,
			WouldAction:    payload, // observe 模式直接复用
			Action:         payload, // protect 模式需 mode.Resolver 决策时填
		},
	}, nil
}

var _ Stage = (*BruteForceStage)(nil)
