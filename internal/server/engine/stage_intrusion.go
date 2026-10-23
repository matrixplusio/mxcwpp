package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
)

// DataTypeAuthEvent 主机认证事件（登录、sudo、su、账号变更），由认证日志插件上报。
const DataTypeAuthEvent int32 = 3020

// BruteForceStage 接入入侵检测六件套之"暴力破解"。
//
// 只处理认证事件里的登录成功与失败。失败累计到阈值报暴力破解；
// 同一来源在大量失败之后登录成功，另报一条「爆破后登录成功」。
type BruteForceStage struct {
	detector *intrusion.BruteForceDetector
	logger   *zap.Logger
}

// NewBruteForceStage 构造。
func NewBruteForceStage(d *intrusion.BruteForceDetector, logger *zap.Logger) *BruteForceStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	// 与其它入侵检测 Stage 一致：不传就用默认检测器。此前这里原样接受 nil，
	// 而入口传的正是 nil——就算有输入，这个 Stage 也一条都不会处理。
	if d == nil {
		d = intrusion.NewBruteForceDetector(0, 0)
	}
	return &BruteForceStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *BruteForceStage) Name() string { return "intrusion_brute_force" }

// Process 把登录事件喂给 detector。
func (s *BruteForceStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil || ev.DataType != DataTypeAuthEvent {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	att := intrusion.ParseLoginAttempt(ev.HostID, fields)
	if att == nil {
		return nil, nil
	}

	res := s.detector.Ingest(ctx, *att)
	var alerts []Alert
	if res.BruteForce != nil {
		alerts = append(alerts, Alert{
			AlertID:        fmt.Sprintf("alrt-brute-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "BRUTE_FORCE_SSH",
			Severity:       "high",
			ATTCKTactic:    "TA0006",    // Credential Access
			ATTCKTechnique: "T1110.001", // Brute Force: Password Guessing
			Payload:        res.BruteForce,
			WouldAction:    res.BruteForce, // observe 模式直接复用
			Action:         res.BruteForce, // protect 模式需 mode.Resolver 决策时填
		})
	}
	if res.SuccessAfterFailures != nil {
		alerts = append(alerts, Alert{
			AlertID: fmt.Sprintf("alrt-brute-ok-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:  BruteForceSuccessRuleID,
			// 声明为 critical：爆破得手就是失陷。实际落成什么级别由 critical 准入决定，
			// 新规则不在准入清单里，先以 high 出现，用数据证明自己之后再由人放开。
			Severity:       "critical",
			ATTCKTactic:    "TA0001", // Initial Access
			ATTCKTechnique: "T1078",  // Valid Accounts
			Payload:        res.SuccessAfterFailures,
			WouldAction:    res.SuccessAfterFailures,
		})
	}
	return alerts, nil
}

// BruteForceSuccessRuleID 「爆破后登录成功」的规则 ID。
const BruteForceSuccessRuleID = "BRUTE_FORCE_SUCCESS"

var _ Stage = (*BruteForceStage)(nil)
