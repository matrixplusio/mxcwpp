package engine

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
)

// AbnormalLoginStage 异常登录检测 (地理 / 时间 / IP / 用户 四维)。
type AbnormalLoginStage struct {
	detector *intrusion.AbnormalLoginDetector
	logger   *zap.Logger
}

// NewAbnormalLoginStage 构造。
func NewAbnormalLoginStage(d *intrusion.AbnormalLoginDetector, logger *zap.Logger) *AbnormalLoginStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AbnormalLoginStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *AbnormalLoginStage) Name() string { return "intrusion_abnormal_login" }

// Process 处理 sshd "Accepted password" 等成功登录事件。
func (s *AbnormalLoginStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	logMsg := fields["log_msg"]
	if logMsg == "" {
		return nil, nil
	}
	// 仅处理成功登录
	if !containsStr(logMsg, "Accepted") && !containsStr(logMsg, "session opened") {
		return nil, nil
	}

	login := intrusion.SuccessfulLogin{
		HostID:    ev.HostID,
		Username:  fields["username"],
		SourceIP:  fields["source_ip"],
		Country:   fields["country"],
		Timestamp: time.Now(),
	}
	payload, hit := s.detector.Ingest(ctx, login)
	if !hit {
		return nil, nil
	}
	return []Alert{
		{
			AlertID:        fmt.Sprintf("alrt-abn-login-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
			RuleID:         "ABNORMAL_LOGIN",
			Severity:       "medium",
			ATTCKTactic:    "TA0001", // Initial Access
			ATTCKTechnique: "T1078",  // Valid Accounts
			Payload:        payload,
			WouldAction:    payload,
		},
	}, nil
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ Stage = (*AbnormalLoginStage)(nil)
