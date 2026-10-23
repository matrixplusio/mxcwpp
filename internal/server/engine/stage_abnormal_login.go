package engine

import (
	"context"
	"fmt"

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

// Process 处理认证事件里的登录成功。
func (s *AbnormalLoginStage) Process(ctx context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil || ev.DataType != DataTypeAuthEvent {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	// 只认主机侧解析出的「登录成功」。sudo、cron 的本地会话不是登录，插件不会报成这一类；
	// 把它们喂进画像的后果是主机靠这些噪声凑够样本毕业、时段分布被 cron 填平，
	// 真正的异常登录反而淹掉。
	att := intrusion.ParseLoginAttempt(ev.HostID, fields)
	if att == nil || !att.Success {
		return nil, nil
	}

	login := intrusion.SuccessfulLogin{
		HostID:    ev.HostID,
		Username:  att.Username,
		SourceIP:  att.SourceIP,
		Country:   fields["country"],
		Timestamp: att.Timestamp,
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
