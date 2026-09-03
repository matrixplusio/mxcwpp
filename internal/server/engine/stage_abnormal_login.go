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
	// 本地会话不是登录。sudo 每执行一条命令、cron 每分钟起一次任务，PAM 都会打
	// 一行 "session opened"，量比真实登录高几个数量级。喂进画像的后果是主机靠
	// 这些噪声凑够样本毕业、时段分布被 cron 填平，真正的异常登录反而淹掉。
	if isLocalPAMSession(logMsg) {
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

// localPAMServices 是会打 "session opened" 但不代表一次登录的 PAM 服务。
// sudo / su 的提权由 priv_escalation 覆盖，cron 与 systemd 用户会话是系统自身行为。
var localPAMServices = []string{"(cron:", "(sudo:", "(su:", "(systemd-user:", "(runuser:"}

func isLocalPAMSession(logMsg string) bool {
	for _, svc := range localPAMServices {
		if containsStr(logMsg, svc) {
			return true
		}
	}
	return false
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
