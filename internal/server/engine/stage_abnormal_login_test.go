package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
)

// graduatedDetector 返回一个 h1 已走完学习期的检测器，画像里是日常运维形态。
func graduatedDetector() *intrusion.AbnormalLoginDetector {
	d := intrusion.NewAbnormalLoginDetector()
	base := time.Now().Add(-30 * 24 * time.Hour)
	for i := 0; i < intrusion.DefaultLearningMinSamples; i++ {
		d.Ingest(context.Background(), intrusion.SuccessfulLogin{
			HostID: "h1", Username: "deploy", SourceIP: "10.0.0.5", Country: "CN",
			Timestamp: base.Add(time.Duration(i) * 24 * time.Hour),
		})
	}
	return d
}

func loginEvent(fields map[string]string) PipelineEvent {
	b, _ := json.Marshal(fields)
	return PipelineEvent{HostID: "h1", DataType: 1003, Payload: b}
}

// Stage 必须把用户 / 源 IP / 国家透传给 detector。
//
// 少传任何一维，那一维在真实链路里永远命中不了：detector 单测照样过，
// 线上却只剩下"凌晨登录"一条规则在起作用。
func TestAbnormalLoginStage_PassesLoginFieldsToDetector(t *testing.T) {
	st := NewAbnormalLoginStage(graduatedDetector(), zap.NewNop())

	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"log_msg":   "Accepted password for root from 203.0.113.9 port 51234 ssh2",
		"username":  "root",
		"source_ip": "203.0.113.9",
		"country":   "RU",
	}))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("陌生用户 + 陌生网段 + 陌生国家的登录应产 1 条告警，实际 %d 条——"+
			"字段没透传时这些维度在链路里等于不存在", len(alerts))
	}
	if alerts[0].RuleID != "ABNORMAL_LOGIN" {
		t.Errorf("RuleID = %s, want ABNORMAL_LOGIN", alerts[0].RuleID)
	}
	if len(alerts[0].Payload) == 0 {
		t.Error("告警 payload 为空，界面上看不到命中了哪一维")
	}
}

// 日常运维登录不产告警。
func TestAbnormalLoginStage_BenignLoginIsSilent(t *testing.T) {
	st := NewAbnormalLoginStage(graduatedDetector(), zap.NewNop())

	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"log_msg":   "Accepted publickey for deploy from 10.0.0.5 port 40122 ssh2",
		"username":  "deploy",
		"source_ip": "10.0.0.5",
		"country":   "CN",
	}))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("画像内的日常登录不该告警，实际 %d 条", len(alerts))
	}
}

// 登录失败与无关日志不进检测——喂进去会污染画像。
func TestAbnormalLoginStage_IgnoresNonSuccessfulLogins(t *testing.T) {
	st := NewAbnormalLoginStage(graduatedDetector(), zap.NewNop())

	for _, msg := range []string{
		"Failed password for root from 203.0.113.9 port 51234 ssh2",
		"Connection closed by authenticating user root 203.0.113.9 port 51234",
		"pam_unix(cron:session): session closed for user root",
	} {
		alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
			"log_msg": msg, "username": "root", "source_ip": "203.0.113.9", "country": "RU",
		}))
		if err != nil {
			t.Fatalf("Process(%q): %v", msg, err)
		}
		if len(alerts) != 0 {
			t.Errorf("非成功登录不该走异常登录检测: %q", msg)
		}
	}
}

// 本地 PAM 会话不算登录：sudo / cron 的量比真实登录高几个数量级，
// 喂进画像会让主机靠噪声毕业、时段分布被填平。
func TestAbnormalLoginStage_IgnoresLocalPAMSessions(t *testing.T) {
	d := graduatedDetector()
	st := NewAbnormalLoginStage(d, zap.NewNop())
	before := d.Stats()

	for _, msg := range []string{
		"pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1000)",
		"pam_unix(cron:session): session opened for user root(uid=0)",
		"pam_unix(su:session): session opened for user postgres(uid=26) by deploy(uid=1000)",
		"pam_unix(systemd-user:session): session opened for user deploy(uid=1000)",
	} {
		alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
			"log_msg": msg, "username": "root",
		}))
		if err != nil {
			t.Fatalf("Process(%q): %v", msg, err)
		}
		if len(alerts) != 0 {
			t.Errorf("本地会话不该产异常登录告警: %q", msg)
		}
	}

	if after := d.Stats(); after != before {
		t.Errorf("本地会话不该进画像: before=%+v after=%+v", before, after)
	}
}

// 真实 SSH 登录仍然照收——上面的过滤不能把 sshd 的 PAM 行一起挡掉。
func TestAbnormalLoginStage_KeepsSSHDSessionOpened(t *testing.T) {
	st := NewAbnormalLoginStage(graduatedDetector(), zap.NewNop())

	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"log_msg":   "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
		"username":  "root",
		"source_ip": "203.0.113.9",
		"country":   "RU",
	}))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("sshd 的 session opened 是真实登录，应产 1 条告警，实际 %d 条", len(alerts))
	}
}

// detector 为 nil 时 Stage 安全 no-op（未配 DB 的部署会走到这里）。
func TestAbnormalLoginStage_NilDetectorIsNoop(t *testing.T) {
	st := NewAbnormalLoginStage(nil, zap.NewNop())
	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"log_msg": "Accepted password for root from 203.0.113.9 port 22 ssh2",
	}))
	if err != nil || len(alerts) != 0 {
		t.Fatalf("nil detector 应安全跳过, alerts=%d err=%v", len(alerts), err)
	}
}
