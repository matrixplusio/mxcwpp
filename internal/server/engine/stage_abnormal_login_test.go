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
	return PipelineEvent{HostID: "h1", DataType: DataTypeAuthEvent, Payload: b}
}

// Stage 必须把用户 / 源 IP / 国家透传给 detector。
//
// 少传任何一维，那一维在真实链路里永远命中不了：detector 单测照样过，
// 线上却只剩下"凌晨登录"一条规则在起作用。
func TestAbnormalLoginStage_PassesLoginFieldsToDetector(t *testing.T) {
	st := NewAbnormalLoginStage(graduatedDetector(), zap.NewNop())

	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"event_type": "auth_login_success",
		"username":   "root",
		"source_ip":  "203.0.113.9",
		"country":    "RU",
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
		"event_type": "auth_login_success",
		"username":   "deploy",
		"source_ip":  "10.0.0.5",
		"country":    "CN",
	}))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("画像内的日常登录不该告警，实际 %d 条", len(alerts))
	}
}

// 只有「登录成功」进检测。登录失败、sudo、会话开始这些喂进去会污染画像：
// sudo 与 cron 的量比真实登录高几个数量级，主机会靠这些噪声凑够样本毕业。
func TestAbnormalLoginStage_OnlyTakesLoginSuccess(t *testing.T) {
	d := graduatedDetector()
	st := NewAbnormalLoginStage(d, zap.NewNop())
	before := d.Stats()

	for _, kind := range []string{"auth_login_failed", "auth_preauth_close", "auth_sudo", "auth_su_success", "auth_session_open", ""} {
		alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
			"event_type": kind, "username": "root", "source_ip": "203.0.113.9", "country": "RU",
		}))
		if err != nil {
			t.Fatalf("Process(%q): %v", kind, err)
		}
		if len(alerts) != 0 {
			t.Errorf("%q 不该走异常登录检测", kind)
		}
	}
	if after := d.Stats(); after != before {
		t.Errorf("非登录成功的事件不该进画像: before=%+v after=%+v", before, after)
	}
}

// 日志原文不再参与判断：别的数据类型里出现一行长得像成功登录的内容，不算登录。
func TestAbnormalLoginStage_IgnoresOtherDataTypesAndRawText(t *testing.T) {
	st := NewAbnormalLoginStage(graduatedDetector(), zap.NewNop())
	b, _ := json.Marshal(map[string]string{
		"event_type": "auth_login_success", "username": "root", "source_ip": "203.0.113.9", "country": "RU",
	})
	if alerts, _ := st.Process(context.Background(), PipelineEvent{HostID: "h1", DataType: 3000, Payload: b}); len(alerts) != 0 {
		t.Error("非认证事件不该被当成登录")
	}
	alerts, _ := st.Process(context.Background(), loginEvent(map[string]string{
		"event_type": "auth_login_failed", "username": "root", "source_ip": "203.0.113.9",
		"raw": "Accepted password for root from 203.0.113.9 port 22 ssh2", "log_msg": "Accepted password for root",
	}))
	if len(alerts) != 0 {
		t.Error("原文里出现 Accepted 不该被当成登录成功")
	}
}

// detector 为 nil 时 Stage 安全 no-op（未配 DB 的部署会走到这里）。
func TestAbnormalLoginStage_NilDetectorIsNoop(t *testing.T) {
	st := NewAbnormalLoginStage(nil, zap.NewNop())
	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"event_type": "auth_login_success", "source_ip": "203.0.113.9",
	}))
	if err != nil || len(alerts) != 0 {
		t.Fatalf("nil detector 应安全跳过, alerts=%d err=%v", len(alerts), err)
	}
}

// 暴力破解阶段：失败累计到阈值报一条；同一来源随后登录成功，再报「爆破后登录成功」。
func TestBruteForceStage_BruteThenSuccess(t *testing.T) {
	// 不传检测器也要能工作：入口一直传的是 nil，此前这个 Stage 因此一条都不处理。
	st := NewBruteForceStage(nil, zap.NewNop())

	alerts, err := st.Process(context.Background(), loginEvent(map[string]string{
		"event_type": "auth_login_failed", "username": "root", "source_ip": "203.0.113.9", "count": "30",
	}))
	if err != nil || len(alerts) != 1 || alerts[0].RuleID != "BRUTE_FORCE_SSH" || alerts[0].Severity != "high" {
		t.Fatalf("应报暴力破解：%+v err=%v", alerts, err)
	}

	alerts, err = st.Process(context.Background(), loginEvent(map[string]string{
		"event_type": "auth_login_success", "username": "root", "source_ip": "203.0.113.9",
	}))
	if err != nil || len(alerts) != 1 || alerts[0].RuleID != BruteForceSuccessRuleID {
		t.Fatalf("应报爆破后登录成功：%+v err=%v", alerts, err)
	}

	// 正常登录、别的事件类型、别的数据类型都不产告警。
	quiet := []PipelineEvent{
		loginEvent(map[string]string{"event_type": "auth_login_success", "username": "deploy", "source_ip": "10.0.0.5"}),
		loginEvent(map[string]string{"event_type": "auth_sudo", "username": "deploy"}),
	}
	b, _ := json.Marshal(map[string]string{"event_type": "auth_login_failed", "source_ip": "203.0.113.9", "count": "99"})
	quiet = append(quiet, PipelineEvent{HostID: "h1", DataType: 3000, Payload: b})
	for i, ev := range quiet {
		if alerts, _ := st.Process(context.Background(), ev); len(alerts) != 0 {
			t.Errorf("第 %d 个事件不该产告警：%+v", i, alerts)
		}
	}
}
