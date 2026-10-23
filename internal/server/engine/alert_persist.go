package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// StageAlertWriter 把没有自带落库能力的 Stage 产出的告警写进 alerts 表。
//
// 为什么需要它：流水线里所有 Stage 都把告警发往 mxcwpp.engine.alert，而该 topic
// 没有任何消费者。CEL / Sequence / IOC 之所以能出现在界面上，是因为它们额外挂了
// AlertGenerator 自行落库；Privilege / RASP / AntiRootkit 没挂，于是检测在跑、
// 告警在发、界面上永远看不到——能力清单里把这一档标作 dead_end。
//
// 不复用 AlertGenerator 是刻意的：它与 CEL 深度耦合（数字 rule.ID、cel-%d 结果键、
// 依赖规则字段的低保真与观察期判定）。给这些 Stage 合成假的 DetectionRule 能让编译
// 通过，但会把硬编码检测伪装成 CEL 规则，也会误用那套只对 CEL 有意义的治理语义——
// 那是换一种方式撒谎。
type StageAlertWriter struct {
	db  *gorm.DB
	log *zap.Logger
	// criticalGate 决定规则的告警能否落成 critical。为空时不限制。
	criticalGate *celengine.CriticalGate
}

// SetCriticalGate 注入 critical 准入判断。须在开始处理事件之前设置。
func (w *StageAlertWriter) SetCriticalGate(gate *celengine.CriticalGate) {
	if w != nil {
		w.criticalGate = gate
	}
}

// NewStageAlertWriter 构造告警落库器。db 为 nil 时返回 nil，调用方按"未启用"处理。
func NewStageAlertWriter(db *gorm.DB, logger *zap.Logger) *StageAlertWriter {
	if db == nil {
		return nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &StageAlertWriter{db: db, log: logger}
}

// stageAlertResultID 是告警在 alerts 表中的稳定身份。
//
// 与 CEL 的 cel-{ruleID}-{hostID} 同构：不含时间戳，因此同一主机上同一规则的重复命中
// 会累加 hit_count 而不是刷出无数行。前缀 engine- 区别于 cel-，避免两套来源撞键。
func stageAlertResultID(ruleID, hostID string) string {
	return fmt.Sprintf("engine-%s-%s", ruleID, hostID)
}

// Persist 落库一条 Stage 告警。已存在则刷新最后命中时间与计数。
func (w *StageAlertWriter) Persist(stage string, ev PipelineEvent, a Alert) error {
	if w == nil {
		return nil
	}
	hostID := ev.HostID
	if hostID == "" {
		hostID = ev.AgentID
	}
	ruleID := strings.TrimSpace(a.RuleID)
	if hostID == "" || ruleID == "" {
		// 缺少身份维度就无法稳定去重，写进去只会不断堆积重复行。
		return fmt.Errorf("stage %s 告警缺少 host_id 或 rule_id，拒绝落库", stage)
	}

	// 被压过级的要留痕，否则看不出这条规则本来声明的是 critical。
	var capNote string
	if capped := w.criticalGate.Cap(ruleID, a.Severity); capped != a.Severity {
		capNote = fmt.Sprintf("规则声明的级别为 %s；未获 critical 准入，按 %s 落库。", a.Severity, capped)
		a.Severity = capped
	}
	detail := w.marshalPayload(a)
	// 描述取检测阶段自己给的一句话说明（谁、从哪、做了什么）。只有标题的告警，
	// 值班的人得点开原始数据才知道来源是谁。
	desc := strings.TrimSpace(payloadReason(a.Payload) + " " + capNote)
	groupKey := stageAlertResultID(ruleID, hostID)
	now := model.ToLocalTime(time.Now())

	created, err := model.UpsertGroupedAlert(w.db, groupKey, func() model.Alert {
		return model.Alert{
			HostID:         hostID,
			RuleID:         ruleID,
			Source:         model.AlertSourceDetection,
			Severity:       a.Severity,
			Category:       stage,
			ATTCKTactic:    a.ATTCKTactic,
			ATTCKTechnique: a.ATTCKTechnique,
			Title:          alertTitle(stage, ruleID),
			Description:    desc,
			Actual:         detail,
			Status:         model.AlertStatusActive,
			HitCount:       1,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		}
	}, func(existing *model.Alert) error {
		return w.refresh(existing, now, detail, desc)
	})
	if err != nil {
		return err
	}
	if created == nil {
		return nil
	}
	w.log.Info("Stage 检测告警已落库",
		zap.String("stage", stage),
		zap.String("rule_id", ruleID),
		zap.String("host_id", hostID),
		zap.String("severity", a.Severity))
	w.egress(stage, ruleID, hostID, a, detail)
	return nil
}

// egress 把告警交给外发出口（客户自有 SIEM）。
//
// EgressOnly：alerts 表这条链路的通知由 AgentCenter 内联与 Manager 定时器负责，
// 此处只负责让客户 SIEM 收到记录，不重复通知。
func (w *StageAlertWriter) egress(stage, ruleID, hostID string, a Alert, detail string) {
	alertbus.Publish(alertbus.Event{
		Category:    model.NotifyCategoryDetection,
		Source:      stage,
		HostID:      hostID,
		Severity:    a.Severity,
		Title:       alertTitle(stage, ruleID),
		Description: detail,
		DedupKey:    stageAlertResultID(ruleID, hostID),
		RefTable:    "alerts",
		RefID:       stageAlertResultID(ruleID, hostID),
		EgressOnly:  true,
	})
}

// refresh 刷新已有告警的最后命中时间与累计次数。
func (w *StageAlertWriter) refresh(existing *model.Alert, now model.LocalTime, detail, desc string) error {
	updates := map[string]any{
		"last_seen_at": now,
		"hit_count":    gorm.Expr("hit_count + 1"),
		"actual":       detail,
	}
	// 描述跟着最近一次命中走：同一台主机上换了一个来源在爆破，描述里不能还是第一个来源。
	if desc != "" {
		updates["description"] = desc
	}
	// 只有仍开着的告警会走到这里：关闭过的告警不再改写，复发由分组生成新告警。
	if err := w.db.Model(&model.Alert{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("刷新告警失败: %w", err)
	}
	return nil
}

// marshalPayload 序列化告警详情，写库前做凭据脱敏。
//
// Payload 是 Stage 自行编码的 JSON，常带数字、数组、嵌套的 would_action：按任意 JSON 递归处理，
// 否则入侵检测类告警（rootkit 的 content、反弹 shell 的 cmdline）会原样落库。
// 不是合法 JSON 时原样保留：脱敏不了就不脱敏，但绝不因此把详情丢掉——没有详情的告警无法研判。
func (w *StageAlertWriter) marshalPayload(a Alert) string {
	if len(a.Payload) == 0 {
		return "{}"
	}
	b, _ := sanitize.JSON(a.Payload)
	return string(b)
}

// payloadReason 从检测阶段的负载里取出一句话说明：would_action.reason。没有就返回空。
// 内容里有来自主机的字段（来源地址、账号名），截断后再用。
func payloadReason(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var p struct {
		WouldAction struct {
			Reason string `json:"reason"`
		} `json:"would_action"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	r := []rune(strings.TrimSpace(p.WouldAction.Reason))
	if len(r) > 300 {
		r = r[:300]
	}
	return string(r)
}

// alertTitle 给硬编码规则一个可读标题。
func alertTitle(stage, ruleID string) string {
	return fmt.Sprintf("%s: %s", stage, ruleID)
}
