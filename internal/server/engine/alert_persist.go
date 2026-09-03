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

	detail := w.marshalPayload(a)
	resultID := stageAlertResultID(ruleID, hostID)
	now := model.ToLocalTime(time.Now())

	var existing model.Alert
	err := w.db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		return w.refresh(&existing, now, detail)
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("查询告警失败: %w", err)
	}

	alert := model.Alert{
		ResultID:       resultID,
		HostID:         hostID,
		RuleID:         ruleID,
		Source:         model.AlertSourceDetection,
		Severity:       a.Severity,
		Category:       stage,
		ATTCKTactic:    a.ATTCKTactic,
		ATTCKTechnique: a.ATTCKTechnique,
		Title:          alertTitle(stage, ruleID),
		Actual:         detail,
		Status:         model.AlertStatusActive,
		HitCount:       1,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
	if err := w.db.Create(&alert).Error; err != nil {
		// 并发竞争：另一 worker 在 SELECT 与 INSERT 之间插入了同 result_id。
		// 转更新路径，避免丢命中计数并消除 duplicate key 噪声（与 CEL 落库同处理）。
		var raced model.Alert
		if e := w.db.Where("result_id = ?", resultID).First(&raced).Error; e == nil {
			return w.refresh(&raced, now, detail)
		}
		return fmt.Errorf("写入 alerts 表失败: %w", err)
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
func (w *StageAlertWriter) refresh(existing *model.Alert, now model.LocalTime, detail string) error {
	updates := map[string]any{
		"last_seen_at": now,
		"hit_count":    gorm.Expr("hit_count + 1"),
		"actual":       detail,
	}
	// 已被人处置过的告警重新命中要回到活跃态，否则复发会被旧的处置状态盖住。
	if existing.Status == model.AlertStatusResolved {
		updates["status"] = model.AlertStatusActive
	}
	if err := w.db.Model(&model.Alert{}).Where("id = ?", existing.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("刷新告警失败: %w", err)
	}
	return nil
}

// marshalPayload 序列化告警详情，写库前做凭据脱敏。
//
// Payload 是 Stage 自行编码的 JSON。解不成 map[string]string 时（嵌套结构等）
// 原样保留：脱敏不了就不脱敏，但绝不因此把详情丢掉——没有详情的告警无法研判。
func (w *StageAlertWriter) marshalPayload(a Alert) string {
	if len(a.Payload) == 0 {
		return "{}"
	}
	var fields map[string]string
	if err := json.Unmarshal(a.Payload, &fields); err != nil {
		return string(a.Payload)
	}
	sanitize.Fields(fields)
	b, err := json.Marshal(fields)
	if err != nil {
		return string(a.Payload)
	}
	return string(b)
}

// alertTitle 给硬编码规则一个可读标题。
func alertTitle(stage, ruleID string) string {
	return fmt.Sprintf("%s: %s", stage, ruleID)
}
