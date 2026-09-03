// Package casework 实现安全事件的运营闭环：指派、认领、研判、升级、带原因关闭。
//
// 此前事件只有三个状态和一个 resolved_by（实际只会写 "auto"）：没有负责人、
// 没有响应时限、没有研判结论、关闭不需要理由。检测做得再准，产出的也只是一堆
// 越积越多、最后没人看的告警——发现问题的能力没有变成处理问题的能力。
//
// 本包不新建平行的 Case 表，而是把生命周期长在既有 Incident 上：关联逻辑、
// 风险聚合、成员告警都已经在那里，另起一张表只会产生两份互相不同步的事实。
package casework

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 响应时限。按严重级别区分——把 critical 和 low 放在同一时限下，
// 要么低危把人拖垮，要么高危被淹没。
var (
	ackSLA = map[string]time.Duration{
		"critical": 15 * time.Minute,
		"high":     1 * time.Hour,
		"medium":   4 * time.Hour,
		"low":      24 * time.Hour,
	}
	resolveSLA = map[string]time.Duration{
		"critical": 4 * time.Hour,
		"high":     24 * time.Hour,
		"medium":   72 * time.Hour,
		"low":      7 * 24 * time.Hour,
	}
)

// 未知级别按最宽处理：宁可少催，也不要因为级别拼写错误就把人叫醒。
const defaultAckSLA = 24 * time.Hour
const defaultResolveSLA = 7 * 24 * time.Hour

var (
	// ErrVerdictRequired 关闭事件必须给出研判结论。
	ErrVerdictRequired = errors.New("关闭事件必须给出研判结论（true_positive / false_positive / benign_true_positive）")
	// ErrCloseReasonRequired 关闭事件必须写明原因。
	ErrCloseReasonRequired = errors.New("关闭事件必须写明原因")
	// ErrNotFound 事件不存在。
	ErrNotFound = errors.New("事件不存在")
	// ErrAlreadyResolved 事件已关闭。
	ErrAlreadyResolved = errors.New("事件已关闭")
)

// validVerdicts 是允许的研判结论。
var validVerdicts = map[string]bool{
	model.VerdictTruePositive:       true,
	model.VerdictFalsePositive:      true,
	model.VerdictBenignTruePositive: true,
}

// Service 提供事件运营闭环操作。
type Service struct {
	db     *gorm.DB
	logger *zap.Logger
	now    func() time.Time
}

// NewService 构造服务。
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, logger: logger, now: time.Now}
}

// SLADeadlines 按严重级别算出认领与解决时限。
func SLADeadlines(severity string, from time.Time) (ackDue, resolveDue time.Time) {
	sev := strings.ToLower(strings.TrimSpace(severity))
	a, ok := ackSLA[sev]
	if !ok {
		a = defaultAckSLA
	}
	r, ok := resolveSLA[sev]
	if !ok {
		r = defaultResolveSLA
	}
	return from.Add(a), from.Add(r)
}

// Assign 指派负责人。
//
// 指派与认领分开记录：被指派不等于有人开始看，把两者混为一谈会让 MTTA 失真。
func (s *Service) Assign(incidentID, owner, actor string) error {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return errors.New("负责人不能为空")
	}
	return s.mutate(incidentID, func(inc *model.Incident) (map[string]any, model.IncidentEvent, error) {
		now := model.ToLocalTime(s.now())
		return map[string]any{
				"owner":       owner,
				"assigned_at": now,
				"assigned_by": actor,
			}, model.IncidentEvent{
				Type:  model.IncidentEventAssigned,
				Actor: actor,
				Body:  fmt.Sprintf("指派给 %s", owner),
			}, nil
	})
}

// Ack 认领事件，MTTA 的终点。
func (s *Service) Ack(incidentID, actor string) error {
	return s.mutate(incidentID, func(inc *model.Incident) (map[string]any, model.IncidentEvent, error) {
		if inc.AckedAt != nil {
			// 重复认领不报错但也不刷新时间：MTTA 该记第一个真正开始看的人。
			return nil, model.IncidentEvent{}, nil
		}
		now := model.ToLocalTime(s.now())
		updates := map[string]any{
			"acked_at": now,
			"acked_by": actor,
			"status":   model.IncidentStatusInvestigating,
		}
		// 无人认领的事件被谁认领，谁就默认成为负责人——避免"认领了但仍无人负责"。
		if strings.TrimSpace(inc.Owner) == "" {
			updates["owner"] = actor
			updates["assigned_at"] = now
			updates["assigned_by"] = actor
		}
		return updates, model.IncidentEvent{
			Type:  model.IncidentEventAcked,
			Actor: actor,
			Body:  "已认领，开始调查",
		}, nil
	})
}

// Comment 追加研判备注或证据。
func (s *Service) Comment(incidentID, actor, body, ref string) error {
	if strings.TrimSpace(body) == "" {
		return errors.New("备注内容不能为空")
	}
	typ := model.IncidentEventComment
	if strings.TrimSpace(ref) != "" {
		typ = model.IncidentEventEvidence
	}
	return s.mutate(incidentID, func(*model.Incident) (map[string]any, model.IncidentEvent, error) {
		return nil, model.IncidentEvent{Type: typ, Actor: actor, Body: body, Ref: ref}, nil
	})
}

// Escalate 升级事件。必须写明升级对象与原因，否则"已升级"无从追溯。
func (s *Service) Escalate(incidentID, to, reason, actor string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("升级对象不能为空")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("升级必须写明原因")
	}
	return s.mutate(incidentID, func(*model.Incident) (map[string]any, model.IncidentEvent, error) {
		now := model.ToLocalTime(s.now())
		return map[string]any{
				"escalated":    true,
				"escalated_at": now,
				"escalated_to": to,
			}, model.IncidentEvent{
				Type:  model.IncidentEventEscalated,
				Actor: actor,
				Body:  fmt.Sprintf("升级至 %s：%s", to, reason),
			}, nil
	})
}

// Resolve 关闭事件。**必须给出研判结论与原因。**
//
// 原实现只翻状态：关闭不需要任何理由，resolved_by 实际只会是 "auto"。
// 于是无法回答两个最基本的问题——这条到底是不是真的威胁、当时为什么关掉它。
// 前者是检测质量的唯一可信来源（precision 只能由结论算出，拿 resolved 数量代替
// 会把"没人看所以批量关掉"算成检测准确），后者是复盘的前提。
func (s *Service) Resolve(incidentID, verdict, reason, actor string) error {
	verdict = strings.TrimSpace(verdict)
	if !validVerdicts[verdict] {
		return ErrVerdictRequired
	}
	if strings.TrimSpace(reason) == "" {
		return ErrCloseReasonRequired
	}
	return s.mutate(incidentID, func(*model.Incident) (map[string]any, model.IncidentEvent, error) {
		now := model.ToLocalTime(s.now())
		return map[string]any{
				"status":         model.IncidentStatusResolved,
				"verdict":        verdict,
				"verdict_reason": reason,
				"close_reason":   reason,
				"resolved_at":    now,
				"resolved_by":    actor,
			}, model.IncidentEvent{
				Type:  model.IncidentEventResolved,
				Actor: actor,
				Body:  fmt.Sprintf("结论 %s：%s", verdict, reason),
			}, nil
	})
}

// Timeline 返回事件的完整时间线，供复盘查看"谁在什么时候基于什么做了什么"。
func (s *Service) Timeline(incidentID string) ([]model.IncidentEvent, error) {
	var events []model.IncidentEvent
	err := s.db.Where("incident_id = ?", incidentID).
		Order("created_at ASC, id ASC").Find(&events).Error
	return events, err
}

// mutate 在同一事务里更新事件并追加一条时间线记录。
//
// 两者必须同事务：状态变了却没有记录，等于事后无法解释这个决定是谁做的。
func (s *Service) mutate(
	incidentID string,
	fn func(*model.Incident) (map[string]any, model.IncidentEvent, error),
) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var inc model.Incident
		if err := tx.Where("incident_id = ?", incidentID).First(&inc).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if inc.Status == model.IncidentStatusResolved {
			return ErrAlreadyResolved
		}

		updates, event, err := fn(&inc)
		if err != nil {
			return err
		}
		if len(updates) > 0 {
			if err := tx.Model(&model.Incident{}).
				Where("incident_id = ?", incidentID).Updates(updates).Error; err != nil {
				return err
			}
		}
		if event.Type == "" {
			return nil
		}
		event.IncidentID = incidentID
		event.TenantID = inc.TenantID
		if strings.TrimSpace(event.Actor) == "" {
			event.Actor = "unknown"
		}
		return tx.Create(&event).Error
	})
}
