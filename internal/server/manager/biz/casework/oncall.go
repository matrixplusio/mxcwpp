package casework

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ErrNoOncall 当前时段该层级无人值班。
var ErrNoOncall = errors.New("当前时段无人值班")

// CurrentOncall 返回指定层级当前的值班人。
//
// 同一时段配了多人时取最早开始的那位：值班要有唯一归属，
// "大家都在班"等于"没人负责"。
func (s *Service) CurrentOncall(tier string) (string, error) {
	now := model.ToLocalTime(s.now())
	var shift model.OncallShift
	err := s.db.Where("tier = ? AND starts_at <= ? AND ends_at > ?", tier, now, now).
		Order("starts_at ASC").First(&shift).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", ErrNoOncall
	}
	if err != nil {
		return "", err
	}
	return shift.Username, nil
}

// AutoAssign 把事件指派给当前一线值班人。
//
// 新事件默认无人负责，超时告警只会天天响而没人知道该找谁。自动派单让"有人负责"
// 成为默认状态，而不是需要有人记得去点一下。
//
// 无人值班时不报错、也不静默跳过，而是留下一条时间线记录：排班有缺口本身
// 就是运维要知道的事，把它藏起来只会让事件一直无主。
func (s *Service) AutoAssign(incidentID string) error {
	owner, err := s.CurrentOncall(model.OncallTierL1)
	if errors.Is(err, ErrNoOncall) {
		return s.mutate(incidentID, func(*model.Incident) (map[string]any, model.IncidentEvent, error) {
			return nil, model.IncidentEvent{
				Type:  model.IncidentEventComment,
				Actor: "system",
				Body:  "自动派单失败：当前时段一线无人值班，本事件暂无负责人",
			}, nil
		})
	}
	if err != nil {
		return err
	}
	return s.Assign(incidentID, owner, "system")
}

// EscalateToNextTier 把事件升级到下一层值班人。
//
// 与手工 Escalate 的区别是升级对象由值班表算出：让人在半夜三点自己填"升级给谁"
// 是行不通的。已在最高层时明确报错，而不是假装升级成功。
func (s *Service) EscalateToNextTier(incidentID, fromTier, reason, actor string) error {
	next := model.NextTier(strings.ToLower(strings.TrimSpace(fromTier)))
	if next == "" {
		return fmt.Errorf("%s 已是最高层级，无法继续升级", fromTier)
	}
	to, err := s.CurrentOncall(next)
	if errors.Is(err, ErrNoOncall) {
		return fmt.Errorf("%s 层当前无人值班，无法升级", next)
	}
	if err != nil {
		return err
	}
	return s.Escalate(incidentID, to, reason, actor)
}

// ListShifts 返回指定时间窗内的排班，供值班表页面展示。
func (s *Service) ListShifts(from, to time.Time) ([]model.OncallShift, error) {
	var shifts []model.OncallShift
	err := s.db.Where("ends_at > ? AND starts_at < ?",
		model.ToLocalTime(from), model.ToLocalTime(to)).
		Order("starts_at ASC, tier ASC").Find(&shifts).Error
	return shifts, err
}

// SaveShift 新增或更新一条排班。
func (s *Service) SaveShift(shift *model.OncallShift) error {
	if strings.TrimSpace(shift.Username) == "" {
		return errors.New("值班人不能为空")
	}
	if shift.Tier == "" {
		return errors.New("值班层级不能为空")
	}
	if !shift.EndsAt.Time().After(shift.StartsAt.Time()) {
		// 结束早于开始的排班永远匹配不到人，等于这段时间没人值班却看起来排了。
		return errors.New("值班结束时间必须晚于开始时间")
	}
	return s.db.Save(shift).Error
}
