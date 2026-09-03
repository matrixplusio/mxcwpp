package casework

import (
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

var (
	// ErrNotApproved 未经审批的动作不得执行。
	ErrNotApproved = errors.New("处置动作未经审批，不得执行")
	// ErrSelfApproval 申请人不能审批自己的申请。
	ErrSelfApproval = errors.New("不能审批自己提交的处置申请")
	// ErrAlreadyDecided 该申请已审批或已驳回。
	ErrAlreadyDecided = errors.New("该处置申请已有审批结论")
	// ErrNotExecuted 未执行的动作无从回滚。
	ErrNotExecuted = errors.New("该动作尚未执行，无需回滚")
	// ErrAutoResponseForbidden 系统不得自动执行处置。
	ErrAutoResponseForbidden = errors.New("处置动作必须由人发起并经审批，系统不得自动执行")
)

// systemActors 是不允许发起处置申请的身份。
//
// 硬禁自动处置不能只靠"目前没有自动路径"——那是碰巧成立，不是设计保证。
// 把系统身份挡在申请入口，将来任何自动化想调用处置都会在这里失败，
// 而不是悄悄执行成功。
var systemActors = map[string]bool{
	"":          true,
	"system":    true,
	"auto":      true,
	"scheduler": true,
	"unknown":   true,
}

// Executor 执行具体处置动作。由调用方注入，便于测试与替换实现。
type Executor interface {
	Execute(action *model.ResponseAction) (result string, err error)
	Rollback(action *model.ResponseAction) error
}

// RequestResponse 提交一次处置申请。
//
// 幂等：同一 IdempotencyKey 重复提交返回已存在的申请，不会产生第二次执行。
// 处置动作重复执行的后果不对称——多隔离一次可能切断本已恢复的业务，
// 所以幂等靠数据库唯一索引兜底，而不只是提交前查一次。
func (s *Service) RequestResponse(req *model.ResponseAction) (*model.ResponseAction, error) {
	if systemActors[strings.ToLower(strings.TrimSpace(req.RequestedBy))] {
		return nil, ErrAutoResponseForbidden
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		return nil, errors.New("缺少幂等键")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, errors.New("处置申请必须写明理由")
	}
	if strings.TrimSpace(req.Target) == "" {
		return nil, errors.New("处置目标不能为空")
	}

	var existing model.ResponseAction
	err := s.db.Where("idempotency_key = ?", req.IdempotencyKey).First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	req.Status = model.ResponseStatusPending
	req.RequestedAt = model.ToLocalTime(s.now())
	if err := s.db.Create(req).Error; err != nil {
		// 并发提交时唯一索引会挡住第二条，回读已存在的那条即可。
		var raced model.ResponseAction
		if e := s.db.Where("idempotency_key = ?", req.IdempotencyKey).First(&raced).Error; e == nil {
			return &raced, nil
		}
		return nil, err
	}
	s.recordResponseEvidence(s.db, req, fmt.Sprintf("申请处置 %s（目标 %s）：%s",
		req.Action, req.Target, req.Reason), req.RequestedBy)
	return req, nil
}

// ApproveResponse 审批通过。
//
// 审批人不得是申请人：处置是不可逆或代价高昂的操作，让同一个人既提又批，
// 审批就只是多点一次鼠标。
func (s *Service) ApproveResponse(id uint, approver string) error {
	return s.decide(id, approver, true, "")
}

// RejectResponse 驳回申请。驳回必须写明原因，否则申请人不知道该改什么。
func (s *Service) RejectResponse(id uint, approver, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("驳回必须写明原因")
	}
	return s.decide(id, approver, false, reason)
}

func (s *Service) decide(id uint, approver string, approve bool, rejectReason string) error {
	if systemActors[strings.ToLower(strings.TrimSpace(approver))] {
		return ErrAutoResponseForbidden
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var act model.ResponseAction
		if err := tx.First(&act, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if act.Status != model.ResponseStatusPending {
			return ErrAlreadyDecided
		}
		if strings.EqualFold(act.RequestedBy, approver) {
			return ErrSelfApproval
		}

		now := model.ToLocalTime(s.now())
		updates := map[string]any{"approved_by": approver, "approved_at": now}
		body := ""
		if approve {
			updates["status"] = model.ResponseStatusApproved
			body = fmt.Sprintf("审批通过处置 %s（目标 %s）", act.Action, act.Target)
		} else {
			updates["status"] = model.ResponseStatusRejected
			updates["reject_reason"] = rejectReason
			body = fmt.Sprintf("驳回处置 %s：%s", act.Action, rejectReason)
		}
		if err := tx.Model(&model.ResponseAction{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		s.recordResponseEvidence(tx, &act, body, approver)
		return nil
	})
}

// ExecuteResponse 执行已审批的处置。
//
// 未审批一律拒绝——这是硬禁自动处置的落点：任何执行路径都必须先拿到审批，
// 不存在"内部调用可以跳过"的旁路。
func (s *Service) ExecuteResponse(id uint, exec Executor) error {
	var act model.ResponseAction
	if err := s.db.First(&act, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	if act.Status == model.ResponseStatusExecuted {
		// 幂等：已执行过就不再执行，重复执行的代价不对称。
		return nil
	}
	if !act.Executable() {
		return ErrNotApproved
	}

	result, err := exec.Execute(&act)
	now := model.ToLocalTime(s.now())
	if err != nil {
		// 失败必须与"未执行"区分：前者要人去查为什么没生效，后者只是还没轮到。
		s.db.Model(&model.ResponseAction{}).Where("id = ?", id).Updates(map[string]any{
			"status":      model.ResponseStatusFailed,
			"error_msg":   err.Error(),
			"executed_at": now,
		})
		s.recordResponseEvidence(s.db, &act, fmt.Sprintf("处置 %s 执行失败：%v", act.Action, err), act.ApprovedBy)
		return err
	}

	s.db.Model(&model.ResponseAction{}).Where("id = ?", id).Updates(map[string]any{
		"status":      model.ResponseStatusExecuted,
		"result":      result,
		"executed_at": now,
	})
	s.recordResponseEvidence(s.db, &act, fmt.Sprintf("处置 %s 已执行（目标 %s）：%s",
		act.Action, act.Target, result), act.ApprovedBy)
	return nil
}

// RollbackResponse 回滚已执行的处置。
func (s *Service) RollbackResponse(id uint, actor string, exec Executor) error {
	var act model.ResponseAction
	if err := s.db.First(&act, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	if act.Status != model.ResponseStatusExecuted {
		return ErrNotExecuted
	}
	if err := exec.Rollback(&act); err != nil {
		return err
	}
	now := model.ToLocalTime(s.now())
	if err := s.db.Model(&model.ResponseAction{}).Where("id = ?", id).Updates(map[string]any{
		"status":         model.ResponseStatusRolledBack,
		"rolled_back_at": now,
		"rolled_back_by": actor,
	}).Error; err != nil {
		return err
	}
	s.recordResponseEvidence(s.db, &act, fmt.Sprintf("已回滚处置 %s（目标 %s）", act.Action, act.Target), actor)
	return nil
}

// recordResponseEvidence 把处置过程写回事件时间线。
//
// 处置本身就是事件调查的一部分：复盘要能顺着一条时间线看到"发现→研判→申请→审批→执行"，
// 而不是去另一个页面拼。未关联事件的处置只记在自己表里。
// tx 必须传入当前事务的句柄：在事务里用事务外的连接写库，
// 单连接下会等一把永远不会释放的锁而死锁——这不只是测试现象，生产同样会卡住。
func (s *Service) recordResponseEvidence(tx *gorm.DB, act *model.ResponseAction, body, actor string) {
	if strings.TrimSpace(act.IncidentID) == "" {
		return
	}
	if actor == "" {
		actor = "unknown"
	}
	ev := model.IncidentEvent{
		IncidentID: act.IncidentID,
		TenantID:   act.TenantID,
		Type:       model.IncidentEventEvidence,
		Actor:      actor,
		Body:       body,
		Ref:        act.IdempotencyKey,
	}
	if err := tx.Create(&ev).Error; err != nil {
		s.logger.Warn("处置证据写入事件时间线失败",
			zap.String("incident_id", act.IncidentID), zap.Error(err))
	}
}
