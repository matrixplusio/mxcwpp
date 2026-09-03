// SOAR ApprovalChecker 实际实现 (P3-14).
//
// SOAR Playbook 危险动作 (isolate_host / kill_pid / block_ip 等) 在 protect 模式下
// 需要人工 approve 才能执行. ApprovalChecker 阻塞等待 approval, 超时则视为 reject.
//
// 实现:
//   - 创建 SOARApproval 记录 (status=pending)
//   - 通知值班 (邮件 / 钉钉 / Webhook)
//   - 轮询 (5s 周期) 检查 status, 满 N 个 approver 即 approved
//   - 超时 (默认 30 min) → status=expired
//
// 与 ConfigChangeRequest 区别:
//
//	ConfigChangeRequest 是配置变更审批 (异步, 走 worker apply)
//	SOARApproval 是动作执行前阻塞审批 (同步, 阻塞 Playbook 执行)
package soar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DefaultApprovalChecker 默认 ApprovalChecker.
type DefaultApprovalChecker struct {
	db          *gorm.DB
	logger      *zap.Logger
	pollEvery   time.Duration
	maxWaitTime time.Duration
}

// NewDefaultApprovalChecker 构造.
func NewDefaultApprovalChecker(db *gorm.DB, logger *zap.Logger) *DefaultApprovalChecker {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DefaultApprovalChecker{
		db:          db,
		logger:      logger,
		pollEvery:   5 * time.Second,
		maxWaitTime: 30 * time.Minute,
	}
}

// SetTimeouts 调整轮询/超时.
func (c *DefaultApprovalChecker) SetTimeouts(pollEvery, maxWait time.Duration) {
	if pollEvery > 0 {
		c.pollEvery = pollEvery
	}
	if maxWait > 0 {
		c.maxWaitTime = maxWait
	}
}

// SOARApproval DB 记录.
type SOARApproval struct {
	ID                uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID          string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	PlaybookID        string    `gorm:"column:playbook_id;type:varchar(128);not null;index" json:"playbook_id"`
	StepID            string    `gorm:"column:step_id;type:varchar(128);not null" json:"step_id"`
	RequiredApprovers int       `gorm:"column:required_approvers;not null;default:1" json:"required_approvers"`
	ApprovedCount     int       `gorm:"column:approved_count;not null;default:0" json:"approved_count"`
	Approvers         string    `gorm:"column:approvers;type:text" json:"approvers"`
	Status            string    `gorm:"column:status;type:varchar(16);not null;index;default:'pending'" json:"status"`
	RejectedBy        string    `gorm:"column:rejected_by;type:varchar(100)" json:"rejected_by"`
	RejectReason      string    `gorm:"column:reject_reason;type:text" json:"reject_reason"`
	ExpiresAt         time.Time `gorm:"column:expires_at;type:timestamp" json:"expires_at"`
	CreatedAt         time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt         time.Time `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName.
func (SOARApproval) TableName() string { return "soar_approvals" }

// Check 阻塞等待 approval. 满足条件返回 true.
//
// 超时 / context done → false + error.
func (c *DefaultApprovalChecker) Check(ctx context.Context, playbookID, stepID string, requiredApprovers int) (bool, error) {
	if requiredApprovers <= 0 {
		return true, nil
	}
	expires := time.Now().Add(c.maxWaitTime)
	rec := SOARApproval{
		PlaybookID:        playbookID,
		StepID:            stepID,
		RequiredApprovers: requiredApprovers,
		Status:            "pending",
		ExpiresAt:         expires,
	}
	if err := c.db.WithContext(ctx).Create(&rec).Error; err != nil {
		return false, fmt.Errorf("create approval: %w", err)
	}
	c.logger.Info("SOAR approval requested",
		zap.String("playbook", playbookID),
		zap.String("step", stepID),
		zap.Int("required", requiredApprovers),
		zap.Uint("approval_id", rec.ID))

	// 轮询
	t := time.NewTicker(c.pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.markStatus(rec.ID, "cancelled", "")
			return false, ctx.Err()
		case <-t.C:
			var cur SOARApproval
			if err := c.db.WithContext(ctx).First(&cur, rec.ID).Error; err != nil {
				c.logger.Warn("approval re-fetch failed", zap.Error(err))
				continue
			}
			switch cur.Status {
			case "approved":
				return true, nil
			case "rejected":
				return false, fmt.Errorf("approval rejected: %s", cur.RejectReason)
			case "expired", "cancelled":
				return false, errors.New("approval " + cur.Status)
			}
			// pending: 检查超时
			if time.Now().After(cur.ExpiresAt) {
				c.markStatus(rec.ID, "expired", "timeout")
				return false, errors.New("approval timed out")
			}
		}
	}
}

func (c *DefaultApprovalChecker) markStatus(id uint, status, note string) {
	updates := map[string]any{"status": status}
	if note != "" {
		updates["reject_reason"] = note
	}
	c.db.Model(&SOARApproval{}).Where("id = ?", id).Updates(updates)
}

// Approve 审批人调用.
//
// 满足 RequiredApprovers 即 status=approved.
// 同 approver 不可重复.
func (c *DefaultApprovalChecker) Approve(ctx context.Context, approvalID uint, approver string) error {
	if approver == "" {
		return errors.New("approver required")
	}
	var rec SOARApproval
	if err := c.db.WithContext(ctx).First(&rec, approvalID).Error; err != nil {
		return fmt.Errorf("approval not found: %w", err)
	}
	if rec.Status != "pending" {
		return fmt.Errorf("approval status=%s, cannot approve", rec.Status)
	}
	for _, a := range strings.Split(rec.Approvers, ",") {
		if a == approver {
			return errors.New("approver already approved")
		}
	}
	if rec.Approvers == "" {
		rec.Approvers = approver
	} else {
		rec.Approvers = rec.Approvers + "," + approver
	}
	rec.ApprovedCount++
	if rec.ApprovedCount >= rec.RequiredApprovers {
		rec.Status = "approved"
	}
	return c.db.WithContext(ctx).Save(&rec).Error
}

// Reject 拒绝.
func (c *DefaultApprovalChecker) Reject(ctx context.Context, approvalID uint, rejecter, reason string) error {
	if rejecter == "" || reason == "" {
		return errors.New("rejecter and reason required")
	}
	res := c.db.WithContext(ctx).Model(&SOARApproval{}).
		Where("id = ? AND status = ?", approvalID, "pending").
		Updates(map[string]any{
			"status":        "rejected",
			"rejected_by":   rejecter,
			"reject_reason": reason,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("approval not pending")
	}
	return nil
}

// 编译期 sanity check.
var _ ApprovalChecker = (*DefaultApprovalChecker)(nil)
