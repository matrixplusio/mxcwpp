package biz

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// EscalatePendingFIMEvents 检查超时未确认的 FIM 事件并升级为告警
// 规则：event.status='pending' 且 detected_at 距今超过所属策略的 escalation_timeout_min
func EscalatePendingFIMEvents(db *gorm.DB, logger *zap.Logger) {
	// 1. 加载所有策略的超时配置
	var policies []model.FIMPolicy
	if err := db.Select("policy_id, escalation_timeout_min").Find(&policies).Error; err != nil {
		logger.Error("查询 FIM 策略超时配置失败", zap.Error(err))
		return
	}
	policyTimeouts := make(map[string]int, len(policies))
	for _, p := range policies {
		timeout := p.EscalationTimeoutMin
		if timeout <= 0 {
			timeout = 1440
		}
		policyTimeouts[p.PolicyID] = timeout
	}

	// 2. 查询所有 pending 事件及其所属策略
	type eventRow struct {
		model.FIMEvent
		PolicyID string `gorm:"column:policy_id"`
	}
	var events []eventRow
	if err := db.Table("fim_events").
		Select("fim_events.*, fim_tasks.policy_id").
		Joins("LEFT JOIN fim_tasks ON fim_events.task_id = fim_tasks.task_id").
		Where("fim_events.status = ?", "pending").
		Find(&events).Error; err != nil {
		logger.Error("查询待确认 FIM 事件失败", zap.Error(err))
		return
	}

	if len(events) == 0 {
		return
	}

	escalated := 0
	for _, ev := range events {
		timeout := policyTimeouts[ev.PolicyID]
		if timeout <= 0 {
			timeout = 1440
		}
		cutoff := time.Now().Add(-time.Duration(timeout) * time.Minute)
		if !ev.DetectedAt.Time().Before(cutoff) {
			continue
		}

		// 创建告警
		alert := &model.Alert{
			ResultID:    fmt.Sprintf("fim-escalation-%s", ev.EventID),
			HostID:      ev.HostID,
			RuleID:      "fim-integrity-violation",
			PolicyID:    ev.PolicyID,
			Source:      model.AlertSourceFIM,
			Severity:    ev.Severity,
			Category:    ev.Category,
			Title:       fmt.Sprintf("文件完整性变更超时未确认: %s", ev.FilePath),
			Description: fmt.Sprintf("文件 %s 发生 %s 变更，超过 %d 分钟未确认，已自动升级为告警", ev.FilePath, ev.ChangeType, timeout),
			Actual:      ev.ChangeType,
			Status:      model.AlertStatusActive,
			FirstSeenAt: ev.DetectedAt,
			LastSeenAt:  model.Now(),
			CreatedAt:   model.Now(),
			UpdatedAt:   model.Now(),
		}

		if err := db.Create(alert).Error; err != nil {
			logger.Warn("创建 FIM 升级告警失败",
				zap.String("event_id", ev.EventID),
				zap.Error(err))
			continue
		}

		// 更新事件状态为 escalated
		db.Model(&model.FIMEvent{}).
			Where("event_id = ?", ev.EventID).
			Updates(map[string]any{
				"status":   "escalated",
				"alert_id": alert.ID,
			})

		escalated++
	}

	if escalated > 0 {
		logger.Info("FIM 事件超时升级完成",
			zap.Int("escalated", escalated),
			zap.Int("checked", len(events)))
	}
}
