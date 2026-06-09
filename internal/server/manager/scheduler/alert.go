// Package scheduler 提供任务调度器
package scheduler

import (
	"encoding/json"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// StartAlertScheduler 启动定期告警调度器
// 每分钟检查一次，根据告警配置的间隔发送待通知的告警
func StartAlertScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(1 * time.Minute) // 每分钟检查一次
	defer ticker.Stop()

	logger.Info("定期告警调度器已启动", zap.Duration("check_interval", 1*time.Minute))

	// 启动时立即执行一次检查
	processPeriodicAlerts(db, logger)

	// 定时执行
	for range ticker.C {
		processPeriodicAlerts(db, logger)
	}
}

// getAlertConfig 获取告警配置
func getAlertConfig(db *gorm.DB, logger *zap.Logger) model.AlertConfig {
	defaultConfig := model.DefaultAlertConfig()

	var config model.SystemConfig
	if err := db.Where("`key` = ? AND category = ?", "alert_config", "alert").First(&config).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			logger.Warn("查询告警配置失败，使用默认配置", zap.Error(err))
		}
		return defaultConfig
	}

	if config.Value == "" {
		return defaultConfig
	}

	var alertConfig model.AlertConfig
	if err := json.Unmarshal([]byte(config.Value), &alertConfig); err != nil {
		logger.Warn("解析告警配置失败，使用默认配置", zap.Error(err))
		return defaultConfig
	}

	if alertConfig.RepeatAlertInterval <= 0 {
		alertConfig.RepeatAlertInterval = defaultConfig.RepeatAlertInterval
	}

	return alertConfig
}

// processPeriodicAlerts 处理定期告警
func processPeriodicAlerts(db *gorm.DB, logger *zap.Logger) {
	// 获取告警配置
	alertConfig := getAlertConfig(db, logger)

	logger.Debug("定期告警检查开始",
		zap.Bool("enabled", alertConfig.EnablePeriodicSummary),
		zap.Int("repeat_interval_minutes", alertConfig.RepeatAlertInterval),
	)

	// 如果未启用定期汇总，直接返回
	if !alertConfig.EnablePeriodicSummary {
		logger.Debug("定期告警汇总未启用，跳过本次检查")
		return
	}

	// 获取通知间隔
	intervalMinutes := alertConfig.RepeatAlertInterval
	if intervalMinutes <= 0 {
		intervalMinutes = 30 // 默认 30 分钟
	}

	// 计算截止时间（上次通知时间早于此时间的告警需要重新通知）
	cutoffTime := time.Now().Add(-time.Duration(intervalMinutes) * time.Minute)

	// 查询活跃告警总数
	var totalActiveAlerts int64
	db.Model(&model.Alert{}).Where("status = ?", model.AlertStatusActive).Count(&totalActiveAlerts)

	logger.Debug("开始处理定期告警",
		zap.Int("interval_minutes", intervalMinutes),
		zap.Time("cutoff_time", cutoffTime),
		zap.Int64("total_active_alerts", totalActiveAlerts),
	)

	// 查询所有启用的、类别为 baseline_alert 的通知配置
	var baselineNotifications []model.Notification
	if err := db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryBaselineAlert).Find(&baselineNotifications).Error; err != nil {
		logger.Error("查询通知配置失败", zap.Error(err))
		return
	}

	// 过滤出配置了 severities 的通知
	var validNotifications []model.Notification
	for _, n := range baselineNotifications {
		if len(n.Severities) > 0 {
			validNotifications = append(validNotifications, n)
		}
	}

	if len(validNotifications) == 0 {
		logger.Debug("没有找到配置了告警等级的基线告警通知配置，跳过定期告警")
		return
	}
	baselineNotifications = validNotifications

	logger.Debug("找到可用的基线告警通知配置",
		zap.Int("count", len(baselineNotifications)),
	)

	// 对每个通知配置处理告警
	sentTotal := 0
	for _, notification := range baselineNotifications {
		sent := processNotificationAlerts(db, logger, &notification, cutoffTime, intervalMinutes)
		sentTotal += sent
	}

	logger.Debug("定期告警检查完成",
		zap.Int("sent_count", sentTotal),
	)
}

// processNotificationAlerts 处理单个通知配置的告警
// 返回成功发送的通知数量
func processNotificationAlerts(db *gorm.DB, logger *zap.Logger, notification *model.Notification, cutoffTime time.Time, intervalMinutes int) int {
	// 构建查询条件：
	// 1. 状态为 active
	// 2. 严重级别匹配
	// 3. 需要通知的告警：
	//    - 从未通知过的告警（last_notified_at IS NULL，可能首次通知时没有匹配的通知配置）
	//    - 或者上次通知时间早于截止时间的告警（需要重复通知）

	query := db.Model(&model.Alert{}).
		Where("status = ?", model.AlertStatusActive).
		Where("severity IN (?)", []string(notification.Severities)).
		Where("(last_notified_at IS NULL OR last_notified_at < ?)", cutoffTime) // 支持从未通知过的告警

	// 查询需要通知的告警
	var alerts []model.Alert
	if err := query.Find(&alerts).Error; err != nil {
		logger.Error("查询待通知告警失败",
			zap.Uint("notification_id", notification.ID),
			zap.Error(err))
		return 0
	}

	if len(alerts) == 0 {
		logger.Debug("没有需要通知的告警",
			zap.Uint("notification_id", notification.ID),
			zap.Strings("severities", notification.Severities),
		)
		return 0
	}

	logger.Info("发现需要通知的告警",
		zap.Uint("notification_id", notification.ID),
		zap.String("notification_name", notification.Name),
		zap.Int("alert_count", len(alerts)),
		zap.Int("interval_minutes", intervalMinutes),
		zap.Time("cutoff_time", cutoffTime),
		zap.String("scope", string(notification.Scope)),
	)

	// 发送告警通知
	notificationService := biz.NewNotificationService(db, logger)
	sentCount := 0
	skippedByScopeCount := 0
	failedCount := 0

	for _, alert := range alerts {
		// 检查主机范围是否匹配
		matched, reason := matchAlertScopeWithReason(db, logger, notification, &alert)
		if !matched {
			logger.Debug("告警不在通知配置的主机范围内",
				zap.Uint("alert_id", alert.ID),
				zap.String("host_id", alert.HostID),
				zap.String("scope", string(notification.Scope)),
				zap.String("reason", reason),
			)
			skippedByScopeCount++
			continue
		}

		// 发送通知
		sent, err := notificationService.SendAlertNotificationForAlert(&alert)
		if err != nil {
			logger.Warn("发送定期告警通知失败",
				zap.Uint("alert_id", alert.ID),
				zap.Error(err))
			failedCount++
			continue
		}

		if sent {
			// 更新告警的通知时间和通知次数
			now := model.Now()
			db.Model(&model.Alert{}).Where("id = ?", alert.ID).Updates(map[string]interface{}{
				"last_notified_at": &now,
				"notify_count":     gorm.Expr("notify_count + 1"),
			})

			logger.Info("定期告警通知已发送",
				zap.Uint("alert_id", alert.ID),
				zap.String("host_id", alert.HostID),
				zap.String("rule_id", alert.RuleID),
				zap.String("severity", alert.Severity),
			)
			sentCount++
		}
	}

	// 输出汇总日志，帮助诊断通知数量不足问题
	if skippedByScopeCount > 0 || failedCount > 0 {
		logger.Warn("定期告警通知处理汇总",
			zap.Uint("notification_id", notification.ID),
			zap.String("notification_name", notification.Name),
			zap.Int("total_alerts", len(alerts)),
			zap.Int("sent_count", sentCount),
			zap.Int("skipped_by_scope", skippedByScopeCount),
			zap.Int("failed_count", failedCount),
			zap.String("scope", string(notification.Scope)),
		)
	}

	return sentCount
}

// matchAlertScopeWithReason 检查告警是否在通知配置的主机范围内，并返回不匹配的原因
func matchAlertScopeWithReason(db *gorm.DB, logger *zap.Logger, notification *model.Notification, alert *model.Alert) (bool, string) {
	switch notification.Scope {
	case model.NotificationScopeGlobal:
		return true, ""

	case model.NotificationScopeBusinessLine:
		// 查询主机的业务线
		var host model.Host
		if err := db.First(&host, "host_id = ?", alert.HostID).Error; err != nil {
			logger.Debug("查询主机失败，跳过告警",
				zap.String("host_id", alert.HostID),
				zap.Uint("alert_id", alert.ID),
				zap.Error(err),
			)
			return false, "主机不存在"
		}
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			logger.Warn("解析通知配置主机范围失败",
				zap.Uint("notification_id", notification.ID),
				zap.Error(err),
			)
			return false, "解析业务线配置失败"
		}
		// 检查主机是否设置了业务线
		if host.BusinessLine == "" {
			return false, "主机未设置业务线"
		}
		for _, bl := range scopeValue.BusinessLines {
			if host.BusinessLine == bl {
				return true, ""
			}
		}
		return false, "主机业务线(" + host.BusinessLine + ")不在通知配置的业务线列表中"

	case model.NotificationScopeSpecified:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			logger.Warn("解析通知配置主机范围失败",
				zap.Uint("notification_id", notification.ID),
				zap.Error(err),
			)
			return false, "解析指定主机配置失败"
		}
		for _, hostID := range scopeValue.HostIDs {
			if hostID == alert.HostID {
				return true, ""
			}
		}
		return false, "主机不在指定主机列表中"

	case model.NotificationScopeHostTags:
		// TODO: 实现主机标签匹配
		return true, ""

	default:
		logger.Warn("未知的通知范围类型",
			zap.Uint("notification_id", notification.ID),
			zap.String("scope", string(notification.Scope)),
		)
		return false, "未知的通知范围类型"
	}
}
