package scheduler

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// StartBulletinEscalationScheduler 启动漏洞通报升级调度器
// 每 5 分钟检查一次：SLA 超时标记、升级通知、自动关闭已修复通报
func StartBulletinEscalationScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	logger.Info("漏洞通报升级调度器已启动", zap.Duration("check_interval", 5*time.Minute))

	// 启动时立即执行一次
	processBulletinEscalation(db, logger)

	for range ticker.C {
		processBulletinEscalation(db, logger)
	}
}

// processBulletinEscalation 处理通报升级逻辑
func processBulletinEscalation(db *gorm.DB, logger *zap.Logger) {
	svc := biz.NewVulnBulletinService(db, logger)

	// 1. 检查 SLA 超时
	svc.CheckSLABreach()

	// 2. 自动关闭所有主机已修复的通报
	svc.AutoResolvePatched()

	// 3. 升级通知：对未确认的 P0/P1 通报重新发送通知
	cfg := svc.GetConfig()
	if !cfg.EscalationEnabled {
		return
	}

	escalatePriority(db, logger, model.BulletinPriorityP0, cfg.GetEscalationMinutes(model.BulletinPriorityP0))
	escalatePriority(db, logger, model.BulletinPriorityP1, cfg.GetEscalationMinutes(model.BulletinPriorityP1))
}

// escalatePriority 对指定优先级的未确认通报发送升级通知
func escalatePriority(db *gorm.DB, logger *zap.Logger, priority string, intervalMinutes int) {
	if intervalMinutes <= 0 {
		return
	}

	cutoff := time.Now().Add(-time.Duration(intervalMinutes) * time.Minute)

	var bulletins []model.VulnBulletin
	db.Where("priority = ? AND status IN ? AND (last_notified_at IS NULL OR last_notified_at < ?)",
		priority,
		[]string{model.BulletinStatusPending, model.BulletinStatusNotified},
		cutoff,
	).Find(&bulletins)

	if len(bulletins) == 0 {
		return
	}

	logger.Info("发现需要升级通知的通报",
		zap.String("priority", priority),
		zap.Int("count", len(bulletins)),
	)

	ns := biz.NewNotificationService(db, logger)
	for _, b := range bulletins {
		if err := ns.SendVulnBulletinNotification(&b); err != nil {
			logger.Error("升级通知发送失败",
				zap.String("bulletin_no", b.BulletinNo),
				zap.Error(err))
		}
	}
}
