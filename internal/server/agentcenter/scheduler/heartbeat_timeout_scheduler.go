// Package scheduler 提供任务调度器
package scheduler

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// heartbeatTimeoutMinutes 心跳超时阈值（分钟）
// 主机超过此时间未发送心跳，判定为离线
const heartbeatTimeoutMinutes = 5

// StartHeartbeatTimeoutScheduler 启动心跳超时检测调度器
// 每 60 秒扫描一次 status='online' 但 last_heartbeat 超时的主机，
// 将其标记为 offline 并创建离线告警。
// 用于覆盖网络分区等 gRPC 连接未正常断开的场景。
func StartHeartbeatTimeoutScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	logger.Info("心跳超时检测调度器已启动",
		zap.Duration("check_interval", 60*time.Second),
		zap.Int("timeout_minutes", heartbeatTimeoutMinutes),
	)

	// 启动时立即执行一次
	checkHeartbeatTimeout(db, logger)

	for range ticker.C {
		checkHeartbeatTimeout(db, logger)
	}
}

// checkHeartbeatTimeout 检查心跳超时的主机
func checkHeartbeatTimeout(db *gorm.DB, logger *zap.Logger) {
	threshold := time.Now().Add(-time.Duration(heartbeatTimeoutMinutes) * time.Minute)

	// 查询状态为 online 但心跳已超时的主机
	var staleHosts []model.Host
	err := db.Where("status = ? AND last_heartbeat IS NOT NULL AND last_heartbeat < ?",
		model.HostStatusOnline, threshold).
		Find(&staleHosts).Error
	if err != nil {
		logger.Error("查询心跳超时主机失败", zap.Error(err))
		return
	}

	if len(staleHosts) == 0 {
		return
	}

	logger.Warn("检测到心跳超时主机",
		zap.Int("count", len(staleHosts)),
		zap.Int("timeout_minutes", heartbeatTimeoutMinutes),
	)

	for _, host := range staleHosts {
		// 更新主机状态为离线
		if err := db.Model(&model.Host{}).Where("host_id = ? AND status = ?",
			host.HostID, model.HostStatusOnline).
			Update("status", model.HostStatusOffline).Error; err != nil {
			logger.Error("更新主机离线状态失败",
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			continue
		}

		// 创建离线告警
		createHeartbeatTimeoutAlert(db, logger, &host)

		lastHB := time.Time{}
		if host.LastHeartbeat != nil {
			lastHB = host.LastHeartbeat.Time()
		}
		logger.Info("已将心跳超时主机标记为离线",
			zap.String("host_id", host.HostID),
			zap.String("hostname", host.Hostname),
			zap.Time("last_heartbeat", lastHB),
			zap.Duration("elapsed", time.Since(lastHB)),
		)
	}
}

// createHeartbeatTimeoutAlert 为心跳超时主机创建离线告警
// 复用 transfer/service.go 中 createAgentOfflineAlert 的 result_id 格式，
// 保证 Agent 重新上线时能被 resolveAgentOfflineAlert 自动解除。
func createHeartbeatTimeoutAlert(db *gorm.DB, logger *zap.Logger, host *model.Host) {
	now := model.Now()
	resultID := fmt.Sprintf("offline-%s", host.HostID)

	ip := ""
	if len(host.IPv4) > 0 {
		ip = strings.Join(host.IPv4, ",")
	}
	title := fmt.Sprintf("Agent 离线: %s (%s)", host.Hostname, ip)
	description := fmt.Sprintf("主机 %s 心跳超时（超过 %d 分钟未上报心跳）", host.Hostname, heartbeatTimeoutMinutes)

	// 查找已有告警（包括已解决的）
	var existing model.Alert
	err := db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		// 已有记录且已激活，无需重复操作
		if existing.Status == model.AlertStatusActive {
			return
		}
		// 重新激活
		db.Model(&existing).Updates(map[string]any{
			"status":       model.AlertStatusActive,
			"title":        title,
			"description":  description,
			"last_seen_at": now,
			"resolved_at":  nil,
			"resolved_by":  "",
		})
		logger.Info("已重新激活心跳超时离线告警",
			zap.String("host_id", host.HostID),
			zap.Uint("alert_id", existing.ID),
		)
	} else {
		alert := &model.Alert{
			ResultID:    resultID,
			HostID:      host.HostID,
			RuleID:      "agent_offline",
			Source:      model.AlertSourceAgent,
			Severity:    "high",
			Category:    "agent_offline",
			Title:       title,
			Description: description,
			Status:      model.AlertStatusActive,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
		if err := db.Create(alert).Error; err != nil {
			logger.Warn("创建心跳超时离线告警失败",
				zap.String("host_id", host.HostID),
				zap.Error(err),
			)
			return
		}
		logger.Info("已创建心跳超时离线告警",
			zap.String("host_id", host.HostID),
			zap.Uint("alert_id", alert.ID),
		)
	}
}
