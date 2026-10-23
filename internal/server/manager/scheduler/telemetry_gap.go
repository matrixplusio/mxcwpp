package scheduler

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 采集中断检测：心跳在，插件数据却停了。
//
// 离线有心跳超时告警兜着，但「心跳正常、插件全哑」此前没有任何告警——主机在控制台上
// 显示在线，检测与资产却早已是空的，往往要等恢复后一批误报才暴露。
// 主机指标是从心跳里解析的，不能拿它判断；判据是 AC 记下的 hosts.last_data_at。

const (
	// telemetryGapThreshold 在线主机超过多久没有插件数据算中断。
	// 资产采集是小时级周期，阈值要盖住一个周期再留余量。
	telemetryGapThreshold = 6 * time.Hour
	// telemetryGapOnlineWindow 心跳多新才算「在线」，与 AC 心跳超时一致。
	telemetryGapOnlineWindow = 5 * time.Minute
	// telemetryGapStartGrace agent 刚启动时插件还在拉起，这段时间内不判。
	// 否则长时间离线的主机一回来，last_data_at 还是离线前的值，会在插件送出首批数据前被误判。
	telemetryGapStartGrace = 30 * time.Minute
	telemetryGapInterval   = 5 * time.Minute
	telemetryGapRuleID     = "telemetry_gap"
)

// StartTelemetryGapScheduler 周期检测采集中断。
func StartTelemetryGapScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(telemetryGapInterval)
	defer ticker.Stop()

	logger.Info("采集中断检测已启动", zap.Duration("threshold", telemetryGapThreshold))
	checkTelemetryGap(db, logger, time.Now())
	for range ticker.C {
		checkTelemetryGap(db, logger, time.Now())
	}
}

func telemetryGapResultID(hostID string) string { return "telemetry-gap-" + hostID }

// checkTelemetryGap 为采集中断的在线主机开告警，并恢复已不再中断的。
//
// last_data_at 为空的主机不判：要么从未装插件，要么是本功能上线前就没送过数据，
// 拿空值当「很久以前」会在上线瞬间对全网告警。
func checkTelemetryGap(db *gorm.DB, logger *zap.Logger, now time.Time) {
	online := now.Add(-telemetryGapOnlineWindow)
	cutoff := now.Add(-telemetryGapThreshold)

	var gaps []model.Host
	if err := db.Where("status = ? AND last_heartbeat >= ? AND last_data_at IS NOT NULL AND last_data_at < ?"+
		" AND (agent_start_time IS NULL OR agent_start_time < ?)",
		model.HostStatusOnline, online, cutoff, now.Add(-telemetryGapStartGrace)).Find(&gaps).Error; err != nil {
		logger.Error("查询采集中断主机失败", zap.Error(err))
		return
	}
	for i := range gaps {
		openTelemetryGapAlert(db, logger, &gaps[i], now)
	}

	var actives []model.Alert
	if err := db.Where("rule_id = ? AND status = ?", telemetryGapRuleID, model.AlertStatusActive).
		Find(&actives).Error; err != nil {
		logger.Error("查询采集中断告警失败", zap.Error(err))
		return
	}
	for i := range actives {
		var h model.Host
		if err := db.Where("host_id = ?", actives[i].HostID).First(&h).Error; err != nil {
			continue
		}
		var reason string
		switch {
		case h.LastDataAt != nil && !h.LastDataAt.Time().Before(cutoff):
			reason = "插件数据已恢复"
		case h.Status != model.HostStatusOnline:
			// 离线由心跳超时告警接管，两条并存只会让人以为是两件事。
			reason = "主机已离线，由离线告警接管"
		default:
			continue
		}
		resolveTelemetryGapAlert(db, logger, &actives[i], reason, now)
	}
}

func openTelemetryGapAlert(db *gorm.DB, logger *zap.Logger, h *model.Host, now time.Time) {
	ts := model.ToLocalTime(now)
	title := fmt.Sprintf("采集中断: %s (%s)", h.Hostname, strings.Join(h.IPv4, ","))
	desc := fmt.Sprintf("主机心跳正常，但已 %s 未收到任何插件数据（最近一次 %s）。检测、资产、基线结果均可能缺失，请检查插件状态。",
		now.Sub(h.LastDataAt.Time()).Truncate(time.Minute), h.LastDataAt.Time().Format("2006-01-02 15:04"))

	var existing model.Alert
	err := db.Where("result_id = ?", telemetryGapResultID(h.HostID)).First(&existing).Error
	if err == nil {
		if existing.Status == model.AlertStatusActive {
			return
		}
		// 置空 last_notified_at：统一出口把它当作再次中断通知。
		db.Model(&existing).Updates(map[string]any{
			"status": model.AlertStatusActive, "title": title, "description": desc,
			"last_seen_at": ts, "resolved_at": nil, "resolved_by": "", "resolve_reason": "",
			"last_notified_at": nil,
		})
		return
	}
	a := &model.Alert{
		ResultID:    telemetryGapResultID(h.HostID),
		HostID:      h.HostID,
		RuleID:      telemetryGapRuleID,
		Source:      model.AlertSourceAgent,
		Severity:    "high",
		Category:    telemetryGapRuleID,
		Title:       title,
		Description: desc,
		Status:      model.AlertStatusActive,
		FirstSeenAt: ts,
		LastSeenAt:  ts,
	}
	if err := db.Create(a).Error; err != nil {
		logger.Warn("创建采集中断告警失败", zap.String("host_id", h.HostID), zap.Error(err))
		return
	}
	logger.Info("已创建采集中断告警", zap.String("host_id", h.HostID), zap.Uint("alert_id", a.ID))
}

func resolveTelemetryGapAlert(db *gorm.DB, logger *zap.Logger, a *model.Alert, reason string, now time.Time) {
	ts := model.ToLocalTime(now)
	res := db.Model(&model.Alert{}).Where("id = ? AND status = ?", a.ID, model.AlertStatusActive).
		Updates(map[string]any{
			"status": model.AlertStatusResolved, "resolved_at": &ts,
			"resolved_by": "system", "resolve_reason": reason,
		})
	if res.Error != nil || res.RowsAffected == 0 {
		return
	}
	logger.Info("已自动恢复采集中断告警", zap.String("host_id", a.HostID), zap.String("reason", reason))
	a.ResolveReason = reason
	if e, ok := alertbus.ResolvedEvent(a); ok {
		alertbus.Publish(e)
	}
}
