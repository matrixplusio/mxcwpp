package scheduler

import (
	"context"
	"fmt"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 认证日志采集断流：主机在线，logcollector 的心跳却停了。
//
// 插件被停、被杀、卡死时，认证事件在服务端看起来和「没人登录」一样，只有心跳能把两者分开。
// 这件事不放在 engine 里判断：engine 的状态在内存里，重启就丢；而且它只能在「这台主机又来了
// 别的事件」时顺带判断，事件稀疏的主机等不来判断的时机。这里按 ClickHouse 里实际落库的心跳
// （received_at 是 AgentCenter 收到的时间，不是主机自报的）与主机在线状态对账。

const (
	// authlogSilenceThreshold 心跳间隔 5 分钟，丢两条还算正常（插件升级、agent 重连补发），丢三条才报。
	authlogSilenceThreshold = 16 * time.Minute
	// authlogSilenceLookback 只看最近这么久发过心跳的主机：从没装插件的主机不判。
	authlogSilenceLookback = 7 * 24 * time.Hour
	// authlogSilenceStartGrace agent 刚启动时插件还在拉起、积压在补发，这段时间不判。
	authlogSilenceStartGrace = 20 * time.Minute
	// authlogPipelineStale 内核事件表与认证事件表都这么久没有新写入，说明是落库管道停了（consumer 积压或宕机），
	// 不是每台主机各自的问题——那时逐台开告警会一次刷出大量告警，而真正的问题另有积压告警。
	// 判据不用心跳本身：只看心跳的话，装插件的主机少、或插件全体崩溃时，「所有心跳都旧」也成立，
	// 真正的断流就被当成管道问题放过去了。也不用事件里的时间：那是主机时钟。
	authlogPipelineStale  = 10 * time.Minute
	authlogSilenceEvery   = 5 * time.Minute
	authlogSilenceRuleID  = "AUTHLOG_COLLECTOR_SILENT"
	authlogSilenceQueryTO = 60 * time.Second
)

// authlogPipelineQuery 这两张表最近一次写入的服务端时间。level 0 是插入直接生成的数据分片，
// 合并出来的分片 level 更高，不算写入；刚被合并掉的 level 0 分片在 system.parts 里还会留几分钟，所以不限 active。
const authlogPipelineQuery = `
SELECT max(modification_time) FROM system.parts
WHERE database = currentDatabase() AND table IN ('ebpf_events', 'auth_events') AND level = 0`

const authlogLastBeatQuery = `
SELECT host_id, max(received_at) AS last
FROM auth_events
WHERE event_type = 'auth_collector_heartbeat' AND received_at >= ? AND received_at <= ?
GROUP BY host_id`

// StartAuthlogSilenceScheduler 周期检测认证日志采集断流。
func StartAuthlogSilenceScheduler(db *gorm.DB, ch chdriver.Conn, logger *zap.Logger) {
	if ch == nil {
		logger.Info("未启用 ClickHouse，认证日志采集断流检测不启动")
		return
	}
	ticker := time.NewTicker(authlogSilenceEvery)
	defer ticker.Stop()
	logger.Info("认证日志采集断流检测已启动", zap.Duration("threshold", authlogSilenceThreshold))
	checkAuthlogSilence(db, ch, logger, time.Now())
	for range ticker.C {
		checkAuthlogSilence(db, ch, logger, time.Now())
	}
}

func authlogSilenceResultID(hostID string) string { return "authlog-silent-" + hostID }

func checkAuthlogSilence(db *gorm.DB, ch chdriver.Conn, logger *zap.Logger, now time.Time) {
	last, err := queryAuthlogLastBeats(ch, now)
	if err != nil {
		logger.Error("查询认证日志采集心跳失败，本轮不判断断流", zap.Error(err))
		return
	}
	if len(last) == 0 {
		return
	}
	var hosts []model.Host
	ids := make([]string, 0, len(last))
	for id := range last {
		ids = append(ids, id)
	}
	if err := db.Where("host_id IN ?", ids).Find(&hosts).Error; err != nil {
		logger.Error("查询主机在线状态失败", zap.Error(err))
		return
	}
	var actives []model.Alert
	if err := db.Where("rule_id = ? AND status = ?", authlogSilenceRuleID, model.AlertStatusActive).
		Find(&actives).Error; err != nil {
		logger.Error("查询认证日志采集断流告警失败", zap.Error(err))
		return
	}
	activeHosts := make(map[string]bool, len(actives))
	for _, a := range actives {
		activeHosts[a.HostID] = true
	}

	pipeline, err := queryPipelineLatest(ch, now)
	switch {
	case err != nil:
		// 判断不了管道是否在走时照常逐台判断：宁可多报，不能因此不报。
		logger.Warn("查询落库进度失败，按管道正常处理", zap.Error(err))
		pipeline = now
	case pipeline.Unix() <= 0:
		// 一个新写入的数据分片都查不到（库名不对、表还没建）：同样是判断不了，不是「停了」。
		logger.Warn("查不到落库进度，按管道正常处理")
		pipeline = now
	}
	d := decideAuthlogSilence(last, hosts, activeHosts, pipeline, now)
	if d.pipelineStale {
		logger.Error("内核事件与认证日志心跳都已停止落库，判断为落库管道问题，本轮不逐台告警",
			zap.Time("pipeline_latest", pipeline))
		return
	}
	for _, h := range d.open {
		openAuthlogSilenceAlert(db, logger, h, last[h.HostID], now)
	}
	for i := range actives {
		if reason, ok := d.resolve[actives[i].HostID]; ok {
			resolveAuthlogSilenceAlert(db, logger, &actives[i], reason, now)
		}
	}
}

func queryPipelineLatest(ch chdriver.Conn, now time.Time) (time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), authlogSilenceQueryTO)
	defer cancel()
	var t time.Time
	err := ch.QueryRow(ctx, authlogPipelineQuery).Scan(&t)
	return t, err
}

func queryAuthlogLastBeats(ch chdriver.Conn, now time.Time) (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), authlogSilenceQueryTO)
	defer cancel()
	// 上界：received_at 只有在加列前的旧行上才会取默认值（主机报的事件时间），时钟拨快的主机
	// 会让那几行落在未来，看起来一直在发心跳。
	rows, err := ch.Query(ctx, authlogLastBeatQuery, now.Add(-authlogSilenceLookback), now.Add(5*time.Minute))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var t time.Time
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

type authlogSilenceDecision struct {
	pipelineStale bool
	open          []*model.Host
	resolve       map[string]string // host_id → 恢复原因
}

// decideAuthlogSilence 纯判定，不碰数据库，便于测试。
func decideAuthlogSilence(last map[string]time.Time, hosts []model.Host, active map[string]bool, pipeline, now time.Time) authlogSilenceDecision {
	d := authlogSilenceDecision{resolve: map[string]string{}}
	if now.Sub(pipeline) > authlogPipelineStale {
		d.pipelineStale = true
		return d
	}
	online := now.Add(-telemetryGapOnlineWindow)
	for i := range hosts {
		h := &hosts[i]
		silent := now.Sub(last[h.HostID]) > authlogSilenceThreshold
		isOnline := h.Status == model.HostStatusOnline && h.LastHeartbeat != nil && !h.LastHeartbeat.Time().Before(online)
		switch {
		case !silent:
			if active[h.HostID] {
				d.resolve[h.HostID] = "采集心跳已恢复"
			}
		case !isOnline:
			// 离线由心跳超时告警接管，两条并存只会让人以为是两件事。
			if active[h.HostID] {
				d.resolve[h.HostID] = "主机已离线，由离线告警接管"
			}
		case h.AgentStartTime != nil && !h.AgentStartTime.Time().After(now) &&
			now.Sub(h.AgentStartTime.Time()) < authlogSilenceStartGrace:
			// agent 刚启动，插件还没送出首批心跳。启动时间是主机时钟报的：晚于现在的不可信，
			// 不给宽限——否则把时钟拨快一天再杀插件，主机就永远处在宽限期里。
		case !active[h.HostID]:
			d.open = append(d.open, h)
		}
	}
	return d
}

func openAuthlogSilenceAlert(db *gorm.DB, logger *zap.Logger, h *model.Host, last, now time.Time) {
	ts := model.ToLocalTime(now)
	title := fmt.Sprintf("认证日志采集中断: %s", h.Hostname)
	desc := fmt.Sprintf("主机在线，但认证日志采集插件的心跳已 %s 没有到达（最近一次 %s）。此期间的登录、sudo、账号变更不会被记录与检测："+
		"插件可能被停止、被杀或卡死，请检查插件状态。",
		now.Sub(last).Truncate(time.Minute), last.Local().Format("2006-01-02 15:04"))

	var existing model.Alert
	if err := db.Where("result_id = ?", authlogSilenceResultID(h.HostID)).First(&existing).Error; err == nil {
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
		ResultID:       authlogSilenceResultID(h.HostID),
		HostID:         h.HostID,
		RuleID:         authlogSilenceRuleID,
		Source:         model.AlertSourceDetection,
		Severity:       "medium",
		Category:       "authlog_integrity",
		ATTCKTactic:    "TA0005",
		ATTCKTechnique: "T1562.001",
		Title:          title,
		Description:    desc,
		Status:         model.AlertStatusActive,
		HitCount:       1,
		FirstSeenAt:    ts,
		LastSeenAt:     ts,
	}
	if err := db.Create(a).Error; err != nil {
		logger.Warn("创建认证日志采集断流告警失败", zap.String("host_id", h.HostID), zap.Error(err))
		return
	}
	logger.Info("已创建认证日志采集断流告警", zap.String("host_id", h.HostID), zap.Uint("alert_id", a.ID))
}

func resolveAuthlogSilenceAlert(db *gorm.DB, logger *zap.Logger, a *model.Alert, reason string, now time.Time) {
	ts := model.ToLocalTime(now)
	res := db.Model(&model.Alert{}).Where("id = ? AND status = ?", a.ID, model.AlertStatusActive).
		Updates(map[string]any{
			"status": model.AlertStatusResolved, "resolved_at": &ts,
			"resolved_by": "system", "resolve_reason": reason,
		})
	if res.Error != nil || res.RowsAffected == 0 {
		return
	}
	logger.Info("已自动恢复认证日志采集断流告警", zap.String("host_id", a.HostID), zap.String("reason", reason))
	a.ResolveReason = reason
	if e, ok := alertbus.ResolvedEvent(a); ok {
		alertbus.Publish(e)
	}
}
