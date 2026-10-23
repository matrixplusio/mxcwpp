package alertbus

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

// 主告警表（alerts）→ 待通知事件的桥接。
//
// 写 alerts 的地方有十几处（基线、检测、Agent、基础设施、FIM 升级、行为偏离……），
// 让每一处各自记得发通知，漏掉一处就是一类告警静默——基础设施告警就是这样从来没发出去过。
// 改为在这里统一看表：活跃且从未通知过的告警即待通知。新建告警（首次、关闭后复发都会新建一行）
// 天然满足；原地重新激活同一行的来源（基础设施恢复后再触发、Agent 心跳超时再次离线、
// 基线失败再次出现）在重新激活时把 last_notified_at 置空即可。
//
// 不再有周期性重复提醒：只在首次触发与恢复后再次触发时通知，长期未处理的走每日日报。

const (
	bridgeBatch      = 200
	configCategory   = "notify"
	keyBridgeCutover = "notify_bridge_cutover"
	keyDigestLast    = "notify_digest_last"
	// digestAge 超过多久仍未处理的告警进日报
	digestAge = 24 * time.Hour
	// digestMaxRows 日报单类最多统计的告警条数
	digestMaxRows = 20000
)

// digestCategories 进日报的类别（都来自主告警表）。
var digestCategories = []model.NotifyCategory{
	model.NotifyCategoryDetection, model.NotifyCategoryBaselineAlert, model.NotifyCategoryAgentOffline,
	model.NotifyCategoryInfraAlert, model.NotifyCategoryFIMAlert, model.NotifyCategoryBehaviorAlert,
}

// alertSources 主告警表全部来源，用于由类别反查来源。
var alertSources = []string{
	model.AlertSourceBaseline, model.AlertSourceDetection, model.AlertSourceAgent, model.AlertSourceVulnerability,
	model.AlertSourceFIM, model.AlertSourceVirus, model.AlertSourceKube, model.AlertSourcePrometheusInfra,
	model.AlertSourceBehavior, "",
}

func sourcesOf(category model.NotifyCategory) []string {
	var out []string
	for _, s := range alertSources {
		if notify.AlertSourceCategory(s) == category {
			out = append(out, s)
		}
	}
	return out
}

func (d *Dispatcher) getConfig(key string) (string, bool) {
	var c model.SystemConfig
	if err := d.db.Where("`key` = ? AND category = ?", key, configCategory).First(&c).Error; err != nil {
		return "", false
	}
	return c.Value, true
}

func (d *Dispatcher) setConfig(key, value string) error {
	var c model.SystemConfig
	err := d.db.Where("`key` = ? AND category = ?", key, configCategory).First(&c).Error
	if err == gorm.ErrRecordNotFound {
		return d.db.Create(&model.SystemConfig{Key: key, Category: configCategory, Value: value,
			Description: "告警通知统一出口内部状态"}).Error
	}
	if err != nil {
		return err
	}
	return d.db.Model(&c).Update("value", value).Error
}

// ensureCutover 首次启用桥接时，把此刻已在活跃的告警都视为已通知。
// 否则上线瞬间会把历史上从未通知过的存量活跃告警一次性推到群里。
func (d *Dispatcher) ensureCutover() bool {
	if _, ok := d.getConfig(keyBridgeCutover); ok {
		return true
	}
	now := model.ToLocalTime(d.now())
	res := d.db.Model(&model.Alert{}).
		Where("status = ? AND last_notified_at IS NULL", model.AlertStatusActive).
		Update("last_notified_at", &now)
	if res.Error != nil {
		d.logger.Error("告警通知桥接初始化失败", zap.Error(res.Error))
		return false
	}
	if err := d.setConfig(keyBridgeCutover, d.now().Format(time.RFC3339)); err != nil {
		d.logger.Error("记录告警通知桥接初始化时间失败", zap.Error(err))
		return false
	}
	d.logger.Info("告警通知桥接已初始化，现存活跃告警视为已通知", zap.Int64("alerts", res.RowsAffected))
	return true
}

// BridgeAlerts 把活跃且未通知过的告警转成待通知事件，返回转换条数。
func (d *Dispatcher) BridgeAlerts() int {
	if !d.ensureCutover() {
		return 0
	}
	var rows []model.Alert
	if err := d.db.Where("status = ? AND last_notified_at IS NULL", model.AlertStatusActive).
		Order("id").Limit(bridgeBatch).Find(&rows).Error; err != nil {
		d.logger.Error("读取待通知告警失败", zap.Error(err))
		return 0
	}
	n := 0
	for i := range rows {
		a := &rows[i]
		claimed, err := notify.ClaimAlertNotification(d.db, a.ID, time.Unix(1, 0))
		if err != nil || !claimed {
			continue
		}
		if err := d.enqueue(alertEvent(a)); err != nil {
			d.logger.Error("告警转通知事件失败", zap.Uint("alert_id", a.ID), zap.Error(err))
			// 放回去，下一轮再试
			d.db.Model(&model.Alert{}).Where("id = ?", a.ID).Update("last_notified_at", nil)
			continue
		}
		n++
	}
	return n
}

// alertEvent 由告警表记录构造通知事件。
func alertEvent(a *model.Alert) Event {
	desc := strings.TrimSpace(a.Description)
	var extra []string
	if a.Actual != "" {
		extra = append(extra, "**实际值：** "+a.Actual)
	}
	if a.Expected != "" {
		extra = append(extra, "**期望值：** "+a.Expected)
	}
	if a.FixSuggestion != "" {
		extra = append(extra, "**修复建议：** "+a.FixSuggestion)
	}
	if len(extra) > 0 {
		if desc != "" {
			desc += "\n"
		}
		desc += strings.Join(extra, "\n")
	}
	occurred := a.LastSeenAt.Time()
	if occurred.IsZero() {
		occurred = a.FirstSeenAt.Time()
	}
	return Event{
		Category: notify.AlertSourceCategory(a.Source), Source: a.Source,
		HostID: a.HostID, Severity: a.Severity, Title: a.Title, Description: desc,
		DedupKey: "alert|" + a.ResultID, RefTable: "alerts", RefID: fmt.Sprint(a.ID),
		OccurredAt: occurred,
	}
}

// ResolvedEvent 自动恢复的告警（基线复检通过、Agent 重新上线、基础设施恢复）的恢复通知。
// 只有触发时通知过的告警才发恢复，否则群里会冒出一条从没见过的「已恢复」。
func ResolvedEvent(a *model.Alert) (Event, bool) {
	if a.LastNotifiedAt == nil {
		return Event{}, false
	}
	e := alertEvent(a)
	e.Kind = model.NotifyKindResolved
	e.DedupKey += "|resolved"
	e.OccurredAt = time.Now()
	if a.ResolveReason != "" {
		e.Description = a.ResolveReason
	}
	return e, true
}

// enqueue 直接写待通知事件（桥接与日报用；不经外发，外发由各产出方负责）。
func (d *Dispatcher) enqueue(e Event) error {
	now := d.now()
	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = now
	}
	kind := e.Kind
	if kind == "" {
		kind = model.NotifyKindFiring
	}
	return d.db.Create(&model.AlertNotifyEvent{
		Category: e.Category, Kind: kind, Source: e.Source,
		HostID: e.HostID, Hostname: e.Hostname, IP: e.IP,
		Severity: strings.ToLower(e.Severity), Title: truncate(e.Title, 500), Description: e.Description,
		DedupKey: truncate(e.dedupIdentity(), 255), RefTable: e.RefTable, RefID: e.RefID,
		OccurredAt: occurred, Status: model.NotifyEventPending, NextAttemptAt: now,
	}).Error
}

// digestSchedule 读日报的排期：几点发、是否启用。
//
// 排期与其它后台任务放在同一张表里统一在控制台配置，但日报仍由这里自己发——
// 「当天发过没有」的判断和各渠道的统计都在本包。表里还没有这条（刚升级、调度器尚未补齐）
// 或读失败时按默认时刻发，不因为读不到配置就停发。
func (d *Dispatcher) digestSchedule() (hour int, enabled bool) {
	var job model.ScheduledJob
	if err := d.db.Where("job_key = ?", model.JobKeyAlertDigest).First(&job).Error; err != nil {
		return model.DefaultAlertDigestHour, true
	}
	if job.StartHour < 0 || job.StartHour > 23 {
		return model.DefaultAlertDigestHour, job.Enabled
	}
	return job.StartHour, job.Enabled
}

// maybeScheduleDigest 每天到了设定的时刻后为各类别排一次日报。
func (d *Dispatcher) maybeScheduleDigest() {
	now := d.now().Local()
	hour, enabled := d.digestSchedule()
	if !enabled || now.Hour() < hour {
		return
	}
	today := now.Format("2006-01-02")
	if last, _ := d.getConfig(keyDigestLast); last == today {
		return
	}
	for _, c := range digestCategories {
		if err := d.enqueue(Event{
			Category: c, Kind: model.NotifyKindDigest, Source: "digest",
			Severity: "high", Title: "未处理告警日报", DedupKey: "digest|" + string(c) + "|" + today,
			RefTable: "alerts",
		}); err != nil {
			d.logger.Error("排未处理告警日报失败", zap.String("category", string(c)), zap.Error(err))
			return
		}
	}
	if err := d.setConfig(keyDigestLast, today); err != nil {
		d.logger.Error("记录日报日期失败", zap.Error(err))
	}
	// 回写执行时间只为在控制台上显示，失败不影响日报本身。
	d.db.Model(&model.ScheduledJob{}).Where("job_key = ?", model.JobKeyAlertDigest).Updates(map[string]any{
		"last_run_at": model.ToLocalTime(now), "last_status": model.JobStatusOK, "last_trigger": model.JobTriggerSchedule,
	})
}

// digestStat 一个渠道能看到的未处理告警统计。
type digestStat struct {
	bySeverity map[string]int
	total      int
	oldest     time.Time
}

// processDigest 为每个渠道按它自己的等级与主机范围统计超过 24 小时仍未处理的告警；没有就不发。
func (d *Dispatcher) processDigest(ev *model.AlertNotifyEvent, base *notify.EventMessage) {
	svc, ok := d.notify.(digestNotifier)
	if !ok {
		d.finish(ev, nil)
		return
	}
	channels, err := svc.ChannelsFor(ev.Category)
	if err != nil {
		d.retry(ev, "读取通知配置失败: "+err.Error(), nil)
		return
	}
	if len(channels) == 0 {
		d.finish(ev, []model.NotificationDelivery{d.delivery(ev, nil, model.DeliveryNoRecipient, "")})
		return
	}
	// 逐条取出再在内存里统计：超期的活跃告警数量通常有限；聚合函数的时间列在不同驱动下类型不一，
	// 逐行读取走模型字段解析更稳。上限防止异常积压时一次读太多。
	var rows []struct {
		HostID      string
		Severity    string
		FirstSeenAt model.LocalTime
	}
	err = d.db.Model(&model.Alert{}).
		Select("host_id, severity, first_seen_at").
		Where("status = ? AND first_seen_at < ? AND source IN ?",
			model.AlertStatusActive, model.ToLocalTime(d.now().Add(-digestAge)), sourcesOf(ev.Category)).
		Limit(digestMaxRows).Scan(&rows).Error
	if err != nil {
		d.retry(ev, "统计未处理告警失败: "+err.Error(), nil)
		return
	}

	d.deliverEach(ev, channels, func(ch *model.Notification) (*notify.EventMessage, bool) {
		st := digestStat{bySeverity: map[string]int{}}
		accepts := map[[2]string]bool{}
		for _, r := range rows {
			key := [2]string{r.HostID, r.Severity}
			ok, seen := accepts[key]
			if !seen {
				ok = svc.ChannelAccepts(ch, r.HostID, r.Severity)
				accepts[key] = ok
			}
			if !ok {
				continue
			}
			st.bySeverity[r.Severity]++
			st.total++
			if t := r.FirstSeenAt.Time(); st.oldest.IsZero() || t.Before(st.oldest) {
				st.oldest = t
			}
		}
		if st.total == 0 {
			return nil, false
		}
		msg := *base
		var parts []string
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := st.bySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}[sev], n))
			}
		}
		msg.Title = fmt.Sprintf("超过 24 小时仍未处理的告警 %d 条", st.total)
		msg.Description = fmt.Sprintf("%s。最早一条已持续 %d 天。", strings.Join(parts, "，"), int(d.now().Sub(st.oldest).Hours()/24))
		msg.Severity = highestSeverity(st.bySeverity)
		return &msg, true
	})
}

// digestNotifier 日报需要的额外能力。
type digestNotifier interface {
	ChannelsFor(category model.NotifyCategory) ([]model.Notification, error)
	ChannelAccepts(n *model.Notification, hostID, severity string) bool
}

func highestSeverity(m map[string]int) string {
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if m[s] > 0 {
			return s
		}
	}
	return "low"
}
