package alertbus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

// deliverer 是 Dispatcher 对通知服务的依赖，测试可替换。
type deliverer interface {
	EnrichHost(m *notify.EventMessage)
	MatchChannels(m *notify.EventMessage) ([]model.Notification, error)
	DeliverEvent(n *model.Notification, m *notify.EventMessage) error
}

// retryBackoff 发送失败后的重试间隔；用完即放弃并把事件标为 failed。
var retryBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}

const (
	dispatchInterval = 2 * time.Second
	dispatchBatch    = 100
	// claimLease 认领租约。分发一批远小于此时长；进程崩溃后到期，别的实例或重启后可重新认领。
	claimLease = 2 * time.Minute

	cleanupInterval   = time.Hour
	eventRetention    = 7 * 24 * time.Hour
	deliveryRetention = 30 * 24 * time.Hour
)

// Dispatcher 唯一的通知出口：从 alert_notify_events 取事件，决定发给谁、发不发，并记录每一次决定。
// 运行在 manager 进程。
type Dispatcher struct {
	db     *gorm.DB
	logger *zap.Logger
	cfg    Config
	notify deliverer
	now    func() time.Time
}

// NewDispatcher 构造分发器。
func NewDispatcher(db *gorm.DB, logger *zap.Logger, cfg Config) *Dispatcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Dispatcher{db: db, logger: logger, cfg: cfg, notify: notify.NewNotificationService(db, logger), now: time.Now}
}

// Run 循环分发直到 ctx 结束。
func (d *Dispatcher) Run(ctx context.Context) {
	d.logger.Info("告警通知分发器已启动",
		zap.Int("enabled_categories", len(d.cfg.EnabledCategories)),
		zap.String("min_severity", d.cfg.MinSeverity),
		zap.Duration("suppress_window", d.cfg.window()))
	tick := time.NewTicker(dispatchInterval)
	defer tick.Stop()
	lastCleanup, lastDigestCheck := time.Time{}, time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		d.BridgeAlerts()
		for d.DispatchOnce() == dispatchBatch { // 积压时连续处理，不等下一个 tick
			if ctx.Err() != nil {
				return
			}
		}
		if d.now().Sub(lastDigestCheck) >= time.Minute {
			d.maybeScheduleDigest()
			lastDigestCheck = d.now()
		}
		if d.now().Sub(lastCleanup) >= cleanupInterval {
			d.cleanup()
			lastCleanup = d.now()
		}
	}
}

// DispatchOnce 处理一批到期事件，返回处理条数。
func (d *Dispatcher) DispatchOnce() int {
	now := d.now()
	var due []model.AlertNotifyEvent
	err := d.db.Where("(status = ? AND next_attempt_at <= ?) OR (status = ? AND locked_until < ?)",
		model.NotifyEventPending, now, model.NotifyEventProcessing, now).
		Order("id").Limit(dispatchBatch).Find(&due).Error
	if err != nil {
		d.logger.Error("读取待通知事件失败", zap.Error(err))
		return 0
	}
	d.updatePendingGauge()
	n := 0
	for i := range due {
		if !d.claim(&due[i], now) {
			continue // 已被别的实例认领
		}
		d.process(&due[i])
		n++
	}
	return n
}

// claim 条件更新认领事件，保证多实例下同一事件只被处理一次。
func (d *Dispatcher) claim(ev *model.AlertNotifyEvent, now time.Time) bool {
	lease := now.Add(claimLease)
	res := d.db.Model(&model.AlertNotifyEvent{}).
		Where("id = ? AND ((status = ? AND next_attempt_at <= ?) OR (status = ? AND locked_until < ?))",
			ev.ID, model.NotifyEventPending, now, model.NotifyEventProcessing, now).
		Updates(map[string]any{"status": model.NotifyEventProcessing, "locked_until": lease})
	return res.Error == nil && res.RowsAffected == 1
}

func (d *Dispatcher) process(ev *model.AlertNotifyEvent) {
	msg := &notify.EventMessage{
		Category: ev.Category, Kind: ev.Kind, Source: ev.Source, Severity: ev.Severity,
		Title: ev.Title, Description: ev.Description,
		HostID: ev.HostID, Hostname: ev.Hostname, IP: ev.IP,
		OccurredAt: ev.OccurredAt, RefTable: ev.RefTable, RefID: ev.RefID,
	}

	// 灰度类别：先要在 notify_categories 里开启，且不低于全局最低等级。
	// 历来就通知的类别只按各渠道自己的等级配置过滤，不受这两道门槛约束。
	if needsOptIn(ev.Category, ev.Source) {
		if !d.cfg.EnabledCategories[ev.Category] {
			// 未灰度开启：不通知，告警本身已在调用方的存储里，大屏与列表仍可见。
			d.finish(ev, []model.NotificationDelivery{d.delivery(ev, nil, model.DeliveryCategoryDisabled, "")})
			return
		}
		if severityRank[ev.Severity] < d.cfg.minRank() {
			d.finish(ev, []model.NotificationDelivery{d.delivery(ev, nil, model.DeliveryBelowSeverity, "")})
			return
		}
	}
	if ev.Kind == model.NotifyKindDigest {
		d.processDigest(ev, msg)
		return
	}

	d.notify.EnrichHost(msg)
	if msg.Hostname != ev.Hostname || msg.IP != ev.IP {
		// 写回事件行：通知记录页按事件展示主机，桥接入队时只有 host_id
		d.db.Model(&model.AlertNotifyEvent{}).Where("id = ?", ev.ID).
			Updates(map[string]any{"hostname": msg.Hostname, "ip": msg.IP})
	}
	channels, err := d.notify.MatchChannels(msg)
	if err != nil {
		d.retry(ev, "匹配通知配置失败: "+err.Error(), nil)
		return
	}
	if len(channels) == 0 {
		// 类别已开却没有匹配的通知配置：等于开了个通不到人的口子，必须可见。
		d.logger.Warn("告警类别已开启但没有匹配的通知配置",
			zap.String("category", string(ev.Category)), zap.String("severity", ev.Severity))
		d.finish(ev, []model.NotificationDelivery{d.delivery(ev, nil, model.DeliveryNoRecipient, "")})
		return
	}

	d.deliverEach(ev, channels, func(*model.Notification) (*notify.EventMessage, bool) { return msg, true })
}

// deliverEach 对每个渠道去重、发送、记录。msgFor 返回发给该渠道的内容，false 表示该渠道这次不发。
// 有渠道失败则整条事件排期重试，重试时跳过已送达的渠道。
func (d *Dispatcher) deliverEach(ev *model.AlertNotifyEvent, channels []model.Notification,
	msgFor func(ch *model.Notification) (*notify.EventMessage, bool)) {
	var delivered []uint
	d.db.Model(&model.NotificationDelivery{}).
		Where("event_id = ? AND outcome = ?", ev.ID, model.DeliverySent).Pluck("notification_id", &delivered)
	done := make(map[uint]bool, len(delivered))
	for _, id := range delivered {
		done[id] = true
	}

	identity := hashIdentity(ev.DedupKey)
	var records []model.NotificationDelivery
	failed := 0
	lastErr := ""
	for i := range channels {
		ch := &channels[i]
		if done[ch.ID] {
			continue
		}
		msg, ok := msgFor(ch)
		if !ok {
			continue
		}
		claimed, err := d.claimDedup(identity, ch.ID)
		if err != nil {
			failed++
			lastErr = "去重状态写入失败: " + err.Error()
			records = append(records, d.delivery(ev, ch, model.DeliveryFailed, lastErr))
			continue
		}
		if !claimed {
			records = append(records, d.delivery(ev, ch, model.DeliverySuppressed, ""))
			continue
		}
		if err := d.notify.DeliverEvent(ch, msg); err != nil {
			// 发送失败要释放去重占用，否则重试会被自己挡成 suppressed
			d.releaseDedup(identity, ch.ID)
			failed++
			// 落库、进日志之前再脱敏一次：这段文本会进投递记录并经接口返回，
			// 不能指望每个发送实现都记得去掉地址。
			lastErr = notify.RedactURLs(err.Error())
			records = append(records, d.delivery(ev, ch, model.DeliveryFailed, lastErr))
			continue
		}
		records = append(records, d.delivery(ev, ch, model.DeliverySent, ""))
	}

	if failed > 0 {
		d.retry(ev, lastErr, records)
		return
	}
	d.finish(ev, records)
}

// claimDedup 占用 (身份, 渠道) 的一次送达机会：窗口内已送达过则返回 false。
func (d *Dispatcher) claimDedup(identity string, notificationID uint) (bool, error) {
	now := d.now()
	res := d.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.NotificationDedup{
		Identity: identity, NotificationID: notificationID, LastSentAt: now,
	})
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 1 {
		return true, nil
	}
	res = d.db.Model(&model.NotificationDedup{}).
		Where("identity = ? AND notification_id = ? AND last_sent_at <= ?", identity, notificationID, now.Add(-d.cfg.window())).
		Update("last_sent_at", now)
	return res.RowsAffected == 1, res.Error
}

func (d *Dispatcher) releaseDedup(identity string, notificationID uint) {
	d.db.Model(&model.NotificationDedup{}).
		Where("identity = ? AND notification_id = ?", identity, notificationID).
		Update("last_sent_at", time.Unix(0, 0))
}

func (d *Dispatcher) delivery(ev *model.AlertNotifyEvent, ch *model.Notification, outcome, errMsg string) model.NotificationDelivery {
	rec := model.NotificationDelivery{
		EventID: ev.ID, Category: ev.Category, Severity: ev.Severity,
		Title: ev.Title, Outcome: outcome, Error: truncate(errMsg, 500),
	}
	if ch != nil {
		rec.NotificationID = ch.ID
		rec.ChannelName = ch.Name
	}
	IncDelivery(string(ev.Category), outcome)
	return rec
}

func (d *Dispatcher) saveDeliveries(records []model.NotificationDelivery) {
	if len(records) == 0 {
		return
	}
	if err := d.db.Create(&records).Error; err != nil {
		d.logger.Error("写投递记录失败", zap.Error(err))
	}
}

func (d *Dispatcher) finish(ev *model.AlertNotifyEvent, records []model.NotificationDelivery) {
	d.saveDeliveries(records)
	now := d.now()
	d.db.Model(&model.AlertNotifyEvent{}).Where("id = ?", ev.ID).Updates(map[string]any{
		"status": model.NotifyEventDone, "processed_at": &now, "locked_until": nil, "last_error": "",
	})
}

func (d *Dispatcher) retry(ev *model.AlertNotifyEvent, errMsg string, records []model.NotificationDelivery) {
	d.saveDeliveries(records)
	attempts := ev.Attempts + 1
	updates := map[string]any{"attempts": attempts, "last_error": truncate(errMsg, 500), "locked_until": nil}
	if attempts > len(retryBackoff) {
		now := d.now()
		updates["status"] = model.NotifyEventFailed
		updates["processed_at"] = &now
		d.logger.Error("告警通知多次发送失败，已放弃",
			zap.Uint("event_id", ev.ID), zap.String("category", string(ev.Category)), zap.String("error", errMsg))
	} else {
		updates["status"] = model.NotifyEventPending
		updates["next_attempt_at"] = d.now().Add(retryBackoff[attempts-1])
	}
	d.db.Model(&model.AlertNotifyEvent{}).Where("id = ?", ev.ID).Updates(updates)
}

// cleanup 删除过期的事件、投递记录与去重状态，避免无界增长。
func (d *Dispatcher) cleanup() {
	now := d.now()
	d.db.Where("status IN ? AND created_at < ?", []string{model.NotifyEventDone, model.NotifyEventFailed}, now.Add(-eventRetention)).
		Delete(&model.AlertNotifyEvent{})
	d.db.Where("created_at < ?", now.Add(-deliveryRetention)).Delete(&model.NotificationDelivery{})
	d.db.Where("last_sent_at < ?", now.Add(-eventRetention)).Delete(&model.NotificationDedup{})
}

func (d *Dispatcher) updatePendingGauge() {
	var n int64
	if d.db.Model(&model.AlertNotifyEvent{}).Where("status IN ?", []string{model.NotifyEventPending, model.NotifyEventProcessing}).Count(&n).Error == nil {
		pendingEvents.Set(float64(n))
	}
}

func hashIdentity(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}
