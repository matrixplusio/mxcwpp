package model

import "time"

// 告警通知统一出口的三张表。
//
// 各服务只往 AlertNotifyEvent 写一行（发布），由 manager 里唯一的分发器负责匹配渠道、
// 去重、发送、重试，并为每次决定写一条 NotificationDelivery。此前通知散落在四个服务、
// 十几处直接 POST，去重有五套、没有任何投递记录，「测试能发、真实告警没发出去」无从发现。

// 事件类型：触发、恢复、未处理告警日报。
const (
	NotifyKindFiring   = "firing"
	NotifyKindResolved = "resolved"
	NotifyKindDigest   = "digest"
)

// 发布事件的处理状态。
const (
	NotifyEventPending    = "pending"
	NotifyEventProcessing = "processing"
	NotifyEventDone       = "done"
	NotifyEventFailed     = "failed" // 重试次数耗尽
)

// AlertNotifyEvent 一条待通知的告警事件（outbox）。
type AlertNotifyEvent struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;default:'t-default'" json:"tenant_id"`

	Category    NotifyCategory `gorm:"column:category;type:varchar(30);not null" json:"category"`
	Kind        string         `gorm:"column:kind;type:varchar(16);not null;default:'firing'" json:"kind"`
	Source      string         `gorm:"column:source;type:varchar(50)" json:"source"`
	HostID      string         `gorm:"column:host_id;type:varchar(128);index" json:"host_id"`
	Hostname    string         `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	IP          string         `gorm:"column:ip;type:varchar(255)" json:"ip"`
	Severity    string         `gorm:"column:severity;type:varchar(20)" json:"severity"`
	Title       string         `gorm:"column:title;type:varchar(500)" json:"title"`
	Description string         `gorm:"column:description;type:text" json:"description"`
	// DedupKey 告警的稳定身份；同一渠道在抑制窗口内只收一次
	DedupKey string `gorm:"column:dedup_key;type:varchar(255)" json:"dedup_key"`
	// RefTable / RefID 指向告警原始记录，决定「查看详情」跳到哪
	RefTable   string    `gorm:"column:ref_table;type:varchar(64)" json:"ref_table"`
	RefID      string    `gorm:"column:ref_id;type:varchar(128)" json:"ref_id"`
	OccurredAt time.Time `gorm:"column:occurred_at" json:"occurred_at"`

	Status        string    `gorm:"column:status;type:varchar(16);not null;default:'pending';index:idx_notify_event_due,priority:1" json:"status"`
	NextAttemptAt time.Time `gorm:"column:next_attempt_at;index:idx_notify_event_due,priority:2" json:"next_attempt_at"`
	Attempts      int       `gorm:"column:attempts;default:0" json:"attempts"`
	LastError     string    `gorm:"column:last_error;type:varchar(500)" json:"last_error"`
	// LockedUntil 分发器认领后的租约；进程崩溃时到期自动释放，不会永久卡在 processing
	LockedUntil *time.Time `gorm:"column:locked_until" json:"locked_until,omitempty"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime;index" json:"created_at"`
	ProcessedAt *time.Time `gorm:"column:processed_at" json:"processed_at,omitempty"`
}

func (AlertNotifyEvent) TableName() string { return "alert_notify_events" }

// 投递结果。除 sent / failed 外都是「没发」的原因，单列出来才分得清是配置问题还是链路故障。
const (
	DeliverySent             = "sent"
	DeliveryFailed           = "failed"
	DeliverySuppressed       = "suppressed"        // 抑制窗口内已发过
	DeliveryCategoryDisabled = "category_disabled" // 类别未灰度开启
	DeliveryBelowSeverity    = "below_severity"    // 低于全局最低通知等级
	DeliveryNoRecipient      = "no_recipient"      // 没有匹配的通知配置
)

// NotificationDelivery 分发器对一条事件、一个渠道做出的一次决定。
// 没有匹配到任何渠道时也写一条（NotificationID=0），否则「为什么没收到」无迹可查。
type NotificationDelivery struct {
	ID             uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID       string         `gorm:"column:tenant_id;type:varchar(64);not null;default:'t-default'" json:"tenant_id"`
	EventID        uint           `gorm:"column:event_id;not null;index" json:"event_id"`
	NotificationID uint           `gorm:"column:notification_id;index" json:"notification_id"`
	ChannelName    string         `gorm:"column:channel_name;type:varchar(100)" json:"channel_name"`
	Category       NotifyCategory `gorm:"column:category;type:varchar(30)" json:"category"`
	Severity       string         `gorm:"column:severity;type:varchar(20)" json:"severity"`
	Title          string         `gorm:"column:title;type:varchar(500)" json:"title"`
	Outcome        string         `gorm:"column:outcome;type:varchar(30);not null;index" json:"outcome"`
	Error          string         `gorm:"column:error;type:varchar(500)" json:"error"`
	CreatedAt      time.Time      `gorm:"column:created_at;autoCreateTime;index" json:"created_at"`
}

func (NotificationDelivery) TableName() string { return "notification_deliveries" }

// NotificationDedup 每个 (告警身份, 渠道) 最近一次送达时间。
// 存库而不是进程内存：通知原先在四个服务、多个副本各自抑制，同一条告警能被重复通知。
type NotificationDedup struct {
	ID             uint      `gorm:"primaryKey;autoIncrement"`
	TenantID       string    `gorm:"column:tenant_id;type:varchar(64);not null;default:'t-default'"`
	Identity       string    `gorm:"column:identity;type:char(64);not null;uniqueIndex:uk_notify_dedup,priority:1"` // sha256(dedup key)
	NotificationID uint      `gorm:"column:notification_id;not null;uniqueIndex:uk_notify_dedup,priority:2"`
	LastSentAt     time.Time `gorm:"column:last_sent_at;not null;index"`
}

func (NotificationDedup) TableName() string { return "notification_dedups" }
