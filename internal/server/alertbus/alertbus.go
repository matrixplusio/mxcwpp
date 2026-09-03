// Package alertbus 是检测产出通往通知渠道的统一发布点。
//
// 背景：平台有七处告警存储，其中五处（K8s 基线告警、ML 异常、行为基线、AD 审计、
// 关联事件）**没有任何通知出口**——检测跑了、写进表了、值班不知道。它们各自的写入方
// 也无从复用 alerts 那条链路，因为通知逻辑与 alerts 表和 baseline_alert 类别绑死。
//
// 本包只统一**出口**，不统一存储：各检测的表结构差异是真实的（行为基线要画像、
// 异常要模型分与证据、关联事件要成员列表），硬合会丢信息。调用方照常写自己的表，
// 写完再发布一条 Event。
//
// 中立包：只依赖 model 与 notify，不反向依赖 manager/biz，供 AC / engine / consumer /
// manager 共用。
package alertbus

import (
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

// Outcome 说明一次发布的去向。
//
// 刻意不用 (bool, error)：绝大多数"没发出去"既不是成功也不是错误，而是被某条规则挡下。
// 把原因收敛成 bool 会让"类别没开"和"发送失败"看起来一样，运维无法判断是配置问题
// 还是链路故障——正是本项目反复出现的那类静默失败。
type Outcome string

const (
	OutcomeNotified         Outcome = "notified"          // 已送达至少一个通知配置
	OutcomeCategoryDisabled Outcome = "category_disabled" // 该类别未灰度开启
	OutcomeBelowSeverity    Outcome = "below_severity"    // 低于最低通知等级
	OutcomeSuppressed       Outcome = "suppressed"        // 抑制窗口内的重复告警
	OutcomeNoRecipient      Outcome = "no_recipient"      // 类别已开但没有匹配的通知配置
	OutcomeError            Outcome = "error"             // 发送过程出错
	OutcomeInvalid          Outcome = "invalid"           // 事件本身不合法（缺必填字段）
	OutcomeEgressOnly       Outcome = "egress_only"       // 仅外发，通知由 alerts 链路负责
)

// Event 是一条待发布的告警。调用方在写完自己的存储后构造它。
type Event struct {
	// Category 决定投递到哪一类通知配置。
	Category model.NotifyCategory
	// Source 是产出方标识（anomaly / behavior / ad_audit / incident / kube_baseline），
	// 仅用于指标与日志，不参与路由。
	Source string

	HostID   string
	Hostname string
	IP       string

	Severity    string // critical / high / medium / low
	Title       string
	Description string

	// DedupKey 是这条告警的稳定身份，抑制窗口按它去重。
	// 留空则退化为按 Source+HostID+Title 组合，避免调用方漏填导致完全不抑制。
	DedupKey string

	// RefTable / RefID 指向告警在各自存储中的位置，供通知内容附带跳转。
	RefTable string
	RefID    string

	OccurredAt time.Time

	// EgressOnly 表示这条告警的通知已由别处负责，本次只需外发。
	//
	// alerts 表那条链路自带通知（AgentCenter 内联 + Manager 定时器，经
	// last_notified_at 协调）。把它们也接进来是为了让外发覆盖全部告警源——
	// 只导一部分会让客户 SIEM 出现看不见的缺口，比不导更危险。
	// 但通知不能走两遍，否则值班对同一条告警收到两次。
	EgressOnly bool
}

// dedupIdentity 返回用于抑制的稳定身份。
func (e *Event) dedupIdentity() string {
	if k := strings.TrimSpace(e.DedupKey); k != "" {
		return k
	}
	return e.Source + "|" + e.HostID + "|" + e.Title
}

// severityRank 把等级映射为可比较的序，未知等级按最低处理（宁可不打扰，也不误发）。
var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// Config 控制发布行为。零值即"全部关闭"，符合灰度上线的默认姿态。
type Config struct {
	// EnabledCategories 是已灰度开启通知的类别。**默认全关**。
	//
	// 默认关是刻意的：这些链路此前从未通知过，一次性全开会把值班淹没
	// （ML 异常曾一次产出数千条 critical 假信标）。先接链路与抑制，再逐类开。
	EnabledCategories map[model.NotifyCategory]bool
	// MinSeverity 低于此等级不通知，留空按 high。
	MinSeverity string
	// SuppressWindow 相同 DedupKey 在此窗口内只通知一次，<=0 按 30 分钟。
	SuppressWindow time.Duration
}

func (c Config) minRank() int {
	if r, ok := severityRank[strings.ToLower(strings.TrimSpace(c.MinSeverity))]; ok {
		return r
	}
	return severityRank["high"]
}

func (c Config) window() time.Duration {
	if c.SuppressWindow > 0 {
		return c.SuppressWindow
	}
	return 30 * time.Minute
}

// notifier 抽象通知发送，便于测试替换。
type notifier interface {
	SendCategoryAlertNotification(category model.NotifyCategory, alertData *notify.AlertData) (bool, error)
}

// Publisher 是发布点。构造后并发安全。
type Publisher struct {
	logger   *zap.Logger
	cfg      Config
	notifier notifier

	// egress 外发出口（客户自有 SIEM）。可为 nil（未配置）。
	egress Egress

	mu   sync.Mutex
	seen map[string]time.Time // dedupIdentity → 上次通知时间

	// now 供测试注入时钟。
	now func() time.Time
}

// New 构造发布点。
//
// 抑制状态目前保存在进程内：多副本部署时每个副本各自抑制，同一告警最多被通知
// 副本数次。这是已知的降级，不是可以忽略的细节——接入 Redis 抑制前，灰度开启
// 类别时需要把副本数计入通知量预估。
func New(db *gorm.DB, logger *zap.Logger, cfg Config) *Publisher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Publisher{
		logger:   logger,
		cfg:      cfg,
		notifier: notify.NewNotificationService(db, logger),
		seen:     make(map[string]time.Time),
		now:      time.Now,
	}
}

// WithEgress 注入外发出口。
//
// 外发与通知是两件事：通知叫醒人、可以被抑制；外发是把记录交给客户 SIEM、必须全量。
// 因此外发发生在所有通知门槛**之前**，不受类别灰度、等级门槛与抑制窗口影响。
func (p *Publisher) WithEgress(e Egress) *Publisher {
	p.egress = e
	return p
}

// Publish 发布一条告警，返回它的去向。
//
// 永远不返回 error：调用方已经把告警写进了自己的存储，通知失败不应回滚业务流程。
// 失败通过 Outcome 与指标暴露。
func (p *Publisher) Publish(e Event) Outcome {
	if e.Category == "" || strings.TrimSpace(e.Title) == "" {
		p.logger.Error("拒绝发布不合法的告警事件（缺少 category 或 title）",
			zap.String("source", e.Source), zap.String("host_id", e.HostID))
		return p.record(e, OutcomeInvalid)
	}

	// 外发先行且不受门槛限制：抑制是为了少打扰人，不是为了让客户 SIEM 少收记录。
	// 若外发也走抑制，客户侧就会出现平台单方面造成的缺口，而他们无从知道少了什么。
	if p.egress != nil {
		p.egress.Forward(e)
	}

	if e.EgressOnly {
		// 通知由 alerts 表那条链路负责，此处只做外发。
		return p.record(e, OutcomeEgressOnly)
	}

	if !p.cfg.EnabledCategories[e.Category] {
		// 未灰度开启：不通知，但告警本身已在调用方的存储里，大屏与列表仍可见。
		return p.record(e, OutcomeCategoryDisabled)
	}

	if severityRank[strings.ToLower(e.Severity)] < p.cfg.minRank() {
		return p.record(e, OutcomeBelowSeverity)
	}

	if p.suppressed(e.dedupIdentity()) {
		return p.record(e, OutcomeSuppressed)
	}

	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = p.now()
	}
	sent, err := p.notifier.SendCategoryAlertNotification(e.Category, &notify.AlertData{
		HostID:      e.HostID,
		Hostname:    e.Hostname,
		IP:          e.IP,
		Category:    string(e.Category),
		Severity:    e.Severity,
		Title:       e.Title,
		Description: e.Description,
		RuleID:      e.RefTable,
		ResultID:    e.RefID,
		CheckedAt:   occurred,
	})
	if err != nil {
		p.logger.Error("发送告警通知失败",
			zap.String("source", e.Source),
			zap.String("category", string(e.Category)),
			zap.String("host_id", e.HostID),
			zap.Error(err))
		return p.record(e, OutcomeError)
	}
	if !sent {
		// 类别已开却没有任何匹配的通知配置：等于开了个通不到人的口子，必须可见。
		p.logger.Warn("告警类别已开启但没有匹配的通知配置，本条未送达任何接收方",
			zap.String("source", e.Source),
			zap.String("category", string(e.Category)),
			zap.String("severity", e.Severity))
		return p.record(e, OutcomeNoRecipient)
	}

	p.markNotified(e.dedupIdentity())
	return p.record(e, OutcomeNotified)
}

// suppressed 判断该身份是否仍在抑制窗口内。
func (p *Publisher) suppressed(identity string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	last, ok := p.seen[identity]
	return ok && p.now().Sub(last) < p.cfg.window()
}

// markNotified 记录通知时间，并顺带清理过期条目，避免 map 无界增长。
func (p *Publisher) markNotified(identity string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.seen[identity] = now
	window := p.cfg.window()
	for k, t := range p.seen {
		if now.Sub(t) >= window {
			delete(p.seen, k)
		}
	}
}

// record 计量并返回去向。
func (p *Publisher) record(e Event, outcome Outcome) Outcome {
	IncPublish(e.Source, string(e.Category), string(outcome))
	return outcome
}

// --- 进程级默认发布点 ---
//
// 产出方分布在 AC / engine / consumer / manager 三类进程、五处写入点，多数拿不到统一的
// 构造入口。把 Publisher 穿过每条构造链，只要漏掉一处，那条检测就继续没有出口——正是
// 本包要消灭的失效。因此按进程设一次，产出方直接调用包级 Publish。

var (
	defaultMu sync.RWMutex
	defaultP  *Publisher
)

// SetDefault 由持有配置的进程初始化调用一次。
func SetDefault(p *Publisher) {
	defaultMu.Lock()
	defaultP = p
	defaultMu.Unlock()
}

// OutcomeNoPublisher 表示所在进程没有初始化发布点。
//
// 单独一个去向而不是静默返回：产出方以为自己已经接上了通知，实际所在进程根本没配
// 发布点——这种"看着接线了其实没有"必须能从指标上直接看出来。
const OutcomeNoPublisher Outcome = "no_publisher"

// Publish 经进程默认发布点发布告警。未初始化时计量并返回 OutcomeNoPublisher。
func Publish(e Event) Outcome {
	defaultMu.RLock()
	p := defaultP
	defaultMu.RUnlock()
	if p == nil {
		IncPublish(e.Source, string(e.Category), string(OutcomeNoPublisher))
		return OutcomeNoPublisher
	}
	return p.Publish(e)
}

// FromConfig 由 AlertingConfig 构造发布点配置。
// 未在 notifyCategories 中列出的类别一律不通知。
func FromConfig(notifyCategories []string, minSeverity string, suppressWindowMinutes int) Config {
	enabled := make(map[model.NotifyCategory]bool, len(notifyCategories))
	for _, c := range notifyCategories {
		if c = strings.TrimSpace(c); c != "" {
			enabled[model.NotifyCategory(c)] = true
		}
	}
	return Config{
		EnabledCategories: enabled,
		MinSeverity:       minSeverity,
		SuppressWindow:    time.Duration(suppressWindowMinutes) * time.Minute,
	}
}
