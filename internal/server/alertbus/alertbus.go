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
// 发布只做两件事：外发（客户 SIEM）与写入待通知事件表（outbox）。真正的通知由 manager
// 里唯一的 Dispatcher 完成——类别灰度、等级门槛、渠道匹配（含业务线）、跨进程去重、
// 发送、重试与投递记录都在那一处。此前每个进程各自直发、各自在内存去重，
// 多副本时同一告警会被重复通知，发送失败也不留痕迹。
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
)

// Outcome 说明一次发布的去向。发布只负责入队，通知结果见 notification_deliveries。
type Outcome string

const (
	OutcomeQueued     Outcome = "queued"      // 已写入待通知事件表，由 Dispatcher 处理
	OutcomeError      Outcome = "error"       // 写入待通知事件表失败
	OutcomeInvalid    Outcome = "invalid"     // 事件本身不合法（缺必填字段）
	OutcomeEgressOnly Outcome = "egress_only" // 仅外发，通知由 alerts 链路负责
)

// Event 是一条待发布的告警。调用方在写完自己的存储后构造它。
type Event struct {
	// Category 决定投递到哪一类通知配置。
	Category model.NotifyCategory
	// Kind 触发 / 恢复 / 日报，留空按触发。
	Kind string
	// Source 是产出方标识（anomaly / behavior / ad_audit / incident / kube_baseline），
	// 用于指标、日志与投递记录，不参与路由。
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

	// RefTable / RefID 指向告警在各自存储中的位置，决定「查看详情」跳到哪。
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

// Config 控制分发行为。零值即灰度类别"全部关闭"，符合灰度上线的默认姿态。
type Config struct {
	// EnabledCategories 是已灰度开启通知的类别，只对 needsOptIn 的类别生效。**默认全关**。
	//
	// 默认关是刻意的：这些链路此前从未通知过，一次性全开会把值班淹没
	// （未经调优的检测可能一次产出大量误报）。先接链路与抑制，再逐类开。
	// 检测、基线、Agent、基础设施等历来就通知的类别不受此开关约束，否则迁入统一出口后会集体静音。
	EnabledCategories map[model.NotifyCategory]bool
	// MinSeverity 低于此等级不通知，留空按 high。
	MinSeverity string
	// SuppressWindow 同一告警身份对同一渠道在此窗口内只通知一次，<=0 按 30 分钟。
	SuppressWindow time.Duration
}

// needsOptIn 这类告警是否要在 notify_categories 里显式开启才通知。
// kube_alert 同时承载 K8s 运行时告警（历来通知）与 K8s 基线告警（灰度），按来源区分。
func needsOptIn(category model.NotifyCategory, source string) bool {
	switch category {
	case model.NotifyCategoryAnomalyAlert, model.NotifyCategoryBehaviorAlert,
		model.NotifyCategoryADAuditAlert, model.NotifyCategoryIncident:
		return true
	case model.NotifyCategoryKubeAlert:
		return source == "kube_baseline"
	}
	return false
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

// Publisher 是发布点。构造后并发安全。
type Publisher struct {
	db     *gorm.DB
	logger *zap.Logger

	// egress 外发出口（客户自有 SIEM）。可为 nil（未配置）。
	egress Egress

	// now 供测试注入时钟。
	now func() time.Time
}

// New 构造发布点。
func New(db *gorm.DB, logger *zap.Logger) *Publisher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Publisher{db: db, logger: logger, now: time.Now}
}

// WithEgress 注入外发出口。
//
// 外发与通知是两件事：通知叫醒人、可以被抑制；外发是把记录交给客户 SIEM、必须全量。
// 因此外发发生在入队**之前**，不受类别灰度、等级门槛与抑制窗口影响。
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

	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = p.now()
	}
	now := p.now()
	kind := e.Kind
	if kind == "" {
		kind = model.NotifyKindFiring
	}
	row := model.AlertNotifyEvent{
		Category: e.Category, Kind: kind, Source: e.Source,
		HostID: e.HostID, Hostname: e.Hostname, IP: e.IP,
		Severity: strings.ToLower(e.Severity), Title: truncate(e.Title, 500), Description: e.Description,
		DedupKey: truncate(e.dedupIdentity(), 255), RefTable: e.RefTable, RefID: e.RefID,
		OccurredAt: occurred, Status: model.NotifyEventPending, NextAttemptAt: now,
	}
	if p.db == nil {
		p.logger.Error("发布点未配置数据库，告警事件无法入队", zap.String("source", e.Source))
		return p.record(e, OutcomeError)
	}
	if err := p.db.Create(&row).Error; err != nil {
		p.logger.Error("告警事件入队失败",
			zap.String("source", e.Source),
			zap.String("category", string(e.Category)),
			zap.String("host_id", e.HostID),
			zap.Error(err))
		return p.record(e, OutcomeError)
	}
	return p.record(e, OutcomeQueued)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// record 计量并返回去向。
func (p *Publisher) record(e Event, outcome Outcome) Outcome {
	IncPublish(e.Source, string(e.Category), string(outcome))
	return outcome
}

// --- 进程级默认发布点 ---
//
// 产出方分布在 AC / engine / consumer / manager 多个进程，多数拿不到统一的
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

// FromConfig 由 AlertingConfig 构造分发配置。
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
