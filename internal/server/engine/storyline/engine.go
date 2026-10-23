// Package storyline aggregates Agent-side story_id-tagged events into
// attack storylines on the Server. Each storyline groups causally related
// events on a single host, tracks severity escalation, and persists
// timeline data for SOC investigation.
package storyline

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// flushInterval controls how often in-memory storylines are checkpointed to DB.
	flushInterval = 30 * time.Second
	// staleTimeout marks storylines as stale (no new events) for cleanup.
	staleTimeout = 30 * time.Minute
	// maxEventsPerStory 单条故事线最多落库的明细事件数。
	//
	// 与规则无关的兜底：达到上限后仍累计计数、仍更新 storylines 元数据（严重度、
	// 风险分、命中规则、last_seen 都照常演进），只是不再往 storyline_events 追加明细。
	//
	// 为什么必须有：常驻进程的单条故事线会无限延续、明细无界增长。
	// 已有的 pendingEvts 上限只约束"单次 flush 窗口内"的条数（500），
	// 对总量没有任何约束——每 30 秒刷 500 条，时间一长明细量就失控。
	// 一条攻击叙事需要的是首尾与关键节点，不是把进程一生的每个系统调用抄一遍；
	// 上限之后的明细对研判无增量价值，却能独力写满存储。
	maxEventsPerStory = 10000

	// closeAfter 故事线多久没有新事件就在库里关闭。
	//
	// 内存里 staleTimeout 后就不再聚合，但库里状态从不变化，active 只增不减：
	// 计数与事件关联都按 active 取，表越大越慢，事件里挂的故事线 ID 也越攒越多。
	// 取 staleTimeout 的两倍，保证还在内存里聚合的故事线不会被关掉。
	closeAfter = 2 * staleTimeout
	// closeBatch / closeMaxBatches 每次刷盘最多关闭的行数，存量积压分多轮消化，不长时间持锁。
	closeBatch      = 5000
	closeMaxBatches = 20
)

// storyState holds in-memory state for an active storyline.
type storyState struct {
	mu          sync.Mutex
	storyID     string
	hostID      string
	hostname    string
	severity    string
	phase       string
	ruleNames   map[string]struct{}
	eventCount  int
	alertCount  int
	riskScore   float64
	firstSeen   time.Time
	lastSeen    time.Time
	dirty       bool
	pendingEvts []model.StorylineEvent
	// cappedLogged 保证"已达明细上限"只警告一次，不随每条事件刷屏。
	cappedLogged bool
	// reopen 新进内存的故事线首次落库时，库里可能是已被关闭的同一 story_id，需要重新打开。
	reopen bool
}

// Engine aggregates story_id-tagged events into attack storylines.
//
// storylines 元数据始终写 MySQL (OLTP, frequently updated)
// storyline_events 按 feature_flag.data_source.storyline_events 路由
// 到 MySQL 或 ClickHouse。chConn 为 nil 时强制走 MySQL。
type Engine struct {
	mu      sync.RWMutex
	stories map[string]*storyState // story_id → state
	db      *gorm.DB
	chConn  chdriver.Conn // 可为 nil
	logger  *zap.Logger

	// eventsTarget 缓存当前 events 写入目标 ("mysql" / "ch")，由 consumer 启动时读
	// feature_flag.data_source.storyline_events 设置。运行时不动态变更，需重启进程生效。
	eventsTarget string
}

// NewEngine creates a storyline aggregation engine.
func NewEngine(db *gorm.DB, logger *zap.Logger) *Engine {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Engine{
		stories:      make(map[string]*storyState),
		db:           db,
		logger:       logger,
		eventsTarget: "mysql",
	}
}

// SetClickHouse 注入 CH 连接（启动时一次）。
func (e *Engine) SetClickHouse(conn chdriver.Conn) {
	e.chConn = conn
}

// SetEventsTarget 设置 storyline_events 写入目标 ("mysql" 或 "ch")。
// 若设为 "ch" 但 chConn 为 nil，writeStorylineEvents 会自动回落 mysql。
func (e *Engine) SetEventsTarget(target string) {
	switch target {
	case "mysql", "ch":
		e.eventsTarget = target
	default:
		e.eventsTarget = "mysql"
	}
}

// Ingest processes an event with a story_id.
// Called from the consumer router for events carrying story_id field.
func (e *Engine) Ingest(storyID, hostID, hostname string, dataType int32, fields map[string]string) {
	st := e.getOrCreate(storyID, hostID, hostname)
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	st.lastSeen = now
	st.eventCount++
	st.dirty = true
	// 超限后只维护聚合态，不再收集明细（见 maxEventsPerStory）。
	detailCapped := st.eventCount > maxEventsPerStory
	if detailCapped && !st.cappedLogged {
		st.cappedLogged = true
		e.logger.Warn("故事线明细已达上限，后续只累计计数不再落明细",
			zap.String("story_id", st.storyID),
			zap.String("host_id", st.hostID),
			zap.Int("cap", maxEventsPerStory))
	}

	// Track matched rules.
	isAlert := false
	ruleName := fields["agent_rule_name"]
	if ruleName != "" {
		st.ruleNames[ruleName] = struct{}{}
		st.alertCount++
		isAlert = true
	}

	// Escalate severity.
	severity := fields["agent_severity"]
	if severityRank(severity) > severityRank(st.severity) {
		st.severity = severity
	}

	// Track MITRE phase.
	if tactic := fields["agent_mitre_tactic"]; tactic != "" {
		st.phase = tactic
	}

	// Update risk score based on alert density.
	if st.eventCount > 0 {
		alertRatio := float64(st.alertCount) / float64(st.eventCount)
		st.riskScore = alertRatio * 100 * severityMultiplier(st.severity)
		if st.riskScore > 100 {
			st.riskScore = 100
		}
	}

	// 明细超限：聚合态已在上方更新完毕，此处直接返回，
	// 不再构造 StorylineEvent（省掉热路径上的 detail 序列化与分配）。
	if detailCapped {
		return
	}

	// Build denormalized event detail (key fields for timeline).
	detail := buildDetail(dataType, fields)

	evt := model.StorylineEvent{
		StoryID:   storyID,
		HostID:    hostID,
		DataType:  dataType,
		EventType: fields["event_type"],
		PID:       fields["pid"],
		Exe:       fields["exe"],
		Detail:    detail,
		Timestamp: model.LocalTime(now),
	}
	if isAlert {
		evt.RuleName = ruleName
		evt.Severity = severity
	}

	// P1-6: pendingEvts 上限保护, 防止单 story 内存爆 (高频 30s flush 间隔内可能数千事件).
	const maxPendingEvts = 500
	if len(st.pendingEvts) < maxPendingEvts {
		st.pendingEvts = append(st.pendingEvts, evt)
	} else {
		// drop oldest 半窗口, 保留最新
		copy(st.pendingEvts, st.pendingEvts[maxPendingEvts/2:])
		st.pendingEvts = st.pendingEvts[:maxPendingEvts/2]
		st.pendingEvts = append(st.pendingEvts, evt)
	}
}

// P1-6: storyline map 上限 (LRU 风格 — flush 时按 lastSeen 淘汰过老 story).
//
// 与 stale TTL 配合: stale 是按时间, capacity 是按数量. 防长会话 + 海量 story_id 内存爆.
const maxStories = 10000

// StartFlush starts a background goroutine that periodically flushes dirty storylines to DB.
func (e *Engine) StartFlush(done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				e.flush()
				return
			case <-ticker.C:
				e.flush()
			}
		}
	}()
}

func (e *Engine) getOrCreate(storyID, hostID, hostname string) *storyState {
	e.mu.RLock()
	st, ok := e.stories[storyID]
	e.mu.RUnlock()
	if ok {
		return st
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if st, ok = e.stories[storyID]; ok {
		return st
	}
	// P1-6: 容量到上限, 淘汰最老 (lastSeen 最早) 1 个
	if len(e.stories) >= maxStories {
		var oldestID string
		var oldestT time.Time
		for id, s := range e.stories {
			if oldestID == "" || s.lastSeen.Before(oldestT) {
				oldestID = id
				oldestT = s.lastSeen
			}
		}
		if oldestID != "" {
			delete(e.stories, oldestID)
			e.logger.Debug("storyline LRU evict",
				zap.String("evicted_id", oldestID),
				zap.Time("last_seen", oldestT))
		}
	}
	st = &storyState{
		storyID:   storyID,
		hostID:    hostID,
		hostname:  hostname,
		severity:  "low",
		ruleNames: make(map[string]struct{}),
		firstSeen: time.Now(),
		lastSeen:  time.Now(),
		reopen:    true,
	}
	e.stories[storyID] = st
	return st
}

// flush persists all dirty storylines and their events to DB.
func (e *Engine) flush() {
	e.mu.RLock()
	var dirty []*storyState
	var stale []string
	cutoff := time.Now().Add(-staleTimeout)
	for sid, st := range e.stories {
		st.mu.Lock()
		if st.dirty {
			dirty = append(dirty, st)
		}
		if st.lastSeen.Before(cutoff) {
			stale = append(stale, sid)
		}
		st.mu.Unlock()
	}
	e.mu.RUnlock()

	for _, st := range dirty {
		e.persistStory(st)
	}

	// Evict stale storylines from memory (already persisted).
	if len(stale) > 0 {
		e.mu.Lock()
		for _, sid := range stale {
			delete(e.stories, sid)
		}
		e.mu.Unlock()
	}

	e.closeInactive(time.Now().Add(-closeAfter))
}

// closeInactive 把 cutoff 之前就没有新事件的 active 故事线置为 closed。
//
// 按库里的 last_seen_at 判断而不是按内存：进程重启后内存清空，只靠内存淘汰
// 会让重启前的故事线永远停在 active。先取 id 再按 id 更新，sqlite 与 MySQL 通用；
// 更新时再带一次时间条件，期间刚好有新事件落库的不会被误关。
func (e *Engine) closeInactive(cutoff time.Time) {
	var total int64
	for range closeMaxBatches {
		var ids []uint
		if err := e.db.Model(&model.Storyline{}).
			Where("status = ? AND last_seen_at < ?", model.StorylineStatusActive, cutoff).
			Limit(closeBatch).Pluck("id", &ids).Error; err != nil {
			e.logger.Warn("查询待关闭故事线失败", zap.Error(err))
			return
		}
		if len(ids) == 0 {
			break
		}
		res := e.db.Model(&model.Storyline{}).
			Where("id IN ? AND status = ? AND last_seen_at < ?", ids, model.StorylineStatusActive, cutoff).
			Update("status", model.StorylineStatusClosed)
		if res.Error != nil {
			e.logger.Warn("关闭故事线失败", zap.Error(res.Error))
			return
		}
		total += res.RowsAffected
		if len(ids) < closeBatch {
			break
		}
	}
	if total > 0 {
		e.logger.Info("已关闭长时间无新事件的故事线", zap.Int64("closed", total))
	}
}

func (e *Engine) persistStory(st *storyState) {
	st.mu.Lock()
	ruleList := make([]string, 0, len(st.ruleNames))
	for r := range st.ruleNames {
		ruleList = append(ruleList, r)
	}
	record := model.Storyline{
		StoryID:     st.storyID,
		HostID:      st.hostID,
		Hostname:    st.hostname,
		Severity:    st.severity,
		Phase:       st.phase,
		RuleNames:   strings.Join(ruleList, ","),
		EventCount:  st.eventCount,
		AlertCount:  st.alertCount,
		RiskScore:   st.riskScore,
		FirstSeenAt: model.LocalTime(st.firstSeen),
		LastSeenAt:  model.LocalTime(st.lastSeen),
	}
	events := make([]model.StorylineEvent, len(st.pendingEvts))
	copy(events, st.pendingEvts)
	st.pendingEvts = st.pendingEvts[:0]
	st.dirty = false
	reopen := st.reopen
	st.reopen = false
	st.mu.Unlock()

	// Upsert storyline.
	result := e.db.Where("story_id = ?", record.StoryID).
		Assign(model.Storyline{
			Severity:   record.Severity,
			Phase:      record.Phase,
			RuleNames:  record.RuleNames,
			EventCount: record.EventCount,
			AlertCount: record.AlertCount,
			RiskScore:  record.RiskScore,
			LastSeenAt: record.LastSeenAt,
		}).
		FirstOrCreate(&record)
	if result.Error != nil {
		e.logger.Warn("持久化故事线失败", zap.String("story_id", record.StoryID), zap.Error(result.Error))
		return
	}
	// 同一 story_id 停了一阵又来事件：库里那条可能已被关闭，重新打开。
	// 只动 closed，人工处置过的 resolved 不被自动改回。
	if reopen {
		if err := e.db.Model(&model.Storyline{}).
			Where("story_id = ? AND status = ?", record.StoryID, model.StorylineStatusClosed).
			Update("status", model.StorylineStatusActive).Error; err != nil {
			e.logger.Warn("重新打开故事线失败", zap.String("story_id", record.StoryID), zap.Error(err))
		}
	}

	// Batch insert events — 按 eventsTarget 路由到 MySQL 或 ClickHouse
	if len(events) > 0 {
		e.writeStorylineEvents(record.StoryID, events)
	}
}

// writeStorylineEvents 按 feature flag 路由把 events 写到 MySQL 或 ClickHouse。
//
// 当前限制：
//   - ch 路径不写 id 列（CH MergeTree 不需要 auto increment）
//   - 失败仅 warn，不重试（事件类，可丢忍）
//   - 不支持双写
func (e *Engine) writeStorylineEvents(storyID string, events []model.StorylineEvent) {
	if e.eventsTarget == "ch" && e.chConn != nil {
		if err := e.writeStorylineEventsCH(events); err != nil {
			e.logger.Warn("持久化故事线事件 (CH) 失败，回落 MySQL",
				zap.String("story_id", storyID), zap.Int("count", len(events)), zap.Error(err))
			// 回落 MySQL，保证不丢
			if err := e.db.CreateInBatches(events, 100).Error; err != nil {
				e.logger.Warn("持久化故事线事件 (MySQL fallback) 失败",
					zap.String("story_id", storyID), zap.Error(err))
			}
		}
		return
	}
	if err := e.db.CreateInBatches(events, 100).Error; err != nil {
		e.logger.Warn("持久化故事线事件失败", zap.String("story_id", storyID), zap.Error(err))
	}
}

// writeStorylineEventsCH 批量 INSERT 到 ClickHouse storyline_events 表。
func (e *Engine) writeStorylineEventsCH(events []model.StorylineEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	batch, err := e.chConn.PrepareBatch(ctx,
		"INSERT INTO storyline_events (id, story_id, host_id, data_type, event_type, pid, exe, detail, rule_name, severity, timestamp, created_at)")
	if err != nil {
		return err
	}
	for _, ev := range events {
		ts := time.Time(ev.Timestamp)
		ct := time.Time(ev.CreatedAt)
		if ts.IsZero() {
			ts = time.Now()
		}
		if ct.IsZero() {
			ct = ts
		}
		if err := batch.Append(
			uint64(ev.ID),
			ev.StoryID, ev.HostID,
			int32(ev.DataType), ev.EventType,
			ev.PID, ev.Exe, ev.Detail, ev.RuleName, ev.Severity,
			ts, ct,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func severityMultiplier(s string) float64 {
	switch s {
	case "critical":
		return 1.0
	case "high":
		return 0.8
	case "medium":
		return 0.5
	default:
		return 0.3
	}
}

func buildDetail(dataType int32, fields map[string]string) string {
	detail := make(map[string]string)
	// Include event-type-specific key fields.
	switch dataType {
	case 3000: // process
		for _, k := range []string{"ppid", "cmdline", "uid", "cwd"} {
			if v := fields[k]; v != "" {
				detail[k] = v
			}
		}
	case 3001: // file
		for _, k := range []string{"file_path", "file_action"} {
			if v := fields[k]; v != "" {
				detail[k] = v
			}
		}
	case 3002: // network
		for _, k := range []string{"remote_addr", "remote_port", "protocol"} {
			if v := fields[k]; v != "" {
				detail[k] = v
			}
		}
	case 3003: // DNS
		for _, k := range []string{"domain", "rcode"} {
			if v := fields[k]; v != "" {
				detail[k] = v
			}
		}
	}
	// Add IOC info if present.
	if fields["ioc_match"] == "true" {
		detail["ioc_type"] = fields["ioc_type"]
		detail["ioc_value"] = fields["ioc_value"]
	}
	b, _ := json.Marshal(detail)
	return string(b)
}
