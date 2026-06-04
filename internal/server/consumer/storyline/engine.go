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

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	// flushInterval controls how often in-memory storylines are checkpointed to DB.
	flushInterval = 30 * time.Second
	// staleTimeout marks storylines as stale (no new events) for cleanup.
	staleTimeout = 30 * time.Minute
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
	st.pendingEvts = append(st.pendingEvts, evt)
}

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
	st = &storyState{
		storyID:   storyID,
		hostID:    hostID,
		hostname:  hostname,
		severity:  "low",
		ruleNames: make(map[string]struct{}),
		firstSeen: time.Now(),
		lastSeen:  time.Now(),
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
