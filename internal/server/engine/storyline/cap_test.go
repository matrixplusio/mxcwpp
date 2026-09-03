package storyline

import (
	"testing"

	"go.uber.org/zap"
)

func netFields(rule string) map[string]string {
	f := map[string]string{
		"event_type":  "tcp_connect",
		"pid":         "1234",
		"exe":         "/usr/sbin/nginx",
		"remote_addr": "10.0.0.11",
		"remote_port": "8888",
	}
	if rule != "" {
		f["agent_rule_name"] = rule
		f["agent_severity"] = "high"
		f["agent_mitre_tactic"] = "command_and_control"
	}
	return f
}

// storyOf 取出内存中的故事状态，测试专用。
func storyOf(t *testing.T, e *Engine, storyID string) *storyState {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	st, ok := e.stories[storyID]
	if !ok {
		t.Fatalf("story %s 不在内存中", storyID)
	}
	return st
}

// TestIngest_DetailCappedPerStory 单条故事线的明细必须封顶。
//
// 回归 2026-08 事故：已有的 pendingEvts 上限只约束单次 flush 窗口内的条数（500），
// 对总量无约束。常驻进程被打上 story_id 后每 30 秒刷 500 条，观察到单条故事线
// 攒到 千万级条明细，storyline_events 整表 亿级行、数百 GB，写满存储节点后
// 级联拖垮整个平台。
func TestIngest_DetailCappedPerStory(t *testing.T) {
	e := NewEngine(nil, zap.NewNop())

	const sid = "story-cap"
	total := maxEventsPerStory + 500
	for range total {
		e.Ingest(sid, "host-1", "nginx-01", 3002, netFields(""))
	}

	st := storyOf(t, e, sid)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.eventCount != total {
		t.Errorf("计数应继续累计（用于风险分与规模展示），期望 %d 实际 %d", total, st.eventCount)
	}
	if len(st.pendingEvts) > maxEventsPerStory {
		t.Errorf("待落库明细 %d 条已超上限 %d", len(st.pendingEvts), maxEventsPerStory)
	}
	if !st.cappedLogged {
		t.Error("触顶应记录一次告警，否则运维看不到有故事线被截断")
	}
}

// TestIngest_AggregateStateKeepsEvolvingAfterCap 触顶后聚合态必须继续演进。
//
// 上限截断的是明细，不是这条故事线本身。命中新规则、严重度升级、last_seen 推进
// 都还要照常发生 —— 否则一条长期攻击在触顶那一刻就"冻结"，后续的提权、横移
// 全部看不见，等于用一个存储保护把检测能力也关掉了。
func TestIngest_AggregateStateKeepsEvolvingAfterCap(t *testing.T) {
	e := NewEngine(nil, zap.NewNop())

	const sid = "story-evolve"
	for range maxEventsPerStory + 10 {
		e.Ingest(sid, "host-1", "nginx-01", 3002, netFields(""))
	}

	before := storyOf(t, e, sid)
	before.mu.Lock()
	sevBefore := before.severity
	seenBefore := before.lastSeen
	before.mu.Unlock()

	// 触顶之后来了一条新的、更严重的命中
	crit := netFields("privesc_suid_set")
	crit["agent_severity"] = "critical"
	crit["agent_mitre_tactic"] = "privilege_escalation"
	e.Ingest(sid, "host-1", "nginx-01", 3000, crit)

	st := storyOf(t, e, sid)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.severity != "critical" {
		t.Errorf("触顶后严重度仍须升级，期望 critical 实际 %q（升级前 %q）", st.severity, sevBefore)
	}
	if st.phase != "privilege_escalation" {
		t.Errorf("触顶后 MITRE 阶段仍须推进，实际 %q", st.phase)
	}
	if _, ok := st.ruleNames["privesc_suid_set"]; !ok {
		t.Error("触顶后新命中的规则仍须记入 rule_names")
	}
	if !st.lastSeen.After(seenBefore) && !st.lastSeen.Equal(seenBefore) {
		t.Error("触顶后 last_seen 仍须推进")
	}
	if st.alertCount == 0 {
		t.Error("触顶后告警计数仍须累加")
	}
}

// TestIngest_BelowCapCollectsDetail 未触顶时行为不变：明细照常收集。
func TestIngest_BelowCapCollectsDetail(t *testing.T) {
	e := NewEngine(nil, zap.NewNop())

	const sid = "story-normal"
	const n = 20
	for range n {
		e.Ingest(sid, "host-1", "app-01", 3002, netFields("c2_high_risk_port"))
	}

	st := storyOf(t, e, sid)
	st.mu.Lock()
	defer st.mu.Unlock()

	if len(st.pendingEvts) != n {
		t.Errorf("未触顶应收集全部 %d 条明细，实际 %d", n, len(st.pendingEvts))
	}
	if st.cappedLogged {
		t.Error("未触顶不应记截断告警")
	}
}
