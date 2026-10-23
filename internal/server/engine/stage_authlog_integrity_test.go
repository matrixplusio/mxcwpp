package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

var authlogT0 = time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)

func heartbeatAt(at time.Time, f map[string]string) PipelineEvent {
	m := map[string]string{"event_type": authlogHeartbeatKind, "reason": "periodic", "source": "journal",
		"journal_seqnum_id": "aa", "journal_seqnum": "100", "journal_boot_id": "b1", "journal_persistent": "true"}
	for k, v := range f {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return PipelineEvent{HostID: "h1", DataType: DataTypeAuthEvent, Payload: b, EventTime: at}
}

func otherEventAt(at time.Time) PipelineEvent {
	return PipelineEvent{HostID: "h1", DataType: 3000, Payload: []byte(`{"exe":"/usr/bin/ls"}`), EventTime: at}
}

func runAuthlog(t *testing.T, s *AuthlogIntegrityStage, ev PipelineEvent) []string {
	t.Helper()
	alerts, err := s.Process(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ids = append(ids, a.RuleID)
	}
	return ids
}

func TestAuthlogJournalRewindWithinSameBoot(t *testing.T) {
	cases := []struct {
		name string
		next map[string]string
		want bool
	}{
		{"序号前进", map[string]string{"journal_seqnum": "150"}, false},
		{"序号不变（这段时间没有认证记录）", map[string]string{}, false},
		{"序号倒退", map[string]string{"journal_seqnum": "20"}, true},
		{"序号组变了", map[string]string{"journal_seqnum_id": "bb", "journal_seqnum": "3"}, true},
		{"重启后序号组变了（不判）", map[string]string{"journal_seqnum_id": "bb", "journal_seqnum": "3", "journal_boot_id": "b2"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewAuthlogIntegrityStage(nil)
			if got := runAuthlog(t, s, heartbeatAt(authlogT0, nil)); len(got) != 0 {
				t.Fatalf("第一条心跳不该告警: %v", got)
			}
			got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(5*time.Minute), c.next))
			if hit := len(got) == 1 && got[0] == RuleAuthlogJournalRewind; hit != c.want {
				t.Fatalf("got %v, want rewind=%v", got, c.want)
			}
		})
	}
}

func TestAuthlogIgnoresNonHeartbeatEvents(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	for m := 0; m < 60; m += 5 {
		if got := runAuthlog(t, s, otherEventAt(authlogT0.Add(time.Duration(m)*time.Minute))); len(got) != 0 {
			t.Fatalf("非心跳事件不该触发: %v", got)
		}
	}
	if len(s.hosts) != 0 {
		t.Fatalf("没发过心跳的主机不该进状态表: %d", len(s.hosts))
	}
}

// agent 断线期间的心跳落盘、重连后补发，可能晚于新心跳到达。旧的不能被当成「序号倒退」。
func TestAuthlogStaleHeartbeatIsNotRewind(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	inst := map[string]string{"instance_id": "i1", "instance_started": "1000"}
	with := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range inst {
			out[k] = v
		}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	runAuthlog(t, s, heartbeatAt(authlogT0, with(map[string]string{"hb_seq": "1", "journal_seqnum": "100"})))
	runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Minute), with(map[string]string{"hb_seq": "3", "journal_seqnum": "200"})))
	if got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(2*time.Minute), with(map[string]string{"hb_seq": "2", "journal_seqnum": "150"}))); len(got) != 0 {
		t.Fatalf("同一实例里序号更小的心跳是补发的旧心跳: %v", got)
	}
	// 上一个实例补发上来的心跳同样是旧的。
	runAuthlog(t, s, heartbeatAt(authlogT0.Add(3*time.Minute), map[string]string{"instance_id": "i2", "instance_started": "2000", "hb_seq": "1", "journal_seqnum": "300"}))
	if got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(4*time.Minute), with(map[string]string{"hb_seq": "9", "journal_seqnum": "250"}))); len(got) != 0 {
		t.Fatalf("旧实例的心跳不参与比对: %v", got)
	}
	// 但真倒退照报。
	if got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(5*time.Minute), map[string]string{"instance_id": "i2", "instance_started": "2000", "hb_seq": "2", "journal_seqnum": "5"})); len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("最新实例的倒退应报: %v", got)
	}
}

// 插件重启后、读到新记录之前的心跳不带序号；不能把基线清掉，否则先杀插件再清 journal 就看不出来。
func TestAuthlogRestartKeepsBaseline(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s, heartbeatAt(authlogT0, map[string]string{"instance_id": "i1", "instance_started": "1000", "hb_seq": "1"}))
	runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Minute), map[string]string{"instance_id": "i2", "instance_started": "2000", "hb_seq": "1",
		"reason": "start", "journal_seqnum_id": "", "journal_seqnum": "", "journal_boot_id": "b1"}))
	got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(2*time.Minute), map[string]string{"instance_id": "i2", "instance_started": "2000", "hb_seq": "2",
		"journal_seqnum_id": "zz", "journal_seqnum": "1"}))
	if len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("重启后序号组变了应报: %v", got)
	}
}

func TestAuthlogFrequentRestarts(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	var fired int
	for i := 0; i < 6; i++ {
		got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Duration(i)*5*time.Minute), map[string]string{
			"instance_id": fmt.Sprintf("i%d", i), "instance_started": fmt.Sprint(1000 + i), "hb_seq": "1", "reason": "start"}))
		for _, r := range got {
			if r == RuleAuthlogCollectorRestarts {
				fired++
			}
		}
	}
	if fired != 1 {
		t.Fatalf("半小时 6 个实例应报一次频繁重启，got %d", fired)
	}
}

func TestAuthlogLogdDownAndStalled(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	got := runAuthlog(t, s, heartbeatAt(authlogT0, map[string]string{"logd_alive": "false", "reason": "periodic,stalled"}))
	want := map[string]bool{RuleAuthlogLogdDown: true, RuleAuthlogCollectorStalled: true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("got %v", got)
	}
}

func TestAuthlogSourceDowngradeAndPluginReports(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s, heartbeatAt(authlogT0, nil))
	got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Minute), map[string]string{
		"reason": "source_changed", "source": "file", "journal_seqnum_id": "", "journal_seqnum": "",
		"file_path": "/var/log/secure"}))
	if len(got) != 1 || got[0] != RuleAuthlogSourceDowngrade {
		t.Fatalf("journald 退到读文件应报: %v", got)
	}

	got = runAuthlog(t, s, heartbeatAt(authlogT0.Add(2*time.Minute), map[string]string{
		"reason": "file_truncated", "source": "file", "journal_seqnum_id": "", "journal_seqnum": "",
		"file_path": "/var/log/secure"}))
	if len(got) != 1 || got[0] != RuleAuthlogFileTruncated {
		t.Fatalf("插件报的截断应告警: %v", got)
	}

	s2 := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s2, heartbeatAt(authlogT0, nil))
	got = runAuthlog(t, s2, heartbeatAt(authlogT0.Add(time.Minute), map[string]string{"journal_persistent": "false"}))
	if len(got) != 1 || got[0] != RuleAuthlogSourceDowngrade {
		t.Fatalf("同一次开机内 /var/log/journal 消失应报: %v", got)
	}
}

func TestAuthlogAlertsCarryReason(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s, heartbeatAt(authlogT0, nil))
	alerts, _ := s.Process(context.Background(), heartbeatAt(authlogT0.Add(time.Minute), map[string]string{"journal_seqnum": "1"}))
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts", len(alerts))
	}
	if r := payloadReason(alerts[0].Payload); r == "" {
		t.Fatal("告警描述取自 payload 的 would_action.reason，不能为空")
	}
	if alerts[0].Severity != "high" || alerts[0].ATTCKTechnique != "T1070.002" {
		t.Fatalf("got %+v", alerts[0])
	}
}

// 主机把时钟回拨后重启插件，新实例自报的启动时间更早；它仍是新实例，之后清 journal 要照报。
func TestAuthlogClockRollbackDoesNotHideRewind(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s, heartbeatAt(authlogT0, map[string]string{"instance_id": "i1", "instance_started": "5000", "hb_seq": "1", "journal_seqnum": "100"}))
	runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Minute), map[string]string{"instance_id": "i2", "instance_started": "10", "hb_seq": "1", "journal_seqnum": "100"}))
	got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(2*time.Minute), map[string]string{"instance_id": "i2", "instance_started": "10", "hb_seq": "2",
		"journal_seqnum_id": "new", "journal_seqnum": "1"}))
	if len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("时钟回拨不该让倒退被当成旧心跳: %v", got)
	}
}

func TestAuthlogProbeFailuresAndMissingFile(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	var fired int
	for i := 0; i < 5; i++ {
		for _, r := range runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Duration(i)*5*time.Minute),
			map[string]string{"instance_id": "i1", "hb_seq": fmt.Sprint(i + 1), "head_probe_error": "true"})) {
			if r == RuleAuthlogProbeFailed {
				fired++
			}
		}
	}
	if fired != 1 {
		t.Fatalf("连续探测失败应报一次，got %d", fired)
	}
	got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Hour), map[string]string{"instance_id": "i1", "hb_seq": "9",
		"source": "file", "file_path": "/var/log/secure", "file_missing": "true", "journal_seqnum_id": "", "journal_seqnum": ""}))
	found := false
	for _, r := range got {
		found = found || r == RuleAuthlogFileMissing
	}
	if !found {
		t.Fatalf("日志文件不存在应报: %v", got)
	}
}

// engine 不认识的旧实例心跳晚到（离线期间落盘、重连后补发），不能把当前实例挤掉。
func TestAuthlogUnknownLateInstanceDoesNotTakeOver(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	b := func(at time.Duration, seq int, m map[string]string) PipelineEvent {
		f := map[string]string{"instance_id": "B", "hb_seq": fmt.Sprint(seq)}
		for k, v := range m {
			f[k] = v
		}
		return heartbeatAt(authlogT0.Add(at), f)
	}
	runAuthlog(t, s, b(0, 1, map[string]string{"journal_seqnum": "200"}))
	runAuthlog(t, s, b(time.Minute, 2, map[string]string{"journal_seqnum": "210"}))
	// A 是 engine 从没见过的旧实例，序号已经很大，带着更早的位置补发上来。
	if got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(2*time.Minute), map[string]string{"instance_id": "A", "hb_seq": "40", "journal_seqnum": "150"})); len(got) != 0 {
		t.Fatalf("晚到的旧实例不该触发倒退: %v", got)
	}
	// B 的实时心跳照常比对。
	got := runAuthlog(t, s, b(5*time.Minute, 3, map[string]string{"journal_seqnum_id": "zz", "journal_seqnum": "1"}))
	if len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("当前实例的真实倒退应照报: %v", got)
	}
}

// 当前实例的心跳晚到一会儿，补发上来的旧实例也不能把它挤掉；挤掉后它要能回来。
func TestAuthlogDelayedCurrentHeartbeatSurvivesOldInstance(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	b := func(at time.Duration, seq int, m map[string]string) PipelineEvent {
		f := map[string]string{"instance_id": "B", "hb_seq": fmt.Sprint(seq)}
		for k, v := range m {
			f[k] = v
		}
		return heartbeatAt(authlogT0.Add(at), f)
	}
	runAuthlog(t, s, b(0, 1, map[string]string{"journal_seqnum": "200"}))
	runAuthlog(t, s, b(5*time.Minute, 2, map[string]string{"journal_seqnum": "210"}))
	// B 的第 3 条晚到；这时 A 落盘的旧心跳补发上来。
	if got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(11*time.Minute+10*time.Second), map[string]string{"instance_id": "A", "hb_seq": "57", "journal_seqnum": "150"})); len(got) != 0 {
		t.Fatalf("补发的旧实例不该触发倒退: %v", got)
	}
	runAuthlog(t, s, b(11*time.Minute+20*time.Second, 3, map[string]string{"journal_seqnum": "220"}))
	got := runAuthlog(t, s, b(16*time.Minute, 4, map[string]string{"journal_seqnum_id": "zz", "journal_seqnum": "1"}))
	if len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("B 仍是当前实例，真实倒退应照报: %v", got)
	}
}

// engine 重启后旧实例的补发心跳先到、成了当前实例；它不再发心跳后，真正在跑的实例要能接管回来。
func TestAuthlogLiveInstanceRecoversAfterStaleTakeover(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s, heartbeatAt(authlogT0, map[string]string{"instance_id": "A", "hb_seq": "57", "journal_seqnum": "150"}))
	for i := 1; i <= 3; i++ {
		runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Duration(i)*5*time.Minute), map[string]string{"instance_id": "B", "hb_seq": fmt.Sprint(500 + i), "journal_seqnum": "300"}))
	}
	got := runAuthlog(t, s, heartbeatAt(authlogT0.Add(20*time.Minute), map[string]string{"instance_id": "B", "hb_seq": "504", "journal_seqnum_id": "zz", "journal_seqnum": "1"}))
	if len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("B 接管回来后真实倒退应照报: %v", got)
	}
}

// 旧实例离线期间落盘的心跳持续补发，不能把当前实例压住；刚重启就断线的旧实例补发上来也不算新启动。
func TestAuthlogReplayedHeartbeatsCannotHoldOrTakeOver(t *testing.T) {
	hb := func(at time.Duration, hostAgo time.Duration, id string, seq int, m map[string]string) PipelineEvent {
		f := map[string]string{"instance_id": id, "hb_seq": fmt.Sprint(seq),
			"timestamp": fmt.Sprint(authlogT0.Add(at).Add(-hostAgo).Unix())}
		for k, v := range m {
			f[k] = v
		}
		return heartbeatAt(authlogT0.Add(at), f)
	}
	// engine 刚重启：A 的补发先到并成为当前实例，之后持续补发。
	s := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s, hb(0, 2*time.Hour, "A", 57, map[string]string{"journal_seqnum": "150"}))
	for i := 1; i <= 4; i++ {
		runAuthlog(t, s, hb(time.Duration(i)*30*time.Second, 2*time.Hour, "A", 57+i, map[string]string{"journal_seqnum": "150"}))
	}
	// B 的实时心跳：A 真正的心跳早已停了，B 应立即接管，之后的真实倒退马上报出。
	runAuthlog(t, s, hb(3*time.Minute, 0, "B", 500, map[string]string{"journal_seqnum": "300"}))
	got := runAuthlog(t, s, hb(8*time.Minute, 0, "B", 501, map[string]string{"journal_seqnum_id": "zz", "journal_seqnum": "1"}))
	if len(got) != 1 || got[0] != RuleAuthlogJournalRewind {
		t.Fatalf("补发不该压住当前实例: %v", got)
	}

	// A 刚重启（seq 1）就断线，补发晚于 B 到达：不算新启动，不接管、不报假倒退。
	s2 := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s2, hb(0, 0, "B", 10, map[string]string{"journal_seqnum": "310"}))
	if got := runAuthlog(t, s2, hb(time.Minute, 40*time.Minute, "A", 1, map[string]string{"journal_seqnum": "200"})); len(got) != 0 {
		t.Fatalf("补发上来的旧启动心跳不该接管: %v", got)
	}
}

// 主机时钟回拨后，所有心跳的延迟一起变大；重启照样要计数，频繁重启照样要报。
func TestAuthlogRestartsCountedDespiteClockSkew(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	var fired int
	for i := 0; i < 8; i++ {
		at := time.Duration(i) * 4 * time.Minute
		f := map[string]string{"instance_id": fmt.Sprintf("i%d", i), "hb_seq": "1",
			"timestamp": fmt.Sprint(authlogT0.Add(at).Add(-3 * time.Minute).Unix())}
		for _, r := range runAuthlog(t, s, heartbeatAt(authlogT0.Add(at), f)) {
			if r == RuleAuthlogCollectorRestarts {
				fired++
			}
		}
	}
	if fired == 0 {
		t.Fatal("时钟回拨后频繁重启仍应报")
	}
}

// 主机时钟慢 20 分钟、旧实例补发与当前实例交替到达，不能来回抢、反复报假倒退。
func TestAuthlogNoFlappingWithSlowClock(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	hb := func(at, hostAgo time.Duration, id string, seq int, num string) PipelineEvent {
		return heartbeatAt(authlogT0.Add(at), map[string]string{"instance_id": id, "hb_seq": fmt.Sprint(seq), "journal_seqnum": num,
			"timestamp": fmt.Sprint(authlogT0.Add(at).Add(-hostAgo).Unix())})
	}
	runAuthlog(t, s, hb(0, 20*time.Minute, "B", 10, "310"))
	var alerts int
	for i := 1; i <= 4; i++ {
		alerts += len(runAuthlog(t, s, hb(time.Duration(i)*time.Minute, 3*time.Hour, "A", 50+i, "200")))
		alerts += len(runAuthlog(t, s, hb(time.Duration(i)*time.Minute+10*time.Second, 20*time.Minute, "B", 10+i, "310")))
	}
	if alerts != 0 {
		t.Fatalf("不该来回抢、报假倒退: %d", alerts)
	}
}

func TestAuthlogCursorSaveFailures(t *testing.T) {
	s := NewAuthlogIntegrityStage(nil)
	var fired int
	for i := 0; i < 4; i++ {
		for _, r := range runAuthlog(t, s, heartbeatAt(authlogT0.Add(time.Duration(i)*5*time.Minute),
			map[string]string{"instance_id": "i1", "hb_seq": fmt.Sprint(i + 1), "cursor_save_failed": "true"})) {
			if r == RuleAuthlogCursorSaveFailed {
				fired++
			}
		}
	}
	if fired != 1 {
		t.Fatalf("连续写盘失败应报一次，got %d", fired)
	}
	// 只失败一次不报。
	s2 := NewAuthlogIntegrityStage(nil)
	runAuthlog(t, s2, heartbeatAt(authlogT0, map[string]string{"instance_id": "i1", "hb_seq": "1", "cursor_save_failed": "true"}))
	for _, r := range runAuthlog(t, s2, heartbeatAt(authlogT0.Add(5*time.Minute), map[string]string{"instance_id": "i1", "hb_seq": "2"})) {
		if r == RuleAuthlogCursorSaveFailed {
			t.Fatal("偶发一次失败不该报")
		}
	}
}
