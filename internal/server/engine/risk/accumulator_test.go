package risk

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type sink struct {
	mu   sync.Mutex
	rows []model.RiskDecision
}

func (s *sink) persist(d model.RiskDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, d)
	return nil
}

// byLevel 返回某一层最近写入的判断与该层写入次数。
func (s *sink) byLevel(level string) (model.RiskDecision, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last model.RiskDecision
	n := 0
	for _, r := range s.rows {
		if r.Level == level {
			last, n = r, n+1
		}
	}
	return last, n
}

func newAcc(t *testing.T, deps Deps) (*Accumulator, *sink) {
	t.Helper()
	s := &sink{}
	if deps.KnownHost == nil {
		deps.KnownHost = func(string) bool { return true }
	}
	deps.Persist = s.persist
	a := New(deps, ModeShadow, zap.NewNop())
	a.now = func() time.Time { return t0.Add(24 * time.Hour) } // 墙钟在所有测试事件之后
	return a, s
}

// wait 等写库协程把某一层写到 n 条。
func wait(t *testing.T, s *sink, level string, n int) model.RiskDecision {
	t.Helper()
	for i := 0; i < 200; i++ {
		if d, c := s.byLevel(level); c >= n {
			return d
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, c := s.byLevel(level)
	t.Fatalf("%s 层应写 %d 条判断，得 %d", level, n, c)
	return model.RiskDecision{}
}

func settle() { time.Sleep(20 * time.Millisecond) }

var t0 = time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)

// 测试里的血缘：进程号即根。
var byPID = Deps{Lineage: func(_, pid string) (string, string, string, string, bool) {
	return "r" + pid, pid, "/bin/bash", "-bash", true
}}

func hit(rule, tactic, sev string, at time.Duration) Hit {
	return Hit{HostID: "h1", PID: "100", RuleKey: rule, Severity: sev, Tactic: tactic, At: t0.Add(at)}
}

// 同一战术重复命中不叠加；血缘层跨三个战术才算本会告警。
func TestTacticsAccumulate(t *testing.T) {
	a, s := newAcc(t, byPID)
	a.Observe(hit("cel-44", "TA0007", "low", 0))
	a.Observe(hit("cel-45", "TA0007", "low", time.Minute))
	settle()
	if _, c := s.byLevel(LevelLineage); c != 0 {
		t.Fatal("单一战术不该产生判断")
	}
	a.Observe(hit("cel-5", "TA0004", "medium", 2*time.Minute))
	d := wait(t, s, LevelLineage, 1)
	if d.TacticCount != 2 || d.WouldAlert || d.Score != 4 {
		t.Fatalf("两个战术是候选但不告警，分值 1+3: %+v", d)
	}
	a.Observe(hit("cel-22", "TA0003", "high", 3*time.Minute))
	d = wait(t, s, LevelLineage, 2)
	if d.TacticCount != 3 || !d.WouldAlert || d.Tactics != "TA0003,TA0004,TA0007" {
		t.Fatalf("三个战术应判为本会告警: %+v", d)
	}
	// 主机层同时累积，三个战术在主机层只是候选（阈值更严）。
	if h := wait(t, s, LevelHost, 1); h.TacticCount != 3 || h.WouldAlert || h.EntityKey != "host:h1" {
		t.Fatalf("主机层应记为候选、不告警: %+v", h)
	}
}

// 两个战术但分值够高（critical + high）也算本会告警。
func TestHighScoreWithTwoTactics(t *testing.T) {
	a, s := newAcc(t, byPID)
	a.Observe(hit("cel-34", "TA0011", "critical", 0))
	a.Observe(hit("cel-2", "TA0002", "high", time.Minute))
	if d := wait(t, s, LevelLineage, 1); !d.WouldAlert || d.Score != 16 {
		t.Fatalf("critical+high 应达到分值阈值: %+v", d)
	}
}

// 普遍性系数只作用于低危信号：中危以上不因「常见」降分（攻击者可以借全舰队都有的解释器）。
func TestPrevalenceOnlyLowersLowSignals(t *testing.T) {
	common := func(string, string) float64 { return 0.3 }
	a, s := newAcc(t, Deps{Lineage: byPID.Lineage, Prevalence: common})
	a.Observe(hit("cel-34", "TA0011", "critical", 0))
	a.Observe(hit("cel-2", "TA0002", "high", time.Minute))
	if d := wait(t, s, LevelLineage, 1); !d.WouldAlert || d.Score != 16 {
		t.Fatalf("中危以上不应被普遍性降分: %+v", d)
	}
	// 常见低危信号在血缘层照样算战术（只降分），但凑出的三个战术分值太低，只是候选、不告警。
	b, s2 := newAcc(t, Deps{Lineage: byPID.Lineage, Prevalence: common})
	b.Observe(hit("cel-196", "TA0005", "low", 0))
	b.Observe(hit("cel-44", "TA0007", "low", time.Minute))
	b.Observe(hit("cel-5", "TA0004", "medium", 2*time.Minute))
	if d := wait(t, s2, LevelLineage, 2); d.TacticCount != 3 || d.WouldAlert {
		t.Fatalf("三个战术但降分前只有 5 分，应是候选不告警: %+v", d)
	}
}

// 攻击者把每一步放进不同的血缘（cron、ssh 回环、伪装程序名），血缘层凑不起来，主机层照样叠加。
func TestHostLevelCatchesSplitLineages(t *testing.T) {
	a, s := newAcc(t, byPID)
	steps := []Hit{
		hit("cel-47", "TA0007", "medium", 0),
		hit("cel-5", "TA0004", "high", time.Minute),
		hit("cel-22", "TA0003", "high", 2*time.Minute),
		hit("ioc-ip", "TA0011", "high", 3*time.Minute),
	}
	for i, h := range steps {
		h.PID = fmt.Sprint(1000 + i) // 每一步一个独立的根
		a.Observe(h)
	}
	settle()
	if _, c := s.byLevel(LevelLineage); c != 0 {
		t.Fatal("每个血缘只有一个战术，血缘层不应有判断")
	}
	if d := wait(t, s, LevelHost, 2); !d.WouldAlert || d.TacticCount != 4 {
		t.Fatalf("主机层应凑出四个战术并判为本会告警: %+v", d)
	}
}

// 血缘解析不了的命中只计入主机层，不丢。
func TestUnresolvedLineageCountsOnHost(t *testing.T) {
	a, s := newAcc(t, Deps{Lineage: func(string, string) (string, string, string, string, bool) { return "", "", "", "", false }})
	a.Observe(hit("cel-44", "TA0007", "medium", 0))
	a.Observe(hit("cel-5", "TA0004", "medium", time.Minute))
	a.Observe(hit("cel-22", "TA0003", "medium", 2*time.Minute))
	if d := wait(t, s, LevelHost, 1); d.TacticCount != 3 {
		t.Fatalf("主机层应有三个战术: %+v", d)
	}
}

// 未登记的主机、影子规则、推不出战术的命中都不计。
func TestIgnoredHits(t *testing.T) {
	a, s := newAcc(t, Deps{KnownHost: func(h string) bool { return h == "h1" }, Lineage: byPID.Lineage})
	forged := hit("cel-34", "TA0011", "critical", 0)
	forged.HostID = "forged"
	shadow := hit("cel-44", "TA0007", "low", 0)
	shadow.Shadow = true
	noTactic := hit("cel-999", "", "high", 0)
	for _, h := range []Hit{forged, shadow, noTactic, hit("cel-2", "TA0002", "high", time.Minute)} {
		a.Observe(h)
	}
	settle()
	if _, c := s.byLevel(LevelLineage); c != 0 {
		t.Fatal("被忽略的命中不应凑出候选")
	}
}

// 信号滑出窗口后，再来的命中算新的一段活动；一段活动最长 6 小时。
func TestWindowAndEpisode(t *testing.T) {
	a, s := newAcc(t, byPID)
	a.Observe(hit("cel-44", "TA0007", "medium", 0))
	a.Observe(hit("cel-5", "TA0004", "medium", Window+2*time.Minute))
	settle()
	if _, c := s.byLevel(LevelLineage); c != 0 {
		t.Fatal("窗口外的信号不应与新信号凑在一起")
	}
	// 每 30 分钟一次命中，实体一直活跃；超过 6 小时后应开新的一段。
	b, s2 := newAcc(t, byPID)
	for i := 0; i <= 14; i++ {
		tac := []string{"TA0007", "TA0004"}[i%2]
		b.Observe(hit(fmt.Sprintf("cel-%d", i), tac, "medium", time.Duration(i)*30*time.Minute))
	}
	settle()
	s2.mu.Lock()
	starts := map[string]bool{}
	for _, r := range s2.rows {
		if r.Level == LevelLineage {
			starts[time.Time(r.EpisodeStart).String()] = true
		}
	}
	s2.mu.Unlock()
	if len(starts) < 2 {
		t.Fatalf("一直活跃超过 6 小时应切成新的一段，得 %d 段", len(starts))
	}
	// 清理按事件时间：墙钟过去多久都不影响，最近一次事件之前一个窗口以外的才清。
	a.Sweep(t0.Add(10 * Window))
	if len(a.ents) != 2 {
		t.Fatalf("最近的血缘与主机两个实体都还在窗口内，应保留，剩 %d", len(a.ents))
	}
}

// 状态没变时不重写；新出现高危规则时即使战术数没变也要记一笔。
func TestPersistOnChangeAndNewSevereRule(t *testing.T) {
	a, s := newAcc(t, byPID)
	a.Observe(hit("cel-5", "TA0004", "medium", 0))
	a.Observe(hit("cel-22", "TA0003", "medium", time.Minute))
	wait(t, s, LevelLineage, 1)
	for i := 2; i < 10; i++ {
		a.Observe(hit("cel-22", "TA0003", "medium", time.Duration(i)*time.Minute))
	}
	settle()
	if _, c := s.byLevel(LevelLineage); c != 1 {
		t.Fatalf("状态没变不应重写，写了 %d 次", c)
	}
	a.Observe(hit("cel-23", "TA0003", "high", 10*time.Minute)) // 同战术新出现的高危规则
	d := wait(t, s, LevelLineage, 2)
	if !strings.Contains(d.Signals, "cel-23") {
		t.Fatalf("新的高危规则应出现在明细里: %s", d.Signals)
	}
}

// 写库失败后实体回到「未写过」，下一次命中重新写。
func TestPersistFailureRetried(t *testing.T) {
	var mu sync.Mutex
	fail := true
	var rows []model.RiskDecision
	a := New(Deps{
		KnownHost: func(string) bool { return true },
		Lineage:   byPID.Lineage,
		Persist: func(d model.RiskDecision) error {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return fmt.Errorf("mysql down")
			}
			rows = append(rows, d)
			return nil
		},
	}, ModeShadow, zap.NewNop())
	a.now = func() time.Time { return t0.Add(24 * time.Hour) }
	a.Observe(hit("cel-5", "TA0004", "medium", 0))
	a.Observe(hit("cel-22", "TA0003", "medium", time.Minute))
	settle()
	mu.Lock()
	fail = false
	mu.Unlock()
	a.Observe(hit("cel-22", "TA0003", "medium", 2*time.Minute)) // 状态没变，但上次没写成
	settle()
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, r := range rows {
		if r.Level == LevelLineage {
			found = true
		}
	}
	if !found {
		t.Fatal("写库失败的判断应在下一次命中时重写")
	}
}

// 一台主机造出大量血缘时，超出上限的命中只计入主机层，不无限占内存。
func TestPerHostEntityLimit(t *testing.T) {
	a, _ := newAcc(t, byPID)
	for i := 0; i < maxEntitiesPerHost+50; i++ {
		h := hit("cel-44", "TA0007", "low", time.Duration(i)*time.Millisecond)
		h.PID = fmt.Sprint(i)
		a.Observe(h)
	}
	if n := a.byHost["h1"]; n != maxEntitiesPerHost {
		t.Fatalf("单主机血缘实体数应封顶在 %d，得 %d", maxEntitiesPerHost, n)
	}
}

func TestFactorFor(t *testing.T) {
	for _, c := range []struct {
		hosts, total int
		want         float64
	}{{200, 296, 0.3}, {30, 296, 0.7}, {29, 296, 1}, {0, 296, 1}, {5, 0, 1}} {
		if got := FactorFor(c.hosts, c.total); got != c.want {
			t.Errorf("FactorFor(%d,%d)=%v，期望 %v", c.hosts, c.total, got, c.want)
		}
	}
}

// 血缘层里常见的低危信号只降分、不清战术：同一条血缘里的 whoami 是攻击链的一环。
func TestLineageKeepsCommonLowTactic(t *testing.T) {
	common := func(rule, _ string) float64 {
		if rule == "cel-47" {
			return 0.3
		}
		return 1
	}
	a, s := newAcc(t, Deps{Lineage: byPID.Lineage, Prevalence: common})
	a.Observe(hit("cel-47", "TA0007", "low", 0))
	a.Observe(hit("cel-8", "TA0002", "high", time.Minute))
	a.Observe(hit("ioc-ip", "TA0011", "high", 2*time.Minute))
	d := wait(t, s, LevelLineage, 2)
	if d.TacticCount != 3 || !d.WouldAlert {
		t.Fatalf("血缘层应计入常见的发现命令，凑成三个战术: %+v", d)
	}
	// 主机层按降分后的权重：常见低危不算战术。
	if h, _ := s.byLevel(LevelHost); h.TacticCount > 2 {
		t.Fatalf("主机层不应计入常见的低危信号: %+v", h)
	}
}

// 同一规则在窗口内取最高的一次：后来的普遍程序不能冲掉罕见程序那一次的分值。
func TestSameRuleKeepsMaxWeight(t *testing.T) {
	prev := func(_, exe string) float64 {
		if exe == "/usr/bin/id" {
			return 0.3
		}
		return 1
	}
	a, s := newAcc(t, Deps{Prevalence: prev})
	rare := hit("cel-47", "TA0007", "low", 0)
	rare.Exe = "/tmp/.x/id"
	a.Observe(rare)
	later := hit("cel-47", "TA0007", "low", time.Minute)
	later.Exe = "/usr/bin/id"
	a.Observe(later)
	a.Observe(hit("cel-5", "TA0004", "medium", 2*time.Minute))
	a.Observe(hit("cel-22", "TA0003", "medium", 3*time.Minute))
	if d := wait(t, s, LevelHost, 1); d.TacticCount != 3 || !strings.Contains(d.Signals, "/tmp/.x/id") {
		t.Fatalf("罕见程序那次命中应保留，发现战术仍算数: %+v", d)
	}
}

// 清理按见过的最大事件时间判断：消费积压时墙钟远超事件时间，不能把实体清空。
func TestSweepUsesEventTime(t *testing.T) {
	a, _ := newAcc(t, byPID)
	a.Observe(hit("cel-5", "TA0004", "medium", 0))
	a.Sweep(t0.Add(5 * Window)) // 墙钟已过去很久（积压）
	if len(a.ents) == 0 {
		t.Fatal("事件时间还在窗口内，不应因墙钟清掉实体")
	}
	a.Observe(hit("cel-22", "TA0003", "medium", 2*Window))
	a.Sweep(time.Time{})
	if _, ok := a.ents["h1|r100"]; ok && len(a.ents) > 2 {
		t.Fatalf("超过窗口的实体应被清掉: %d", len(a.ents))
	}
}

// 嘈杂实体里新出现中危规则：战术与分值都没变，也要记一笔。
func TestNewMediumRuleInNoisyEntity(t *testing.T) {
	a, s := newAcc(t, byPID)
	a.Observe(hit("cel-22", "TA0003", "high", 0))
	a.Observe(hit("cel-5", "TA0004", "high", time.Minute))
	wait(t, s, LevelLineage, 1)
	a.Observe(hit("cel-9", "TA0003", "medium", 2*time.Minute)) // 同战术、更低分，但是新规则
	if d := wait(t, s, LevelLineage, 2); !strings.Contains(d.Signals, "cel-9") {
		t.Fatalf("新出现的中危规则应记录: %s", d.Signals)
	}
}

// 写入风险判断表的命令行要遮蔽口令，与告警、信号表一致。
func TestCmdlineSanitized(t *testing.T) {
	a, s := newAcc(t, byPID)
	h := hit("cel-5", "TA0004", "medium", 0)
	h.Cmdline = "mysql -uroot --password=hunter2"
	a.Observe(h)
	a.Observe(hit("cel-22", "TA0003", "medium", time.Minute))
	if d := wait(t, s, LevelLineage, 1); strings.Contains(d.Signals, "hunter2") {
		t.Fatalf("口令应被遮蔽: %s", d.Signals)
	}
}

// 未来时间戳按墙钟计，不会把这台主机的清理基准推到未来。
func TestFutureTimestampClamped(t *testing.T) {
	a, _ := newAcc(t, byPID)
	wall := a.now()
	future := hit("cel-5", "TA0004", "medium", 0)
	future.At = wall.Add(48 * time.Hour)
	a.Observe(future)
	if got := a.hostLatest["h1"]; !got.Equal(wall) {
		t.Fatalf("未来时间戳应截到墙钟，得 %v", got)
	}
}

// 一台主机的积压不影响另一台：清理基准按主机各自的事件时间。
func TestPerHostWatermark(t *testing.T) {
	a, _ := newAcc(t, byPID)
	a.Observe(hit("cel-5", "TA0004", "medium", 0)) // h1：落后的分区，事件停在 t0
	h2 := hit("cel-22", "TA0003", "medium", 3*Window)
	h2.HostID = "h2" // h2：追平的分区，事件时间已在三小时后
	a.Observe(h2)
	a.Sweep(a.now())
	if a.ents["host:h1"] == nil {
		t.Fatal("别的主机事件时间前进，不应清掉落后主机的实体")
	}
}

// 血缘根的命令行同样要遮蔽口令。
func TestRootCmdlineSanitized(t *testing.T) {
	a, s := newAcc(t, Deps{Lineage: func(_, pid string) (string, string, string, string, bool) {
		return "r" + pid, pid, "/opt/app/server", "/opt/app/server --db-password=hunter2", true
	}})
	a.Observe(hit("cel-5", "TA0004", "medium", 0))
	a.Observe(hit("cel-22", "TA0003", "medium", time.Minute))
	if d := wait(t, s, LevelLineage, 1); strings.Contains(d.RootCmdline, "hunter2") {
		t.Fatalf("根进程命令行应遮蔽口令: %s", d.RootCmdline)
	}
}
