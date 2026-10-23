package celengine

import (
	"fmt"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestFleetGuardThreshold(t *testing.T) {
	f := newFleetGuard()
	now := time.Now()
	for i := 1; i <= 9; i++ {
		if d, _ := f.observe("cel-1", fmt.Sprintf("h%d", i), now, 20); d {
			t.Fatalf("%d/20 台不应判为失真", i)
		}
	}
	if d, n := f.observe("cel-1", "h10", now, 20); !d || n != 10 {
		t.Fatalf("10/20 台应判为失真，实际 distorted=%v hosts=%d", d, n)
	}
	// 同一主机重复命中不抬高命中面。
	if _, n := f.observe("cel-1", "h10", now, 20); n != 10 {
		t.Fatalf("重复命中不应计为新主机，实际 %d", n)
	}
}

func TestFleetGuardIgnoresSmallFleets(t *testing.T) {
	f := newFleetGuard()
	for i := 0; i < 5; i++ {
		if d, _ := f.observe("cel-1", fmt.Sprintf("h%d", i), time.Now(), fleetGuardMinHosts-1); d {
			t.Fatal("在线主机太少时不判失真：几台机器全命中说明不了规则有问题")
		}
	}
}

func TestFleetGuardWindowExpires(t *testing.T) {
	f := newFleetGuard()
	start := time.Now()
	for i := 0; i < 10; i++ {
		f.observe("cel-1", fmt.Sprintf("h%d", i), start, 20)
	}
	later := start.Add(fleetGuardWindow + fleetGuardPruneGap + time.Minute)
	if d, n := f.observe("cel-1", "h99", later, 20); d || n != 1 {
		t.Fatalf("窗口外的命中应被清掉，实际 distorted=%v hosts=%d", d, n)
	}
}

// 端到端：命中面越过阈值后，各主机的命中降级为 suppressed，只合并出一条失真告警。
func TestFleetDistortionDowngradesAndAggregates(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	g.fleet = newFleetGuard()
	registerHosts(g, 20)
	seedActiveHosts(g.fleet, 20, time.Now())

	rule := model.DetectionRule{Name: "noisy", Severity: "medium", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh}
	rule.ID = 86
	for i := 1; i <= 12; i++ {
		g.Generate(fmt.Sprintf("h%d", i), []model.DetectionRule{rule}, map[string]string{"exe": "/usr/bin/curl"})
	}

	var active, suppressed, fleet int64
	db.Model(&model.Alert{}).Where("status = ? AND host_id <> ?", model.AlertStatusActive, fleetHostID).Count(&active)
	db.Model(&model.Alert{}).Where("status = ?", model.AlertStatusSuppressed).Count(&suppressed)
	db.Model(&model.Alert{}).Where("host_id = ? AND category = ?", fleetHostID, "rule_distortion").Count(&fleet)
	if active != 9 || suppressed != 3 || fleet != 1 {
		t.Fatalf("应为 9 条主机告警 + 3 条降级 + 1 条合并告警，实际 active=%d suppressed=%d fleet=%d", active, suppressed, fleet)
	}
}

// registerHosts 把 h1..hn 登记进主机快照（登记时间远早于观察期，不触发新主机观察期）。
func registerHosts(g *AlertGenerator, n int) {
	m := make(map[string]time.Time, n)
	for i := 1; i <= n; i++ {
		m[fmt.Sprintf("h%d", i)] = time.Now().AddDate(0, -1, 0)
	}
	g.hostCreatedAt.Store(&m)
}

// 事件里的 host_id 来自上报方：没在主机表登记过的不计入命中面，伪造的 ID 推不动守卫。
func TestFleetGuardIgnoresUnknownHosts(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	g.fleet = newFleetGuard()
	registerHosts(g, 20)
	seedActiveHosts(g.fleet, 20, time.Now())

	rule := model.DetectionRule{Name: "noisy", Severity: "medium", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh}
	rule.ID = 86
	for i := 0; i < 50; i++ {
		fake := fmt.Sprintf("forged-%d", i)
		g.ObserveHost(fake, time.Now())
		g.Generate(fake, []model.DetectionRule{rule}, map[string]string{"exe": "/usr/bin/curl"})
	}
	g.Generate("h1", []model.DetectionRule{rule}, map[string]string{"exe": "/usr/bin/curl"})

	var suppressed, fleet int64
	db.Model(&model.Alert{}).Where("status = ?", model.AlertStatusSuppressed).Count(&suppressed)
	db.Model(&model.Alert{}).Where("host_id = ? AND category = ?", fleetHostID, "rule_distortion").Count(&fleet)
	if suppressed != 0 || fleet != 0 {
		t.Fatalf("未登记主机不应推动守卫，实际 suppressed=%d fleet=%d", suppressed, fleet)
	}
}

// seedActiveHosts 让守卫看到 n 台有事件的主机，并把开始观测的时间提前到一个窗口之前（已预热）。
func seedActiveHosts(f *fleetGuard, n int, now time.Time) {
	for i := 1; i <= n; i++ {
		f.hosts.observe(fmt.Sprintf("h%d", i), now)
	}
	f.hosts.started = now.Add(-2 * fleetGuardWindow)
	f.hosts.pruneLocked(now) // 运行时每分钟随事件清理一次并记下小时峰值，这里直接记
}

// 分母是 engine 实际收到事件的主机，与心跳写库的在线状态无关：在线状态写不进库时，
// 还在上报事件的主机照样计入，命中少数几台远不到「大多数」。
func TestFleetGuardDenominatorIsActiveHosts(t *testing.T) {
	f := newFleetGuard()
	now := time.Now()
	seedActiveHosts(f, 200, now)
	for i := 1; i <= 8; i++ {
		if wide, _, online, _, _ := f.observeAndThrottle("cel-1", fmt.Sprintf("h%d", i), now); wide {
			t.Fatalf("8/%d 台不应判为大范围命中", online)
		}
	}
}

// 大面积断连时（活跃主机掉到峰值一半以下），命中面再大也只聚合、不压制：
// 此时剩下的少数主机撑不起「大多数」，压制会让告警在最需要的时候沉默。
func TestFleetGuardDoesNotSuppressWhenFleetCollapsed(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	g.fleet = newFleetGuard()
	registerHosts(g, 200)
	now := time.Now()
	// 一小时前还有 200 台在上报，此刻只剩 12 台。
	earlier := now.Add(-fleetGuardWindow - 2*fleetGuardPruneGap)
	seedActiveHosts(g.fleet, 200, earlier)
	g.fleet.hosts.started = earlier.Add(-2 * fleetGuardWindow)
	for i := 1; i <= 12; i++ {
		g.fleet.hosts.observe(fmt.Sprintf("h%d", i), now)
	}

	rule := model.DetectionRule{Name: "noisy", Severity: "medium", Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh}
	rule.ID = 86
	for i := 1; i <= 12; i++ {
		g.Generate(fmt.Sprintf("h%d", i), []model.DetectionRule{rule}, map[string]string{"exe": "/usr/bin/curl"})
	}
	var suppressed, active, fleet int64
	db.Model(&model.Alert{}).Where("status = ?", model.AlertStatusSuppressed).Count(&suppressed)
	db.Model(&model.Alert{}).Where("status = ? AND host_id <> ?", model.AlertStatusActive, fleetHostID).Count(&active)
	db.Model(&model.Alert{}).Where("host_id = ? AND category = ?", fleetHostID, "rule_distortion").Count(&fleet)
	if suppressed != 0 || active != 12 || fleet != 1 {
		t.Fatalf("分母塌缩时应全部照常告警并只出一条汇总，实际 active=%d suppressed=%d fleet=%d", active, suppressed, fleet)
	}
}

// engine 刚启动、计数还在爬升时不做判断：此时看到的主机少，命中面占比虚高。
func TestFleetGuardWaitsForWarmup(t *testing.T) {
	f := newFleetGuard()
	now := time.Now()
	for i := 1; i <= 20; i++ {
		f.hosts.observe(fmt.Sprintf("h%d", i), now)
	}
	for i := 1; i <= 20; i++ {
		if wide, _, _, _, _ := f.observeAndThrottle("cel-1", fmt.Sprintf("h%d", i), now); wide {
			t.Fatal("启动不满一个窗口时不应判为大范围命中")
		}
	}
}
