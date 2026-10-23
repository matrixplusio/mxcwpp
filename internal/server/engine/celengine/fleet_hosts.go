package celengine

import (
	"sync"
	"time"
)

// activeHosts 统计 engine 自己在时间窗内看到过事件的主机，作为全舰队守卫的分母。
//
// 分母不能取数据库里 status=online 的主机数。那是心跳写库的结果，恰恰在出事时最不准：
// 心跳写不进库时在线数会远低于实际，而事件仍在进来，守卫的门槛跟着掉到几台主机，
// 大批告警被压成 suppressed——越是出事越沉默。用 engine 实际收到事件的主机数，
// 分母与「谁在被检测」是同一件事。
type activeHosts struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	started   time.Time // 第一次观测的时间；不满一个窗口时计数还在爬升，不可作分母
	lastPrune time.Time
	// hourly 最近 24 小时每小时观测到的最大活跃主机数，用来识别分母突然塌缩。
	hourly [24]hourPeak
}

type hourPeak struct {
	hour int64 // Unix 小时数
	n    int
}

func newActiveHosts() *activeHosts {
	return &activeHosts{seen: make(map[string]time.Time)}
}

// observe 记一次主机有事件。热路径：每个事件调用一次。
func (a *activeHosts) observe(hostID string, now time.Time) {
	if hostID == "" {
		return
	}
	a.mu.Lock()
	if a.started.IsZero() {
		a.started = now
	}
	a.seen[hostID] = now
	if now.Sub(a.lastPrune) >= fleetGuardPruneGap {
		a.pruneLocked(now)
	}
	a.mu.Unlock()
}

func (a *activeHosts) pruneLocked(now time.Time) {
	cutoff := now.Add(-fleetGuardWindow)
	for h, at := range a.seen {
		if at.Before(cutoff) {
			delete(a.seen, h)
		}
	}
	a.lastPrune = now
	hour := now.Unix() / 3600
	slot := &a.hourly[hour%int64(len(a.hourly))]
	if slot.hour != hour {
		*slot = hourPeak{hour: hour}
	}
	if n := len(a.seen); n > slot.n {
		slot.n = n
	}
}

// stats 返回窗口内活跃主机数与最近 24 小时峰值，供指标暴露。
func (a *activeHosts) stats(now time.Time) (n, peak int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastPrune) >= fleetGuardPruneGap {
		a.pruneLocked(now)
	}
	oldest := now.Unix()/3600 - int64(len(a.hourly)) + 1
	for _, p := range a.hourly {
		if p.hour >= oldest && p.n > peak {
			peak = p.n
		}
	}
	return len(a.seen), peak
}

// snapshot 返回窗口内活跃主机数，以及这个数能不能当分母用。
//
// warm 为假：engine 启动不满一个窗口，计数还在从零爬升，命中面占比会虚高，不做判断。
// collapsed 为真：活跃数不到最近 24 小时峰值的一半，agent 大面积断连或停发，
// 剩下的少数主机撑不起「大多数」，命中面再大也只聚合、不压制。
func (a *activeHosts) snapshot(now time.Time) (n int, warm, collapsed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastPrune) >= fleetGuardPruneGap {
		a.pruneLocked(now)
	}
	n = len(a.seen)
	if a.started.IsZero() || now.Sub(a.started) < fleetGuardWindow {
		return n, false, false
	}
	peak := 0
	oldest := now.Unix()/3600 - int64(len(a.hourly)) + 1
	for _, p := range a.hourly {
		if p.hour >= oldest && p.n > peak {
			peak = p.n
		}
	}
	return n, true, n*2 < peak
}
