package celengine

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 全舰队命中守卫。
//
// 一条规则在同一时间窗内对大多数在线主机都命中，几乎总是规则本身失真：
// 匹配条件把某个日常行为当成了攻击。此前这类规则在每台主机上各出一条告警，
// 告警数量多到只能整批忽略——于是真正的命中也一起看不见了。
//
// 守卫的做法是降级与聚合，而不是丢弃：各主机的命中照常记为 suppressed 留痕，
// 另外合并出一条汇总告警交人复核。
//
// 但「大多数主机同时命中」有两种解释：规则失真，或者真的在大范围发生——勒索软件借配置管理
// 同时下发、蠕虫传播、供应链投毒都是这个形态。守卫分不清这两者，所以：
//   - 实际会落成 critical 的规则（已获 critical 准入，攻击链同理），只聚合、不压制各主机的告警。
//     这些规则本来就是因为特异性高才被准入的，一起失真的可能性小，而漏掉一次爆发的代价最大。
//     标准只有这一条，不按规则种类另开口子：未准入的攻击链在全网例行变更时一样会成片命中。
//   - 汇总告警沿用规则实际的级别，不因为命中面大而降级。
const (
	fleetGuardWindow   = time.Hour
	fleetGuardRatio    = 0.5
	fleetGuardMinHosts = 10
	fleetGuardPruneGap = time.Minute
	// fleetAlertRefreshGap 汇总告警的最小刷新间隔。失真期间每条命中都会走到这里，
	// 不节流的话所有命中都去改同一行告警。
	fleetAlertRefreshGap = time.Minute
)

type fleetRuleHits struct {
	hosts       map[string]time.Time
	lastPrune   time.Time
	lastRefresh time.Time // 上次刷新汇总告警的时间
}

type fleetGuard struct {
	mu    sync.Mutex
	rules map[string]*fleetRuleHits
	// hosts 分母：engine 实际收到事件的主机（见 fleet_hosts.go）。
	hosts *activeHosts
}

func newFleetGuard() *fleetGuard {
	return &fleetGuard{rules: make(map[string]*fleetRuleHits), hosts: newActiveHosts()}
}

// ObserveHost 记一次主机有事件，供全舰队守卫算分母。每个事件都要调，不只是命中规则的。
func (g *AlertGenerator) ObserveHost(hostID string, now time.Time) {
	if g == nil || g.fleet == nil || !g.knownHost(hostID) {
		return
	}
	g.fleet.hosts.observe(hostID, now)
}

// FleetGuardHosts 返回守卫当前的分母（1 小时内有事件的登记主机数）与最近 24 小时峰值。
// 守卫平时不触发，看不出分母算得对不对；暴露成指标，才能与在线主机数对照。
func (g *AlertGenerator) FleetGuardHosts() (active, peak int) {
	if g == nil || g.fleet == nil {
		return 0, 0
	}
	return g.fleet.hosts.stats(time.Now())
}

// KnownHost 判断主机是否在主机表里登记过（见 knownHost）。
func (g *AlertGenerator) KnownHost(hostID string) bool { return g != nil && g.knownHost(hostID) }

// knownHost 判断事件里的主机是否在主机表里登记过。
//
// 守卫的分子和分母都只数登记过的主机：事件里的 host_id 来自上报方，若能伪造，大量假 ID
// 会同时抬高命中数和主机数，把一条规则推过「大范围命中」的门槛，压掉真实主机的告警。
// 主机快照还没加载时一律不计，守卫因此不做判断，偏向照常告警。
func (g *AlertGenerator) knownHost(hostID string) bool {
	snap := g.hostCreatedAt.Load()
	if snap == nil || hostID == "" {
		return false
	}
	_, ok := (*snap)[hostID]
	return ok
}

// observe 记一次命中，返回该规则此刻是否处于失真状态，以及窗口内命中的主机数。
func (f *fleetGuard) observe(ruleKey, hostID string, now time.Time, online int) (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rules[ruleKey]
	if r == nil {
		r = &fleetRuleHits{hosts: make(map[string]time.Time)}
		f.rules[ruleKey] = r
	}
	r.hosts[hostID] = now
	if now.Sub(r.lastPrune) >= fleetGuardPruneGap {
		cutoff := now.Add(-fleetGuardWindow)
		for h, at := range r.hosts {
			if at.Before(cutoff) {
				delete(r.hosts, h)
			}
		}
		r.lastPrune = now
	}
	n := len(r.hosts)
	if online < fleetGuardMinHosts {
		return false, n
	}
	return float64(n) >= fleetGuardRatio*float64(online), n
}

// fleetHostID 合并告警不属于任何一台主机。
const fleetHostID = "fleet"

// fleetAlertCategory 汇总告警的分类。沿用旧值：已有的查询与界面按它筛选。
const fleetAlertCategory = "rule_distortion"

// checkFleet 记录一次命中，命中面超过阈值时刷新汇总告警，并返回这次命中是否应当被压制。
//
// severity 是这条规则的告警实际会落成的级别（已过 critical 准入）。实际级别为 critical 的只聚合、不压制。
func (g *AlertGenerator) checkFleet(ruleKey, ruleName, severity, hostID string, now time.Time) bool {
	if g.fleet == nil || !g.knownHost(hostID) {
		return false
	}
	wide, hit, online, collapsed, refresh := g.fleet.observeAndThrottle(ruleKey, hostID, now)
	if !wide {
		return false
	}
	// 分母塌缩时（大面积断连）只聚合不压制：此时的「大多数」只是少数还连着的主机。
	suppress := severity != "critical" && !collapsed
	if refresh {
		g.upsertFleetAlert(ruleKey, ruleName, severity, hit, online, suppress, collapsed, now)
	}
	return suppress
}

// observeAndThrottle 记一次命中并按活跃主机数判断命中面，另返回分母是否塌缩、
// 这次是否轮到刷新汇总告警。engine 启动不满一个窗口时不做判断。
func (f *fleetGuard) observeAndThrottle(ruleKey, hostID string, now time.Time) (wide bool, hit, online int, collapsed, refresh bool) {
	f.hosts.observe(hostID, now)
	online, warm, collapsed := f.hosts.snapshot(now)
	if !warm {
		online = 0 // 低于最小主机数，observe 只记命中、不判失真
	}
	wide, hit = f.observe(ruleKey, hostID, now, online)
	if !wide {
		return false, hit, online, collapsed, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rules[ruleKey]
	if r == nil || now.Sub(r.lastRefresh) < fleetAlertRefreshGap {
		return true, hit, online, collapsed, false
	}
	r.lastRefresh = now
	return true, hit, online, collapsed, true
}

// upsertFleetAlert 维护大范围命中的汇总告警：一条规则一条，进处置队列。
func (g *AlertGenerator) upsertFleetAlert(ruleKey, ruleName, severity string, hit, online int, suppressed, collapsed bool, now time.Time) {
	title := fmt.Sprintf("规则大范围命中：%s（%d/%d 台有事件上报的主机）", ruleName, hit, online)
	desc := fmt.Sprintf("规则 %s 在 %s 内命中了 %d 台主机，超过在线主机的 %.0f%%。"+
		"可能是规则把日常行为当成了攻击，也可能是真实的大范围事件（勒索软件借配置管理下发、蠕虫传播、供应链投毒）。"+
		"请先排除后者。",
		ruleKey, fleetGuardWindow, hit, fleetGuardRatio*100)
	switch {
	case suppressed:
		desc += "各主机的命中已记为 suppressed 留痕，不单独告警，可按规则查询。"
	case collapsed:
		desc += "当前有事件上报的主机数不到 24 小时峰值的一半（大面积断连或停发），命中面不可信，各主机的告警照常产生，没有被压制。"
	default:
		desc += "这条规则的告警级别为 critical，各主机的告警照常产生，没有被压制。"
	}
	at := model.ToLocalTime(now)
	created, err := model.UpsertGroupedAlert(g.db, "fleet-"+ruleKey, func() model.Alert {
		return model.Alert{
			HostID:      fleetHostID,
			RuleID:      ruleKey,
			Source:      model.AlertSourceDetection,
			Severity:    severity,
			Category:    fleetAlertCategory,
			Title:       title,
			Description: desc,
			Status:      model.AlertStatusActive,
			HitCount:    1,
			FirstSeenAt: at,
			LastSeenAt:  at,
		}
	}, func(existing *model.Alert) error {
		upd := map[string]any{
			"last_seen_at": at,
			"hit_count":    gorm.Expr("hit_count + 1"),
			"title":        title,
			"description":  desc,
		}
		// 只升不降：旧版本开的汇总告警带着当时封顶的级别，要跟上来；
		// 但规则之后被撤销准入、或有人改过级别，不能把一条开着的告警悄悄调低。
		if scanSeverityRank(severity) > scanSeverityRank(existing.Severity) {
			upd["severity"] = severity
		}
		return g.db.Model(existing).Updates(upd).Error
	})
	if err != nil {
		g.log.Warn("维护规则失真合并告警失败", zap.String("rule", ruleKey), zap.Error(err))
		return
	}
	if created != nil {
		g.log.Warn("规则命中面超过全舰队阈值，已降级并合并",
			zap.String("rule", ruleKey), zap.Int("hosts", hit), zap.Int("online", online))
	}
}
