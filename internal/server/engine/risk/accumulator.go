// Package risk 按实体累积检测命中的风险，凑出攻击形态时才算「本会告警」。
//
// 单个弱信号（枚举命令、sudo、/tmp 写可执行文件、端口外连……）正常系统每天都在做，单独告警
// 只会制造噪声；直接丢弃又会让多步攻击里的每一步都看不见。这里把一个时间窗内的命中按 ATT&CK
// 战术叠加：同一战术只取最高的一个，跨战术才累加，跨战术够多或分值够高时记一次判断。
//
// 每次命中同时计入两层实体：
//   - 血缘层（主机 + 进程血缘根）：精确，同一台机器上互不相关的活动不会凑在一起；
//   - 主机层：兜底。血缘是从 engine 看到的执行事件推出来的，可以被攻击者拆开（借 cron、ssh 回环、
//     伪装成 sshd 的程序名派生每一步），也会因为祖先进程早于 agent 启动、engine 重启而断开。
//     主机层不受这些影响，阈值更严。
//
// 当前只有影子模式：判断写入 risk_decisions 表供对照，不产生告警。
package risk

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// Window 累积窗口：实体的每个信号在窗口内有效。
	Window = time.Hour
	// maxEpisode 一段活动的最长时长。一直有命中的实体不会自然结束，不设上限的话，
	// 嘈杂实体会把之后出现的真实攻击「吞」进一段早已判过的活动里，看不出变化。
	maxEpisode = 6 * time.Hour
	// minTacticWeight 一个战术要算数，其中最高的信号（乘过普遍性系数之后）至少要有这个权重。
	minTacticWeight = 1.0
	// lowWeight 普遍性系数只作用于低于这个权重的信号（即 low 级）。中危及以上不因「常见」降分：
	// 攻击者用全舰队都有的解释器（python3、bash、curl）执行载荷，系数键里的程序路径就是普遍的。
	lowWeight = 3.0
	// notableWeight 中危以上：新出现这一级的规则时，即使战术数没变也要记一笔。嘈杂实体里每个战术
	// 早已被噪声占住最高分，后来的攻击步骤不抬分、不加战术，只有按「新规则」才看得出来。
	notableWeight = 3.0
	// maxSignalsKept 每个实体保留的贡献明细上限。
	maxSignalsKept = 20
	// maxEntitiesPerHost / maxEntities 血缘层实体的内存上限。超出时这次命中只计入主机层。
	maxEntitiesPerHost = 500
	maxEntities        = 200000
	// persistMinGap 分值上涨时两次写库的最小间隔。
	persistMinGap = time.Minute
	// futureSkew 事件时间最多比墙钟超前这么多，再往前按墙钟计（发送方时钟跳变、多实例时钟偏差）。
	futureSkew = 5 * time.Minute
	// idleWall 按墙钟超过这么久没有更新的实体一律清掉：主机安静或分区停滞时，它自己的事件时间不再前进。
	idleWall = 6 * time.Hour
)

// Level 实体的层级。
const (
	LevelLineage = "lineage"
	LevelHost    = "host"
)

// thresholds 各层的候选与告警阈值。初值，影子数据出来后再调。主机层把一台机器上所有活动
// 叠在一起，噪声更多，阈值更严。
//
// 按战术数告警还要求一个最低分（tacticMinScore）：管理员在一个会话里跑 uname、找隐藏文件、sudo，
// 常见低危信号也能凑够个数，但分值很低；真实攻击里总有中高危的一步。
var thresholds = map[string]struct {
	candidate, alertTactics int
	tacticMinScore          float64
	alertScore              float64
}{
	LevelLineage: {candidate: 2, alertTactics: 3, tacticMinScore: 6, alertScore: 16},
	LevelHost:    {candidate: 3, alertTactics: 4, tacticMinScore: 10, alertScore: 24},
}

// ModeShadow 只记录判断，不产生告警。
const ModeShadow = "shadow"

var (
	clampedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_future_time_clamped_total",
		Help: "Hits whose event time was ahead of the wall clock by more than the tolerance and was clamped.",
	})
	observedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_hits_total",
		Help: "Detection hits seen by risk accumulation, labeled by result (lineage / host_only / capped / unknown_host / no_tactic / shadow_rule).",
	}, []string{"result"})
	decisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_decisions_total",
		Help: "Risk decisions written, labeled by level and would_alert.",
	}, []string{"level", "would_alert"})
	persistDropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_persist_dropped_total",
		Help: "Risk decisions dropped because the write queue was full or the write failed.",
	})
	entitiesGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_entities",
		Help: "Entities currently holding signals in the risk window, by level.",
	}, []string{"level"})
)

func init() {
	for _, r := range []string{"lineage", "host_only", "capped", "unknown_host", "no_tactic", "shadow_rule"} {
		observedTotal.WithLabelValues(r).Add(0)
	}
	for _, l := range []string{LevelLineage, LevelHost} {
		decisionsTotal.WithLabelValues(l, "true").Add(0)
		decisionsTotal.WithLabelValues(l, "false").Add(0)
		entitiesGauge.WithLabelValues(l).Set(0)
	}
}

// Hit 一次检测命中。
type Hit struct {
	HostID    string
	PID       string
	RuleKey   string // 与告警表一致：cel-N / seq-N / ioc-ip ...
	RuleName  string
	Severity  string
	Tactic    string // TA####；推不出来时为空，不参与计分
	Technique string
	Exe       string
	Cmdline   string
	// At 事件时间（取 Kafka 消息时间）。积压追赶时用处理时间会把几小时的事件压进一个窗口。
	At time.Time
	// Shadow 规则处于影子阶段：还没验证过的规则不该影响判断。
	Shadow bool
}

// Deps 外部依赖。为空时按最保守的默认处理。
type Deps struct {
	// KnownHost 主机是否在主机表里登记过。为空时一律不计。
	KnownHost func(hostID string) bool
	// Lineage 返回进程的血缘根。为空或解析不了时只计入主机层。
	Lineage func(hostID, pid string) (key, rootPID, rootExe, rootCmdline string, ok bool)
	// Prevalence 返回「规则 + 程序」的普遍性系数（0.3～1.0）。为空时为 1。
	Prevalence func(ruleKey, exe string) float64
	// Persist 写一条判断。为空时不写。
	Persist func(model.RiskDecision) error
}

type signal struct {
	At       time.Time `json:"at"`
	RuleKey  string    `json:"rule"`
	RuleName string    `json:"name,omitempty"`
	Tactic   string    `json:"tactic"`
	Severity string    `json:"severity"`
	Weight   float64   `json:"weight"`
	// Base 乘普遍性系数之前的权重：血缘层用它判断战术是否算数。
	Base    float64 `json:"-"`
	Exe     string  `json:"exe,omitempty"`
	Cmdline string  `json:"cmdline,omitempty"`
	Count   int     `json:"count"`
}

type entity struct {
	key, level, hostID        string
	rootPID, rootExe, rootCmd string
	episodeStart, first, last time.Time
	signals                   map[string]*signal // tactic|rule → 最近一次
	persisted                 bool
	persistedAt               time.Time
	persistedTactics          int
	persistedAlert            bool
	persistedScore            float64
	persistedRules            map[string]bool // 已写入过的中危以上规则
	lastWall                  time.Time       // 最近一次更新时的墙钟
}

// Accumulator 实体风险累积器。并发安全。
type Accumulator struct {
	deps   Deps
	mode   string
	log    *zap.Logger
	queue  chan model.RiskDecision
	mu     sync.Mutex
	ents   map[string]*entity
	byHost map[string]int // 每台主机的血缘层实体数
	// lineageN 血缘层实体总数（增量维护，避免每次命中都遍历 byHost）。
	lineageN int
	// hostLatest 每台主机见过的最大事件时间。过期按它判断：消费积压时墙钟远超事件时间，按墙钟会把
	// 实体每分钟清空一次；用全局最大值也不行，各分区积压程度不同，一台主机的事件只在一个分区里。
	hostLatest map[string]time.Time
	// now 墙钟，测试替换。
	now func() time.Time
}

// New 构造累积器并启动写库协程。
func New(deps Deps, mode string, logger *zap.Logger) *Accumulator {
	a := &Accumulator{
		deps:       deps,
		mode:       mode,
		log:        logger,
		queue:      make(chan model.RiskDecision, 10000),
		ents:       make(map[string]*entity),
		byHost:     make(map[string]int),
		hostLatest: make(map[string]time.Time),
		now:        time.Now,
	}
	go a.writer()
	return a
}

// Weight 级别对应的基础权重。
func Weight(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 10
	case "high":
		return 6
	case "medium":
		return 3
	case "low":
		return 1
	}
	return 1
}

// Observe 并入一次命中。
func (a *Accumulator) Observe(h Hit) {
	switch {
	case h.Shadow:
		observedTotal.WithLabelValues("shadow_rule").Inc()
		return
	case h.HostID == "" || a.deps.KnownHost == nil || !a.deps.KnownHost(h.HostID):
		observedTotal.WithLabelValues("unknown_host").Inc()
		return
	case h.Tactic == "":
		// 推不出战术的命中不占名额：把它们算成一个「unknown」战术，会让两类噪声凑够个数，
		// 也会让几条不同的未映射规则被合成一个战术。
		observedTotal.WithLabelValues("no_tactic").Inc()
		return
	}
	wall := a.now()
	if h.At.IsZero() {
		h.At = wall
	} else if h.At.After(wall.Add(futureSkew)) {
		clampedTotal.Inc()
		h.At = wall
	}
	base := Weight(h.Severity)
	weight := base
	if base < lowWeight && a.deps.Prevalence != nil {
		weight *= a.deps.Prevalence(h.RuleKey, h.Exe)
	}
	h.Cmdline = sanitize.Cmdline(h.Cmdline)

	var lineageKey, rootPID, rootExe, rootCmd string
	resolved := false
	if a.deps.Lineage != nil && h.PID != "" {
		var k string
		k, rootPID, rootExe, rootCmd, resolved = a.deps.Lineage(h.HostID, h.PID)
		lineageKey = h.HostID + "|" + k
		rootCmd = sanitize.Cmdline(rootCmd)
	}

	var writes []model.RiskDecision
	a.mu.Lock()
	if h.At.After(a.hostLatest[h.HostID]) {
		a.hostLatest[h.HostID] = h.At
	}
	result := "host_only"
	if resolved {
		if e := a.entityLocked(lineageKey, LevelLineage, h, rootPID, rootExe, rootCmd); e != nil {
			result = "lineage"
			if d, ok := a.applyLocked(e, h, base, weight); ok {
				writes = append(writes, d)
			}
		} else {
			result = "capped"
		}
	}
	if e := a.entityLocked("host:"+h.HostID, LevelHost, h, "", "", ""); e != nil {
		if d, ok := a.applyLocked(e, h, base, weight); ok {
			writes = append(writes, d)
		}
	}
	a.updateGaugesLocked()
	a.mu.Unlock()
	observedTotal.WithLabelValues(result).Inc()
	for _, d := range writes {
		a.enqueue(d)
	}
}

// entityLocked 取出或新建实体。整段活动滑出窗口、或一段活动超过最长时长时从头开始。
// 血缘层超出上限时返回 nil（这次命中只计入主机层）。
func (a *Accumulator) entityLocked(key, level string, h Hit, rootPID, rootExe, rootCmd string) *entity {
	e := a.ents[key]
	if e != nil && (h.At.Sub(e.last) > Window || h.At.Sub(e.episodeStart) > maxEpisode) {
		a.dropLocked(e)
		e = nil
	}
	if e != nil {
		return e
	}
	if level == LevelLineage && (a.byHost[h.HostID] >= maxEntitiesPerHost || a.lineageN >= maxEntities) {
		return nil
	}
	e = &entity{key: key, level: level, hostID: h.HostID, rootPID: rootPID, rootExe: rootExe, rootCmd: rootCmd,
		episodeStart: h.At, first: h.At, signals: map[string]*signal{}, persistedRules: map[string]bool{}}
	a.ents[key] = e
	if level == LevelLineage {
		a.byHost[h.HostID]++
		a.lineageN++
	}
	return e
}

func (a *Accumulator) applyLocked(e *entity, h Hit, base, weight float64) (model.RiskDecision, bool) {
	if h.At.After(e.last) {
		e.last = h.At
	}
	e.lastWall = a.now()
	sk := h.Tactic + "|" + h.RuleKey
	s := e.signals[sk]
	if s == nil {
		s = &signal{RuleKey: h.RuleKey, RuleName: h.RuleName, Tactic: h.Tactic, Severity: h.Severity}
		e.signals[sk] = s
	}
	if h.At.After(s.At) {
		s.At = h.At
	}
	// 同一规则在窗口内取最高的一次：后来的普遍程序触发同一规则，不能把罕见程序那一次的分值冲掉。
	if s.Count == 0 || weight > s.Weight {
		s.Weight, s.Exe, s.Cmdline = weight, clip(h.Exe, 256), clip(h.Cmdline, 256)
	}
	if base > s.Base {
		s.Base = base
	}
	s.Count++
	return a.evaluateLocked(e, h.At)
}

// evaluateLocked 计算实体当前的有效战术与分值，决定是否需要写一条判断。
func (a *Accumulator) evaluateLocked(e *entity, now time.Time) (model.RiskDecision, bool) {
	best := map[string]*signal{}
	var live []*signal
	for k, s := range e.signals {
		if now.Sub(s.At) > Window {
			delete(e.signals, k)
			continue
		}
		live = append(live, s)
		if b := best[s.Tactic]; b == nil || s.Weight > b.Weight {
			best[s.Tactic] = s
		}
	}
	var score, baseScore float64
	tactics := make([]string, 0, len(best))
	for t, s := range best {
		// 血缘层范围已经很窄，常见的低危信号（whoami、id、uname）在同一条血缘里出现也是攻击链的一环，
		// 只降分、不清掉这个战术。主机层把整台机器的活动叠在一起，常见低危信号无处不在，按降分后的权重算。
		valid := s.Weight
		if e.level == LevelLineage {
			valid = s.Base
		}
		if valid < minTacticWeight {
			continue
		}
		score += s.Weight
		baseScore += s.Base
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	n := len(tactics)
	th := thresholds[e.level]
	if n < th.candidate {
		// 掉到候选以下也要记住，之后由另一组战术重新升上来时才算变化。
		e.persistedTactics = n
		return model.RiskDecision{}, false
	}
	// 血缘层按战术数告警的最低分用降分前的分值：血缘层已经接纳常见低危信号作为战术，
	// 再用降分后的分值卡门槛，等于把这一步又抵消掉。主机层仍用降分后的分值。
	minCheck := score
	if e.level == LevelLineage {
		minCheck = baseScore
	}
	wouldAlert := (n >= th.alertTactics && minCheck >= th.tacticMinScore) || score >= th.alertScore
	// 新出现的高危以上规则：战术数没变也要记一笔，否则嘈杂实体里冒出的真实攻击看不出来。
	newNotable := false
	for _, s := range live {
		if s.Base >= notableWeight && !e.persistedRules[s.RuleKey] {
			newNotable = true
		}
	}
	changed := !e.persisted || n != e.persistedTactics || wouldAlert != e.persistedAlert || newNotable
	grew := score >= e.persistedScore+1 && now.Sub(e.persistedAt) >= persistMinGap
	if !changed && !grew {
		return model.RiskDecision{}, false
	}

	sort.Slice(live, func(i, j int) bool { return live[i].Weight > live[j].Weight })
	kept := live
	if len(kept) > maxSignalsKept {
		kept = kept[:maxSignalsKept]
	}
	detail, _ := json.Marshal(kept)
	d := model.RiskDecision{
		EntityKey:    clip(e.key, 191),
		Level:        e.level,
		EpisodeStart: model.ToLocalTime(e.episodeStart),
		HostID:       e.hostID,
		RootPID:      e.rootPID,
		RootExe:      clip(e.rootExe, 512),
		RootCmdline:  clip(e.rootCmd, 1024),
		FirstSeen:    model.ToLocalTime(e.first),
		LastSeen:     model.ToLocalTime(e.last),
		Tactics:      clip(strings.Join(tactics, ","), 512),
		TacticCount:  n,
		Score:        score,
		BaseScore:    baseScore,
		WouldAlert:   wouldAlert,
		Signals:      string(detail),
		Mode:         a.mode,
	}
	// 先记账；入队失败或写库失败时由 enqueue / writer 把 persisted 置回 false，下次命中重新写。
	e.persisted, e.persistedAt, e.persistedTactics, e.persistedAlert, e.persistedScore = true, now, n, wouldAlert, score
	for _, s := range live {
		if s.Base >= notableWeight {
			e.persistedRules[s.RuleKey] = true
		}
	}
	return d, true
}

// Sweep 清掉过期的实体。由调用方定期执行（wall 为当前墙钟）。
//
// 过期按该主机见过的最大事件时间判断（见 hostLatest）；按墙钟超过 idleWall 没有更新的也清掉，
// 否则主机安静下来、或它的分区停滞时，实体会一直挂着。
func (a *Accumulator) Sweep(wall time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.ents {
		if a.hostLatest[e.hostID].Sub(e.last) > Window || wall.Sub(e.lastWall) > idleWall {
			a.dropLocked(e)
		}
	}
	for h := range a.hostLatest {
		if a.byHost[h] == 0 && a.ents["host:"+h] == nil {
			delete(a.hostLatest, h)
		}
	}
	a.updateGaugesLocked()
}

func (a *Accumulator) dropLocked(e *entity) {
	delete(a.ents, e.key)
	if e.level != LevelLineage {
		return
	}
	a.lineageN--
	if a.byHost[e.hostID]--; a.byHost[e.hostID] <= 0 {
		delete(a.byHost, e.hostID)
	}
}

func (a *Accumulator) updateGaugesLocked() {
	entitiesGauge.WithLabelValues(LevelLineage).Set(float64(a.lineageN))
	entitiesGauge.WithLabelValues(LevelHost).Set(float64(len(a.ents) - a.lineageN))
}

// enqueue 交给写库协程；队列满时丢弃并计数，不阻塞检测热路径。丢掉的判断让实体回到
// 「未写过」，下一次命中时重新评估、重新写。
func (a *Accumulator) enqueue(d model.RiskDecision) {
	select {
	case a.queue <- d:
	default:
		persistDropped.Inc()
		a.markUnpersisted(d.EntityKey)
	}
}

func (a *Accumulator) markUnpersisted(key string) {
	a.mu.Lock()
	if e := a.ents[key]; e != nil {
		e.persisted = false
	}
	a.mu.Unlock()
}

func (a *Accumulator) writer() {
	for d := range a.queue {
		if a.deps.Persist == nil {
			continue
		}
		if err := a.deps.Persist(d); err != nil {
			persistDropped.Inc()
			a.log.Warn("风险判断写库失败", zap.String("entity", d.EntityKey), zap.Error(err))
			a.markUnpersisted(d.EntityKey)
			continue
		}
		decisionsTotal.WithLabelValues(d.Level, boolLabel(d.WouldAlert)).Inc()
	}
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func clip(v string, n int) string {
	v = strings.ToValidUTF8(v, "")
	if len(v) > n {
		return strings.ToValidUTF8(v[:n], "")
	}
	return v
}
