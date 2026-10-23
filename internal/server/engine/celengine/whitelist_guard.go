package celengine

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine/replay"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// WhitelistGuard 判断一条白名单能不能生效，返回不能生效的原因；为空表示可以。
//
// 白名单是在检测上开的口子。为了降噪加的豁免，最容易在不知不觉中把真实攻击一起放过：
// 规则要求「进程是 bash 且在清日志」，豁免却写「进程是 bash」，这条规则就整体失效了，
// 而且没有任何地方会显示出来。保存时的校验挡得住新条目，挡不住历史条目和规则后来的修改，
// 所以 engine 每次加载白名单都再查一遍，查出来的不生效，并开一条告警让人去改。
type WhitelistGuard func(w *model.AlertWhitelist) string

// attackHit 一条攻击样本命中了一条会独立告警的规则。
type attackHit struct {
	sample   string
	ruleKey  string
	category string
	severity string
	fields   map[string]string
}

// NewWhitelistGuard 用当前加载的规则和随二进制发布的攻击样本构造检查函数。
//
// 两项检查：
//   - 豁免的进程正是规则表达式要求的进程（等于停用规则）；
//   - 豁免会压掉某条攻击样本的告警（在攻击样本上回放：样本命中规则，且豁免匹配这次命中）。
//
// 回放用一个只在内存里的临时引擎：正在检测的引擎求值会改进程树和滑动计数，不能拿样本去喂它。
func NewWhitelistGuard(e *Engine, attacks []replay.Sample, logger *zap.Logger) WhitelistGuard {
	rules := e.Rules()
	// 只查会单独告警的规则：影子、观察阶段与低保真规则在判白名单之前就已跳过，白名单对它们不起作用。
	exprs := make(map[string]string, len(rules))
	for i := range rules {
		if rules[i].AlertsIndependently() && !rules[i].IsLowFidelity() {
			exprs[fmt.Sprintf("cel-%d", rules[i].ID)] = rules[i].Expression
		}
	}
	probe, err := NewInMemory(zap.NewNop(), rules)
	if err != nil {
		logger.Warn("构造白名单检查用的临时引擎失败，只做规则条件检查", zap.Error(err))
	}
	var hits []attackHit
	if probe != nil {
		for _, s := range attacks {
			for _, r := range probe.Evaluate(s.DataType, maps.Clone(s.Fields)) {
				if !r.AlertsIndependently() || r.IsLowFidelity() {
					continue
				}
				hits = append(hits, attackHit{
					sample:   s.Name,
					ruleKey:  fmt.Sprintf("cel-%d", r.ID),
					category: categorize(&r),
					severity: r.Severity,
					fields:   s.Fields,
				})
			}
		}
	}
	return func(w *model.AlertWhitelist) string {
		ruleID := strings.TrimSpace(w.RuleID)
		if ruleID == "" || ruleID == "*" {
			// 对所有规则生效的豁免：哪一条规则点名的正是这个进程，那条就被它整体停掉了。
			// 限定了主机也一样，只是停在那台主机上。
			unscoped := *w
			unscoped.HostID = ""
			for key, expr := range exprs {
				if unscoped.ConflictsWithRule(expr) {
					return fmt.Sprintf("豁免的进程正是规则 %s 要检测的进程，该规则整体失效", key)
				}
			}
		} else if expr := exprs[ruleID]; expr != "" && w.ConflictsWithRule(expr) {
			return "豁免的进程正是规则要检测的进程，规则整体失效"
		}
		for _, h := range hits {
			if h.severity == "critical" && !w.HasEvidenceCondition() {
				continue // 与 matchDBWhitelist 一致：这种条目本来就压不了 critical
			}
			// 限定了主机的豁免，按「攻击就发生在那台主机上」来查。
			if w.MatchesAlert(h.ruleKey, w.HostID, h.category, h.severity, h.fields) {
				return fmt.Sprintf("会压掉攻击样本 %s 在规则 %s 上的告警", h.sample, h.ruleKey)
			}
		}
		return ""
	}
}

// Rules 返回当前加载的规则副本。
func (e *Engine) Rules() []model.DetectionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]model.DetectionRule, 0, len(e.rules))
	for _, cr := range e.rules {
		out = append(out, cr.rule)
	}
	return out
}

// SetWhitelistGuard 注入白名单检查（每次加载白名单时调用以构造最新的检查函数），并立即重新加载一次。
//
// 构造时加载的那份快照没经过检查，接上之后先清空再加载：这次加载失败的话，宁可在下一次
// 成功之前不按任何白名单压制（多出告警），也不沿用一份没查过的快照。
func (g *AlertGenerator) SetWhitelistGuard(build func() WhitelistGuard) {
	g.whitelistGuard = build
	empty := []model.AlertWhitelist{}
	g.dbWhitelist.Store(&empty)
	g.reloadDBWhitelist()
}

// guardWhitelist 剔除不能生效的条目，并为新出现的冲突开告警。
func (g *AlertGenerator) guardWhitelist(rows []model.AlertWhitelist) []model.AlertWhitelist {
	if g.whitelistGuard == nil {
		return rows
	}
	check := g.whitelistGuard()
	kept := rows[:0]
	rejected := make(map[uint]string)
	for i := range rows {
		if !rows[i].Active(time.Now()) {
			kept = append(kept, rows[i])
			continue
		}
		if reason := check(&rows[i]); reason != "" {
			rejected[rows[i].ID] = reason
			continue
		}
		kept = append(kept, rows[i])
	}
	// 只为新出现的冲突开告警：每 5 分钟一次的加载不该每次都去碰告警表。
	// 开告警失败的不记为已报，下一次加载重试。
	reported := make(map[uint]string, len(rejected))
	for _, id := range slices.Sorted(maps.Keys(rejected)) {
		if _, seen := g.rejectedWhitelists[id]; seen || g.raiseWhitelistConflict(id, rejected[id]) {
			reported[id] = rejected[id]
		}
	}
	g.rejectedWhitelists = reported
	return kept
}

// raiseWhitelistConflict 为不能生效的白名单开一条告警：它原本在压的命中从现在起会照常告警，
// 值班需要知道为什么告警突然多了，也需要去改这条白名单。
func (g *AlertGenerator) raiseWhitelistConflict(id uint, reason string) bool {
	g.log.Warn("白名单会让检测失效，已不生效", zap.Uint("whitelist_id", id), zap.String("reason", reason))
	at := model.ToLocalTime(time.Now())
	title := fmt.Sprintf("白名单 #%d 会让检测失效，已停止生效", id)
	desc := fmt.Sprintf("白名单 #%d：%s。engine 的规则检测（CEL、攻击链、威胁情报）已不再按它压制告警，"+
		"它原来压下的命中会照常告警。请收窄这条白名单（限定主机、命令行），或在确认无误后停用。", id, reason)
	_, err := model.UpsertGroupedAlert(g.db, "whitelist-guard-"+strconv.FormatUint(uint64(id), 10), func() model.Alert {
		return model.Alert{
			HostID:      fleetHostID,
			RuleID:      "whitelist-guard",
			Source:      model.AlertSourceDetection,
			Severity:    "high",
			Category:    "suppression_conflict",
			Title:       title,
			Description: desc,
			Status:      model.AlertStatusActive,
			HitCount:    1,
			FirstSeenAt: at,
			LastSeenAt:  at,
		}
	}, func(existing *model.Alert) error {
		return g.db.Model(existing).Updates(map[string]any{
			"last_seen_at": at,
			"description":  desc,
		}).Error
	})
	if err != nil {
		g.log.Warn("为失效的白名单开告警失败，下次加载重试", zap.Uint("whitelist_id", id), zap.Error(err))
		return false
	}
	return true
}
