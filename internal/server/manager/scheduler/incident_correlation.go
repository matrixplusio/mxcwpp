package scheduler

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/casework"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Incident 关联参数（P2）。
const (
	incidentInterval      = 10 * time.Minute // 关联周期
	incidentWindow        = 24 * time.Hour   // 关联时间窗
	incidentMinTactics    = 2                // 跨 ≥ 此战术数 → 成事件
	incidentMinAlerts     = 3                // 或告警数 ≥ 此值 → 成事件
	incidentMultiBoostCap = 100.0
	// incidentMaxPrevalence 单规则活跃告警覆盖主机比例上限；超过则视为环境噪声，剔除后再判事件。
	// 定向攻击是稀有、主机特异的；铺满多数主机的规则对"这台被攻击"零贡献。
	incidentMaxPrevalence = 0.25
)

// attckTacticOrder 按 ATT&CK kill-chain 给战术 ID 排序权重（越小越靠前）。未知放末尾。
var attckTacticOrder = map[string]int{
	"TA0043": 0, "TA0042": 1, "TA0001": 2, "TA0002": 3, "TA0003": 4, "TA0004": 5,
	"TA0005": 6, "TA0006": 7, "TA0007": 8, "TA0008": 9, "TA0009": 10, "TA0011": 11,
	"TA0010": 12, "TA0040": 13,
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// attackChainCategory 攻击链(序列)命中的告警分类，与 celengine.AttackChainCategory 一致。
const attackChainCategory = "attack_chain"

// incidentAlert 是关联用的告警精简视图。
type incidentAlert struct {
	ID          uint
	Severity    string
	RiskScore   float64
	ATTCKTactic string
	Category    string
	RuleID      string
}

// distinctCategoryCount 统计成员告警的不同分类数，作为攻击阶段数的回退度量。
func distinctCategoryCount(alerts []incidentAlert) int {
	seen := map[string]struct{}{}
	for _, a := range alerts {
		if a.Category != "" {
			seen[a.Category] = struct{}{}
		}
	}
	return len(seen)
}

// hasAttackChain 成员中是否含攻击链(多步关联)命中 —— 单条即视为强 IOA 信号。
func hasAttackChain(alerts []incidentAlert) bool {
	for _, a := range alerts {
		if a.Category == attackChainCategory {
			return true
		}
	}
	return false
}

// orderTactics 去重 + 按 kill-chain 排序战术 ID。
func orderTactics(raw []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi, oki := attckTacticOrder[out[i]]
		oj, okj := attckTacticOrder[out[j]]
		if !oki {
			oi = 1 << 30
		}
		if !okj {
			oj = 1 << 30
		}
		return oi < oj
	})
	return out
}

// isIncidentWorthy 判断一组告警是否够成事件：跨多战术 / 告警数达阈值 / 含攻击链命中。
// 攻击链是多步关联的高置信检测，单条即足以成事件(无需再凑战术或告警数)。
func isIncidentWorthy(alertCount, tacticCount int, hasChain bool) bool {
	return hasChain || tacticCount >= incidentMinTactics || alertCount >= incidentMinAlerts
}

// aggregateRisk 聚合风险：成员最高分，跨 ≥2 战术(攻击链推进)×1.2，含攻击链命中再 ×1.3，封顶 100。
func aggregateRisk(maxRisk float64, tacticCount int, hasChain bool) float64 {
	r := maxRisk
	if tacticCount >= incidentMinTactics {
		r *= 1.2
	}
	if hasChain {
		r *= 1.3
	}
	if r > incidentMultiBoostCap {
		r = incidentMultiBoostCap
	}
	return r
}

// summarizeIncident 计算成员告警的聚合属性。
func summarizeIncident(alerts []incidentAlert) (maxSeverity string, maxRisk float64, tactics []string, ids []string) {
	var rawTactics []string
	for _, a := range alerts {
		if severityRank[a.Severity] > severityRank[maxSeverity] {
			maxSeverity = a.Severity
		}
		if a.RiskScore > maxRisk {
			maxRisk = a.RiskScore
		}
		rawTactics = append(rawTactics, a.ATTCKTactic)
		ids = append(ids, fmt.Sprintf("%d", a.ID))
	}
	return maxSeverity, maxRisk, orderTactics(rawTactics), ids
}

// StartIncidentCorrelationScheduler 启动 Incident 关联调度器（P2）。
//
// 周期把同主机、近 incidentWindow 内的 active 告警关联成 Incident：
// 跨 ≥2 ATT&CK 战术或 ≥3 告警即成事件，关联同窗 storyline + behavior_alerts，
// 按 kill-chain 排战术、聚合风险。每主机至多一条 active incident；无 active 告警则自动关闭。
func StartIncidentCorrelationScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(incidentInterval)
	defer ticker.Stop()

	logger.Info("Incident 关联调度器已启动", zap.Duration("interval", incidentInterval))

	processIncidentCorrelation(db, logger)
	for range ticker.C {
		processIncidentCorrelation(db, logger)
	}
}

func processIncidentCorrelation(db *gorm.DB, logger *zap.Logger) {
	cutoff := model.ToLocalTime(time.Now().Add(-incidentWindow))

	// 取近窗有 active 告警的主机。
	var hostIDs []string
	if err := db.Model(&model.Alert{}).
		Where("status = ? AND last_seen_at >= ?", model.AlertStatusActive, cutoff).
		Distinct("host_id").Pluck("host_id", &hostIDs).Error; err != nil {
		logger.Warn("Incident 关联查询主机失败", zap.Error(err))
		return
	}

	// 每周期算一次窗内高流行度规则集合，供各主机剔除环境噪声后再判事件（避免逐主机重复查全舰队）。
	highPrev := highPrevalenceRules(db, cutoff)

	var created, updated int
	for _, hostID := range hostIDs {
		if upsertIncidentForHost(db, logger, hostID, cutoff, highPrev) {
			created++ // 计数粗略：created/updated 合并统计成 affected
		}
	}
	_ = updated

	// 自动关闭：active incident 但主机近窗已无 active 告警。
	closed := autoResolveIncidents(db, cutoff)

	if created > 0 || closed > 0 {
		logger.Info("Incident 关联完成",
			zap.Int("hosts_scanned", len(hostIDs)),
			zap.Int("upserted", created),
			zap.Int("auto_resolved", closed))
	}
}

// suppressedContext 取同主机近窗内被抑制的告警 ID，作为事件的研判上下文。
//
// 抑制规则压下的命中不单独成事件，但当这台主机已经因别的信号成了事件，
// 研判的人需要知道「同期还有哪些被压下的活动」——攻击者恰恰会借用被豁免的进程。
func suppressedContext(db *gorm.DB, hostID string, cutoff model.LocalTime) model.StringArray {
	var ids []uint
	db.Model(&model.Alert{}).
		Where("host_id = ? AND status = ? AND last_seen_at >= ?", hostID, model.AlertStatusSuppressed, cutoff).
		Order("last_seen_at DESC").Limit(100).Pluck("id", &ids)
	out := make(model.StringArray, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.FormatUint(uint64(id), 10))
	}
	return out
}

// upsertIncidentForHost 为单主机构建/更新 active incident。返回是否写入。
func upsertIncidentForHost(db *gorm.DB, logger *zap.Logger, hostID string, cutoff model.LocalTime, highPrev map[string]struct{}) bool {
	var rows []incidentAlert
	if err := db.Model(&model.Alert{}).
		Select("id, severity, risk_score, attck_tactic, category, rule_id").
		Where("host_id = ? AND status = ? AND last_seen_at >= ?", hostID, model.AlertStatusActive, cutoff).
		Scan(&rows).Error; err != nil {
		logger.Warn("Incident 关联查询告警失败", zap.String("host_id", hostID), zap.Error(err))
		return false
	}
	if len(rows) == 0 {
		return false
	}

	// 剔除高流行度(环境噪声)规则告警后再判事件：只有稀有、主机特异的信号才成事件。
	// 若剔除后无信号剩余，主机现存 active incident 应随之关闭（其成员已全为环境噪声）。
	rows = filterHighPrevalence(rows, highPrev)
	chain := hasAttackChain(rows)
	maxSeverity, maxRisk, tactics, alertIDs := summarizeIncident(rows)
	if len(rows) == 0 || !isIncidentWorthy(len(rows), len(tactics), chain) {
		resolveActiveIncident(db, hostID)
		return false
	}

	// 关联同窗 behavior_alerts 数 + 同窗 storyline。
	var behaviorCount int64
	db.Model(&model.BehaviorAlert{}).
		Where("host_id = ? AND created_at >= ?", hostID, cutoff).Count(&behaviorCount)
	storylineIDs := windowStorylineIDs(db, hostID, cutoff)
	contextAlertIDs := suppressedContext(db, hostID, cutoff)

	var hostname string
	db.Model(&model.Host{}).Select("hostname").Where("host_id = ?", hostID).Scan(&hostname)

	now := model.ToLocalTime(time.Now())
	risk := aggregateRisk(maxRisk, len(tactics), chain)
	// 阶段数优先用 ATT&CK 战术数；战术为空时回退用告警分类种类数（更可靠地反映攻击面）
	stageCount := len(tactics)
	if stageCount == 0 {
		stageCount = distinctCategoryCount(rows)
	}
	title := fmt.Sprintf("主机 %s 检测到 %d 阶段攻击(%d 告警)", hostnameOr(hostname, hostID), stageCount, len(rows))
	if chain {
		title += "·含攻击链"
	}

	var existing model.Incident
	err := db.Where("host_id = ? AND status = ?", hostID, model.IncidentStatusActive).First(&existing).Error
	if err == nil {
		existing.Severity = maxSeverity
		existing.RiskScore = risk
		existing.Tactics = strings.Join(tactics, ",")
		existing.TacticCount = len(tactics)
		existing.AlertIDs = alertIDs
		existing.AlertCount = len(rows)
		existing.BehaviorAlertCount = int(behaviorCount)
		existing.StorylineIDs = storylineIDs
		existing.ContextAlertIDs = contextAlertIDs
		existing.Title = title
		existing.LastSeenAt = now
		if err := db.Save(&existing).Error; err != nil {
			logger.Warn("更新 incident 失败", zap.String("host_id", hostID), zap.Error(err))
			return false
		}
		return true
	}
	if err != gorm.ErrRecordNotFound {
		logger.Warn("查询 incident 失败", zap.String("host_id", hostID), zap.Error(err))
		return false
	}

	// 事件创建时即算出响应时限，否则"超时"无从识别——没有截止时间就没有 SLA。
	ackDue, resolveDue := casework.SLADeadlines(maxSeverity, time.Now())
	ackDueAt := model.ToLocalTime(ackDue)
	resolveDueAt := model.ToLocalTime(resolveDue)

	inc := model.Incident{
		IncidentID:         fmt.Sprintf("inc-%s-%d", hostID, time.Now().Unix()),
		AckDueAt:           &ackDueAt,
		ResolveDueAt:       &resolveDueAt,
		HostID:             hostID,
		Hostname:           hostname,
		Status:             model.IncidentStatusActive,
		Severity:           maxSeverity,
		RiskScore:          risk,
		Tactics:            strings.Join(tactics, ","),
		TacticCount:        len(tactics),
		AlertIDs:           alertIDs,
		AlertCount:         len(rows),
		BehaviorAlertCount: int(behaviorCount),
		StorylineIDs:       storylineIDs,
		ContextAlertIDs:    contextAlertIDs,
		Title:              title,
		FirstSeenAt:        now,
		LastSeenAt:         now,
	}
	if err := db.Create(&inc).Error; err != nil {
		logger.Warn("创建 incident 失败", zap.String("host_id", hostID), zap.Error(err))
		return false
	}

	// 自动派给当前一线值班人：新事件默认无人负责，超时告警只会天天响而没人知道该找谁。
	// 派单失败不影响事件本身已经落库——把创建和派单绑成一体，会让排班缺口变成"事件也没了"。
	if err := casework.NewService(db, logger).AutoAssign(inc.IncidentID); err != nil {
		logger.Warn("事件自动派单失败，该事件当前无负责人",
			zap.String("incident_id", inc.IncidentID), zap.Error(err))
	}

	// 关联事件是去重聚合后的视图，本该是最值得通知的一层，此前却是唯一完全没有出口的一层。
	// 抑制身份取 incident_id：同一事件后续更新走的是上面的 update 分支，不会重复发布。
	alertbus.Publish(alertbus.Event{
		Category: model.NotifyCategoryIncident,
		Source:   "incident",
		HostID:   hostID,
		Hostname: hostname,
		Severity: maxSeverity,
		Title:    title,
		Description: fmt.Sprintf("关联 %d 条告警、%d 个战术，风险分 %.0f",
			len(rows), len(tactics), risk),
		DedupKey: "incident|" + inc.IncidentID,
		RefTable: "incidents",
		RefID:    inc.IncidentID,
	})
	return true
}

// autoResolveIncidents 关闭主机近窗已无 active 告警的 active incident。返回关闭数。
func autoResolveIncidents(db *gorm.DB, cutoff model.LocalTime) int {
	var actives []model.Incident
	if err := db.Where("status = ?", model.IncidentStatusActive).Find(&actives).Error; err != nil {
		return 0
	}
	now := model.ToLocalTime(time.Now())
	closed := 0
	for i := range actives {
		var n int64
		db.Model(&model.Alert{}).
			Where("host_id = ? AND status = ? AND last_seen_at >= ?", actives[i].HostID, model.AlertStatusActive, cutoff).
			Count(&n)
		if n > 0 {
			continue
		}
		actives[i].Status = model.IncidentStatusResolved
		actives[i].ResolvedAt = &now
		actives[i].ResolvedBy = model.IncidentResolvedByAuto
		applyAutoCloseConclusion(db, &actives[i], "主机在关联窗口内已没有未处理的告警，事件自动关闭。")
		if err := db.Save(&actives[i]).Error; err == nil {
			closed++
		}
	}
	return closed
}

// highPrevalenceRules 返回窗内"高流行度"规则集合：单规则活跃告警覆盖主机数超过舰队 incidentMaxPrevalence 比例。
// 定向攻击稀有、主机特异；铺满多数主机的规则是环境噪声（运维常态/业务负载），对"这台被攻击"零贡献，
// 应在事件关联前剔除。每关联周期算一次，供本轮所有主机复用。
func highPrevalenceRules(db *gorm.DB, cutoff model.LocalTime) map[string]struct{} {
	high := map[string]struct{}{}

	var fleetSize int64
	if err := db.Model(&model.Host{}).Count(&fleetSize).Error; err != nil || fleetSize <= 0 {
		return high
	}
	threshold := float64(fleetSize) * incidentMaxPrevalence

	type prevRow struct {
		RuleID string
		Hosts  int64
	}
	var rows []prevRow
	if err := db.Model(&model.Alert{}).
		Select("rule_id, COUNT(DISTINCT host_id) AS hosts").
		Where("status = ? AND last_seen_at >= ?", model.AlertStatusActive, cutoff).
		Group("rule_id").Scan(&rows).Error; err != nil {
		return high
	}
	for _, r := range rows {
		if r.RuleID != "" && float64(r.Hosts) > threshold {
			high[r.RuleID] = struct{}{}
		}
	}
	return high
}

// filterHighPrevalence 剔除命中高流行度规则的告警，保留稀有、主机特异的信号。
func filterHighPrevalence(alerts []incidentAlert, highPrev map[string]struct{}) []incidentAlert {
	if len(highPrev) == 0 {
		return alerts
	}
	out := make([]incidentAlert, 0, len(alerts))
	for _, a := range alerts {
		if _, noisy := highPrev[a.RuleID]; noisy {
			continue
		}
		out = append(out, a)
	}
	return out
}

// resolveActiveIncident 关闭主机现存 active incident（其成员告警已全被高流行度过滤或不再够成事件）。
// 与 autoResolveIncidents 互补：后者只处理主机近窗零 active 告警的情况；本函数处理"仍有告警但全为环境噪声"。
func resolveActiveIncident(db *gorm.DB, hostID string) {
	var actives []model.Incident
	if err := db.Where("host_id = ? AND status = ?", hostID, model.IncidentStatusActive).Find(&actives).Error; err != nil {
		return
	}
	now := model.ToLocalTime(time.Now())
	for i := range actives {
		applyAutoCloseConclusion(db, &actives[i], "剩余告警全部来自覆盖多数主机的规则（环境噪声），不再构成事件，自动关闭。")
		db.Model(&actives[i]).Updates(map[string]any{
			"status":         model.IncidentStatusResolved,
			"resolved_at":    now,
			"resolved_by":    model.IncidentResolvedByAuto,
			"close_reason":   actives[i].CloseReason,
			"verdict":        actives[i].Verdict,
			"verdict_reason": actives[i].VerdictReason,
		})
	}
}

// applyAutoCloseConclusion 给自动关闭的事件写上关闭原因，并尽量带上研判结论。
//
// 自动关闭此前不留任何结论：关掉的事件里「成员告警都被人判过了」和「告警过期了、没人看过」
// 完全分不开，事件的准确率也无从统计。关闭原因总是写；研判结论只在成员告警已经被人研判过时
// 才从它们汇总出来——没人判过就留空，事件照常进「待补研判」，不替人下结论。
func applyAutoCloseConclusion(db *gorm.DB, inc *model.Incident, closeReason string) {
	inc.CloseReason = closeReason
	if inc.Verdict != "" || len(inc.AlertIDs) == 0 {
		return
	}
	var verdicts []string
	if err := db.Model(&model.Alert{}).Where("id IN ?", []string(inc.AlertIDs)).Pluck("verdict", &verdicts).Error; err != nil {
		return
	}
	inc.Verdict, inc.VerdictReason = rollupVerdict(verdicts, len(inc.AlertIDs))
}

// rollupVerdict 由成员告警的研判结论汇总出事件结论：有一条真实威胁就是真实威胁；
// 否则有良性行为就是良性；全部成员都判了误报才算误报；其余（没人判、或只判了一部分误报）留空。
func rollupVerdict(verdicts []string, members int) (verdict, reason string) {
	var tp, benign, fp int
	for _, v := range verdicts {
		switch v {
		case model.VerdictTruePositive:
			tp++
		case model.VerdictBenignTruePositive:
			benign++
		case model.VerdictFalsePositive:
			fp++
		}
	}
	judged := tp + benign + fp
	switch {
	case tp > 0:
		verdict = model.VerdictTruePositive
	case benign > 0:
		verdict = model.VerdictBenignTruePositive
	case fp > 0 && fp == members:
		verdict = model.VerdictFalsePositive
	default:
		return "", ""
	}
	return verdict, fmt.Sprintf("由成员告警的研判结论汇总：真实威胁 %d、良性行为 %d、误报 %d、未研判 %d。",
		tp, benign, fp, members-judged)
}

func hostnameOr(hostname, hostID string) string {
	if hostname != "" {
		return hostname
	}
	return hostID
}

// incidentStorylineLimit 一个事件最多挂多少条故事线。
//
// 繁忙主机的故事线数量没有上限，全挂上去既拖慢查询、撑大事件记录，也没人会逐条看。
// 挂的是线索不是全集：只取带告警的，按风险从高到低取前这么多条。
const incidentStorylineLimit = 50

// incidentStorylineScan 从窗口内最近的多少条故事线里挑。
//
// 读取量必须有上限，且与主机的历史总量无关：按风险排序直接取前 N 条的写法，
// 在窗口内不足 N 条时会把这台主机的全部历史读完才结束。先按时间取最近这么多条，
// 再在内存里按风险挑，两种情况下读的行数都不超过这个数。
const incidentStorylineScan = 500

// windowStorylineIDs 取该主机在关联窗口内带告警、风险最高的若干条故事线（从最近 incidentStorylineScan 条里挑）。
//
// 按时间窗取而不是按 active：active 只代表近一小时还有事件，窗口内早些时候结束的
// 同样属于这次事件；不限时间则会把这台主机历史上的全部故事线挂进事件。
func windowStorylineIDs(db *gorm.DB, hostID string, cutoff model.LocalTime) []string {
	// 指定索引：不指定时优化器可能改走单列的 host_id 索引，读出全部历史再过滤。
	// FORCE INDEX 是 MySQL 语法，其它方言不加。
	hint := ""
	if db.Dialector.Name() == "mysql" {
		hint = " FORCE INDEX (idx_story_host_seen)"
	}
	var rows []struct {
		StoryID    string
		RiskScore  float64
		AlertCount int
	}
	db.Raw("SELECT story_id, risk_score, alert_count FROM storylines"+hint+`
		WHERE host_id = ? AND last_seen_at >= ?
		ORDER BY last_seen_at DESC
		LIMIT ?`, hostID, cutoff, incidentStorylineScan).Scan(&rows)

	// 稳定排序：风险相同的保持时间倒序。
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].RiskScore > rows[j].RiskScore })
	ids := make([]string, 0, incidentStorylineLimit)
	for _, r := range rows {
		if r.AlertCount <= 0 {
			continue
		}
		ids = append(ids, r.StoryID)
		if len(ids) == incidentStorylineLimit {
			break
		}
	}
	return ids
}
