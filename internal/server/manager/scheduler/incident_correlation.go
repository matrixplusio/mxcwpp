package scheduler

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Incident 关联参数（P2）。
const (
	incidentInterval      = 10 * time.Minute // 关联周期
	incidentWindow        = 24 * time.Hour   // 关联时间窗
	incidentMinTactics    = 2                // 跨 ≥ 此战术数 → 成事件
	incidentMinAlerts     = 3                // 或告警数 ≥ 此值 → 成事件
	incidentMultiBoostCap = 100.0
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

	var created, updated int
	for _, hostID := range hostIDs {
		if upsertIncidentForHost(db, logger, hostID, cutoff) {
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

// upsertIncidentForHost 为单主机构建/更新 active incident。返回是否写入。
func upsertIncidentForHost(db *gorm.DB, logger *zap.Logger, hostID string, cutoff model.LocalTime) bool {
	var rows []incidentAlert
	if err := db.Model(&model.Alert{}).
		Select("id, severity, risk_score, attck_tactic, category").
		Where("host_id = ? AND status = ? AND last_seen_at >= ?", hostID, model.AlertStatusActive, cutoff).
		Scan(&rows).Error; err != nil {
		logger.Warn("Incident 关联查询告警失败", zap.String("host_id", hostID), zap.Error(err))
		return false
	}
	if len(rows) == 0 {
		return false
	}

	chain := hasAttackChain(rows)
	maxSeverity, maxRisk, tactics, alertIDs := summarizeIncident(rows)
	if !isIncidentWorthy(len(rows), len(tactics), chain) {
		return false
	}

	// 关联同窗 behavior_alerts 数 + active storyline。
	var behaviorCount int64
	db.Model(&model.BehaviorAlert{}).
		Where("host_id = ? AND created_at >= ?", hostID, cutoff).Count(&behaviorCount)
	var storylineIDs []string
	db.Model(&model.Storyline{}).
		Where("host_id = ? AND status = ?", hostID, "active").Pluck("story_id", &storylineIDs)

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

	inc := model.Incident{
		IncidentID:         fmt.Sprintf("inc-%s-%d", hostID, time.Now().Unix()),
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
		Title:              title,
		FirstSeenAt:        now,
		LastSeenAt:         now,
	}
	if err := db.Create(&inc).Error; err != nil {
		logger.Warn("创建 incident 失败", zap.String("host_id", hostID), zap.Error(err))
		return false
	}
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
		actives[i].ResolvedBy = "auto"
		if err := db.Save(&actives[i]).Error; err == nil {
			closed++
		}
	}
	return closed
}

func hostnameOr(hostname, hostID string) string {
	if hostname != "" {
		return hostname
	}
	return hostID
}
