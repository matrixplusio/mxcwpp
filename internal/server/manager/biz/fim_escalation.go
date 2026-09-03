package biz

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// fimBatchHostThreshold 判定"批量变更"的主机数下限。
	//
	// 同一个文件在这么多台主机上发生同种变更，是包管理器更新的特征而非入侵：
	// 攻击者要在全机群同时替换同一个二进制，代价远高于收益，也没有理由这么整齐。
	// 达到这个数就合并成一条告警，并把受影响主机数写进去——聚合不是丢弃，
	// 一条标着"影响 N 台"的告警比 N 条孤立告警更醒目，也更接近事情本身。
	//
	// 定得太低会把小范围的真实横向移动也合并掉；太高则挡不住成规模的包更新。
	fimBatchHostThreshold = 10

	// fimSuppressedStatus 事件已处理但刻意不产生告警。
	// 与 escalated 区分开：那是"升级成告警了"，这里是"看过了，判定不必告警"。
	// 都必须推进状态，否则事件停在 pending，下一轮调度重新命中，形成无限重试。
	fimSuppressedStatus = "suppressed"
)

// fimSelfPaths 是平台自身的文件，升级 agent 必然改写它们。
// 把自己的升级报成完整性违规，除了制造噪声没有任何检测价值。
var fimSelfPaths = []string{
	"/usr/bin/mxcwpp-agent",
	"/opt/mxcwpp/",
}

// isFIMSelfPath 判断路径是否属于平台自身。
func isFIMSelfPath(path string) bool {
	for _, p := range fimSelfPaths {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// fimBatchKey 把同一文件、同一天的同种变更归为一组。
//
// 带上检测日而不是处理日：一批变更是"同一天被检测到的同一件事"，
// 而它们到期升级的时刻可能跨过午夜，用处理日会把一批劈成两半。
func fimBatchKey(filePath, changeType, day string) string {
	return filePath + "\x00" + changeType + "\x00" + day
}

// fimDetectedDay 取事件检测日，作为批次维度。
func fimDetectedDay(t time.Time) string { return t.Format("2006-01-02") }

// fimBatchResultID 为聚合告警构造稳定的 result_id。
//
// 带上日期：同一天的同一批变更收敛到一条（跨调度轮次也会命中同一条，
// 靠 result_id 唯一索引幂等地累积），而第二天的同名变更是新的事实，
// 不该并进昨天那条里。
func fimBatchResultID(filePath, changeType, day string) string {
	sum := sha256.Sum256([]byte(fimBatchKey(filePath, changeType, day)))
	return "fim-escalation-batch-" + hex.EncodeToString(sum[:16])
}

// eventRow 是待升级事件连同它所属策略的视图。
type eventRow struct {
	model.FIMEvent
	PolicyID string `gorm:"column:policy_id"`
}

// upsertFIMAlert 幂等地写入告警并返回它的 ID。
//
// result_id 上有唯一索引。插入冲突意味着这条告警此前已经产生过，只是事件状态
// 没能落库——不能当作失败跳过：事件会一直停在 pending，下一轮调度重新命中，
// 再次冲突，形成无限重试。任何一次写库失败（容量不足、约束冲突等）都会留下
// 这种状态不一致，因此必须能从中恢复，而不是反复重试同一批。
//
// 第二个返回值表示这次是命中了已存在的告警而非新建。
func upsertFIMAlert(db *gorm.DB, alert *model.Alert) (uint, bool, error) {
	res := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "result_id"}},
		DoNothing: true,
	}).Create(alert)
	if res.Error != nil {
		return 0, false, res.Error
	}
	if res.RowsAffected > 0 {
		return alert.ID, false, nil
	}

	var existing model.Alert
	if err := db.Select("id").Where("result_id = ?", alert.ResultID).First(&existing).Error; err != nil {
		return 0, false, err
	}
	return existing.ID, true, nil
}

// fimBatchFanout 统计每个「文件 + 变更类型 + 检测日」波及的主机总数。
//
// 一次查询覆盖全部批次，避免逐组查库。统计不限状态：已升级的事件同样计入规模，
// 否则先处理掉的那部分会让后来者看起来"没那么大范围"。
func fimBatchFanout(db *gorm.DB, logger *zap.Logger) map[string]int {
	type row struct {
		FilePath   string `gorm:"column:file_path"`
		ChangeType string `gorm:"column:change_type"`
		Day        string `gorm:"column:day"`
		Hosts      int    `gorm:"column:hosts"`
	}
	var rows []row
	if err := db.Table("fim_events").
		Select("file_path, change_type, DATE(detected_at) AS day, COUNT(DISTINCT host_id) AS hosts").
		Group("file_path, change_type, day").
		Find(&rows).Error; err != nil {
		// 查不到就退回本轮统计：合并会变少，但不会错合
		logger.Warn("统计 FIM 批量变更规模失败，本轮退回按当前批次判定", zap.Error(err))
		return map[string]int{}
	}
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[fimBatchKey(r.FilePath, r.ChangeType, r.Day)] = r.Hosts
	}
	return out
}

// escalateFIMSingle 为单条事件产生一条告警。
func escalateFIMSingle(db *gorm.DB, logger *zap.Logger, ev eventRow, timeout int) (escalated, recovered bool) {
	alert := &model.Alert{
		ResultID:    fmt.Sprintf("fim-escalation-%s", ev.EventID),
		HostID:      ev.HostID,
		RuleID:      "fim-integrity-violation",
		PolicyID:    ev.PolicyID,
		Source:      model.AlertSourceFIM,
		Severity:    ev.Severity,
		Category:    ev.Category,
		Title:       fmt.Sprintf("文件完整性变更超时未确认: %s", ev.FilePath),
		Description: fmt.Sprintf("文件 %s 发生 %s 变更，超过 %d 分钟未确认，已自动升级为告警", ev.FilePath, ev.ChangeType, timeout),
		Actual:      ev.ChangeType,
		Status:      model.AlertStatusActive,
		FirstSeenAt: ev.DetectedAt,
		LastSeenAt:  model.Now(),
		CreatedAt:   model.Now(),
		UpdatedAt:   model.Now(),
	}

	alertID, wasExisting, err := upsertFIMAlert(db, alert)
	if err != nil {
		logger.Warn("创建 FIM 升级告警失败",
			zap.String("event_id", ev.EventID),
			zap.Error(err))
		return false, false
	}

	db.Model(&model.FIMEvent{}).
		Where("event_id = ?", ev.EventID).
		Updates(map[string]any{
			"status":   "escalated",
			"alert_id": alertID,
		})
	return true, wasExisting
}

// escalateFIMBatch 把同一文件同种变更的一批事件合并成一条告警。
//
// 告警挂在其中一台主机上（取排序后的第一台，保证同一批每轮都落到同一台，
// 不会因为遍历顺序变化而产生第二条），真正的规模写在标题与描述里。
// 每条事件仍各自推进状态并关联到这条告警，所以从任一主机都能追回来。
func escalateFIMBatch(db *gorm.DB, logger *zap.Logger, group []pendingFIMEvent, hostCount int) (escalated, recovered int) {
	first := group[0].ev
	hostIDs := make([]string, 0, len(group))
	for _, pe := range group {
		hostIDs = append(hostIDs, pe.ev.HostID)
	}
	sort.Strings(hostIDs)

	// 取组内最高严重性：聚合是为了少一些条目，不是为了把问题说得更轻
	severity := first.Severity
	for _, pe := range group {
		if fimSeverityRank(pe.ev.Severity) > fimSeverityRank(severity) {
			severity = pe.ev.Severity
		}
	}

	alert := &model.Alert{
		ResultID: fimBatchResultID(first.FilePath, first.ChangeType, fimDetectedDay(first.DetectedAt.Time())),
		HostID:   hostIDs[0],
		RuleID:   "fim-integrity-violation",
		PolicyID: first.PolicyID,
		Source:   model.AlertSourceFIM,
		Severity: severity,
		Category: first.Category,
		Title:    fmt.Sprintf("文件完整性批量变更: %s（%d 台主机）", first.FilePath, hostCount),
		Description: fmt.Sprintf(
			"文件 %s 在 %d 台主机上发生 %s 变更，已合并为一条告警。"+
				"同一文件在这么多主机上同时变更通常来自包管理器更新；"+
				"若本时段没有对应的变更操作，则需要按入侵排查。",
			first.FilePath, hostCount, first.ChangeType),
		Actual:      first.ChangeType,
		Status:      model.AlertStatusActive,
		FirstSeenAt: first.DetectedAt,
		LastSeenAt:  model.Now(),
		CreatedAt:   model.Now(),
		UpdatedAt:   model.Now(),
	}

	alertID, wasExisting, err := upsertFIMAlert(db, alert)
	if err != nil {
		logger.Warn("创建 FIM 批量告警失败",
			zap.String("file_path", first.FilePath),
			zap.Error(err))
		return 0, 0
	}
	if wasExisting {
		recovered = 1
	}

	eventIDs := make([]string, 0, len(group))
	for _, pe := range group {
		eventIDs = append(eventIDs, pe.ev.EventID)
	}
	db.Model(&model.FIMEvent{}).
		Where("event_id IN ?", eventIDs).
		Updates(map[string]any{
			"status":   "escalated",
			"alert_id": alertID,
		})

	logger.Info("FIM 批量变更已合并告警",
		zap.String("file_path", first.FilePath),
		zap.String("change_type", first.ChangeType),
		zap.Int("hosts", hostCount),
		zap.Int("events", len(group)))

	return len(group), recovered
}

// fimSeverityRank 给严重性排序，用于取组内最高。
func fimSeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// pendingFIMEvent 是一条已超时、等待升级的事件。
type pendingFIMEvent struct {
	ev      eventRow
	timeout int
}

// EscalatePendingFIMEvents 检查超时未确认的 FIM 事件并升级为告警
// 规则：event.status='pending' 且 detected_at 距今超过所属策略的 escalation_timeout_min
func EscalatePendingFIMEvents(db *gorm.DB, logger *zap.Logger) {
	// 1. 加载所有策略的超时配置
	var policies []model.FIMPolicy
	if err := db.Select("policy_id, escalation_timeout_min").Find(&policies).Error; err != nil {
		logger.Error("查询 FIM 策略超时配置失败", zap.Error(err))
		return
	}
	policyTimeouts := make(map[string]int, len(policies))
	for _, p := range policies {
		timeout := p.EscalationTimeoutMin
		if timeout <= 0 {
			timeout = 1440
		}
		policyTimeouts[p.PolicyID] = timeout
	}

	// 2. 查询所有 pending 事件及其所属策略
	var events []eventRow
	if err := db.Table("fim_events").
		Select("fim_events.*, fim_tasks.policy_id").
		Joins("LEFT JOIN fim_tasks ON fim_events.task_id = fim_tasks.task_id").
		Where("fim_events.status = ?", "pending").
		Find(&events).Error; err != nil {
		logger.Error("查询待确认 FIM 事件失败", zap.Error(err))
		return
	}

	if len(events) == 0 {
		return
	}

	escalated := 0
	recovered := 0 // 告警已存在、本轮仅补齐状态的数量
	suppressed := 0

	// 先筛出真正超时的事件，并按「同一文件的同种变更」分组。
	// 不分组直接逐条升级，就是当前 alerts 表被同一条规则灌满的原因：
	// 一次系统包更新会在每台主机上改写同一批二进制，逐条升级等于把一次
	// 运维操作拆成成千上万条告警，真正的威胁淹没在里面。
	groups := make(map[string][]pendingFIMEvent)
	for _, ev := range events {
		timeout := policyTimeouts[ev.PolicyID]
		if timeout <= 0 {
			timeout = 1440
		}
		cutoff := time.Now().Add(-time.Duration(timeout) * time.Minute)
		if !ev.DetectedAt.Time().Before(cutoff) {
			continue
		}

		// 平台自身的升级不算完整性违规。状态照常推进，只是不产生告警。
		if isFIMSelfPath(ev.FilePath) {
			db.Model(&model.FIMEvent{}).
				Where("event_id = ?", ev.EventID).
				Update("status", fimSuppressedStatus)
			suppressed++
			continue
		}

		k := fimBatchKey(ev.FilePath, ev.ChangeType, fimDetectedDay(ev.DetectedAt.Time()))
		groups[k] = append(groups[k], pendingFIMEvent{ev: ev, timeout: timeout})
	}

	// 判定是否算批量，要看这一批变更总共波及多少主机，而不是本轮恰好捞到几台。
	//
	// 同一次包更新在各主机上的检测时刻本就有先后，到期升级也就分散在多轮调度里。
	// 只数本轮捞到的，先到期的少数几台会因不足阈值而逐条告警，其余的到齐后才合并——
	// 同一个文件于是既有一堆单条告警又有一条聚合告警，两边都不完整。
	// 按检测日统计该路径的全部事件（不论当前状态），本轮第一次见到它就能知道规模。
	fanout := fimBatchFanout(db, logger)

	// 分组顺序固定，便于日志比对与问题复现
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	batched := 0
	for _, k := range keys {
		group := groups[k]

		hosts := make(map[string]struct{}, len(group))
		for _, pe := range group {
			hosts[pe.ev.HostID] = struct{}{}
		}

		// 全量扇出优先；查不到时退回本轮实际主机数，宁可少合并也不误合并
		total := fanout[k]
		if total < len(hosts) {
			total = len(hosts)
		}

		if total >= fimBatchHostThreshold {
			n, rec := escalateFIMBatch(db, logger, group, total)
			escalated += n
			recovered += rec
			if n > 0 {
				batched++
			}
			continue
		}

		for _, pe := range group {
			ok, rec := escalateFIMSingle(db, logger, pe.ev, pe.timeout)
			if ok {
				escalated++
			}
			if rec {
				recovered++
			}
		}
	}

	if escalated > 0 || suppressed > 0 {
		logger.Info("FIM 事件超时升级完成",
			zap.Int("escalated", escalated),
			zap.Int("recovered", recovered),
			zap.Int("suppressed", suppressed),
			zap.Int("batched_groups", batched),
			zap.Int("checked", len(events)))
	}
}
