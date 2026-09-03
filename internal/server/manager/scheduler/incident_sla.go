package scheduler

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 事件响应超时指标。
//
// 上一轮给事件加了认领与解决时限，却没有任何东西去读它们——没人看的截止时间只是
// 一列数据。超时不是"晚了一点"，而是"这条事件没人管"：在安全产品里，
// 一条无人认领的高危事件与一条未被检出的攻击，结果是一样的。
var (
	// incidentSLABreached 当前处于超时状态的事件数，按超时类型与严重级别。
	// 用 Gauge 而非 Counter：运维要问的是"现在有多少条没人管"，不是"历史上超时过几次"。
	incidentSLABreached = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_incident_sla_breached",
		Help: "Incidents currently past their acknowledgement or resolution deadline",
	}, []string{"kind", "severity"})

	// incidentUnowned 无负责人的未关闭事件数。
	// 与超时分开：还没到时限但已经没人认领，是即将变成超时的前兆。
	incidentUnowned = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mxcwpp_incident_unowned",
		Help: "Open incidents with no owner assigned",
	})
)

// StartIncidentSLAScheduler 周期检查事件响应超时。
func StartIncidentSLAScheduler(db *gorm.DB, logger *zap.Logger) {
	const interval = 2 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.Info("事件响应超时检查器已启动", zap.Duration("check_interval", interval))
	checkIncidentSLA(db, logger)
	for range ticker.C {
		checkIncidentSLA(db, logger)
	}
}

// slaBreach 是一条超时事件的摘要。
type slaBreach struct {
	IncidentID string
	Severity   string
	Owner      string
}

// checkIncidentSLA 统计并上报当前的超时与无主事件。
//
// 只观测不改状态：自动把超时事件标记成别的状态会掩盖问题——超时该做的是让人知道，
// 而不是让它从待办里消失。
func checkIncidentSLA(db *gorm.DB, logger *zap.Logger) {
	now := model.ToLocalTime(time.Now())

	// 认领超时：到了时限仍无人认领。这是最该被叫醒的一类——没人开始看。
	ackBreached := countBreaches(db, logger, "acked_at IS NULL AND ack_due_at IS NOT NULL AND ack_due_at < ?", now)
	// 解决超时：已在处理但超过解决时限。
	resolveBreached := countBreaches(db, logger,
		"acked_at IS NOT NULL AND resolve_due_at IS NOT NULL AND resolve_due_at < ?", now)

	publishBreaches("ack", ackBreached)
	publishBreaches("resolve", resolveBreached)

	var unowned int64
	if err := db.Model(&model.Incident{}).
		Where("status <> ? AND (owner IS NULL OR owner = '')", model.IncidentStatusResolved).
		Count(&unowned).Error; err != nil {
		logger.Warn("统计无主事件失败", zap.Error(err))
	} else {
		incidentUnowned.Set(float64(unowned))
	}

	if len(ackBreached) > 0 {
		// 逐条列出而不只给个数字：运维要能直接知道该去看哪几条。
		ids := make([]string, 0, len(ackBreached))
		for _, b := range ackBreached {
			ids = append(ids, b.IncidentID)
		}
		logger.Warn("存在超过认领时限仍无人认领的事件",
			zap.Int("count", len(ackBreached)),
			zap.Strings("incident_ids", ids))
	}
}

// countBreaches 查出符合条件的未关闭事件。
func countBreaches(db *gorm.DB, logger *zap.Logger, cond string, args ...any) []slaBreach {
	var rows []slaBreach
	if err := db.Model(&model.Incident{}).
		Select("incident_id, severity, owner").
		Where("status <> ?", model.IncidentStatusResolved).
		Where(cond, args...).
		Scan(&rows).Error; err != nil {
		logger.Warn("查询超时事件失败", zap.Error(err))
		return nil
	}
	return rows
}

// publishBreaches 按严重级别刷新超时指标。
//
// 每轮先清零再置数：Gauge 表示"当前状态"，事件被处理后对应标签必须归零，
// 否则告警会一直停在已经解决的问题上。
func publishBreaches(kind string, breaches []slaBreach) {
	bySeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, b := range breaches {
		sev := b.Severity
		if _, ok := bySeverity[sev]; !ok {
			sev = "low" // 未知级别归入最低档，不凭空造新标签
		}
		bySeverity[sev]++
	}
	for sev, n := range bySeverity {
		incidentSLABreached.WithLabelValues(kind, sev).Set(float64(n))
	}
}
