package consumer

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// behaviorDeviation 一次行为基线偏离，写进主告警表所需的全部内容。
type behaviorDeviation struct {
	HostID    string
	Hostname  string
	Metric    string
	Value     float64
	Mean      float64
	Stddev    float64
	ZScore    float64
	RiskScore float64
}

// promoteBehaviorAlert 把行为基线偏离并入主告警表。
//
// behavior_alerts 是 BDE 自己的明细表，不进主表就没有研判入口：白名单、通知、
// 调优环都只认主表，偏离写进去却从来没人看到。同一主机同一指标按分组合并，
// 关闭之后再偏离生成复发告警，和其它来源的告警同一套语义。
func promoteBehaviorAlert(db *gorm.DB, d behaviorDeviation, now time.Time) (*model.Alert, error) {
	actual, err := json.Marshal(map[string]any{
		"hostname": d.Hostname, "metric": d.Metric, "value": d.Value, "mean": d.Mean,
		"stddev": d.Stddev, "z_score": d.ZScore, "risk_score": d.RiskScore,
	})
	if err != nil {
		return nil, err
	}
	ts := model.ToLocalTime(now)
	severity := bdeSeverity(d.RiskScore)
	desc := fmt.Sprintf("值 %.2f 偏离基线均值 %.2f（σ=%.2f, z=%.2f），风险分 %.1f",
		d.Value, d.Mean, d.Stddev, d.ZScore, d.RiskScore)
	groupKey := "behavior|" + d.HostID + "|" + d.Metric

	return model.UpsertGroupedAlert(db, groupKey, func() model.Alert {
		return model.Alert{
			HostID:      d.HostID,
			RuleID:      model.BehaviorRulePrefix + d.Metric,
			Source:      model.AlertSourceBehavior,
			Severity:    severity,
			RiskScore:   int(d.RiskScore),
			Category:    "behavior_anomaly",
			Title:       "行为基线偏离：" + d.Metric,
			Description: desc,
			Actual:      string(actual),
			Status:      model.AlertStatusActive,
			FirstSeenAt: ts,
			LastSeenAt:  ts,
			HitCount:    1,
		}
	}, func(existing *model.Alert) error {
		return db.Model(existing).Updates(map[string]any{
			"last_seen_at": ts,
			"hit_count":    gorm.Expr("hit_count + 1"),
			"actual":       string(actual),
			"description":  desc,
			"risk_score":   int(d.RiskScore),
			"severity":     severity,
		}).Error
	})
}
