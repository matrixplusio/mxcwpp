package scheduler

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 自动调优聚合参数（P2-B）。
const (
	autoTuningInterval   = 6 * time.Hour      // 聚合周期
	autoTuningLookback   = 7 * 24 * time.Hour // 回看窗口
	autoTuningMinHits    = 5                  // 生成建议的最小 resolve/ignore 次数
	autoTuningMaxRiskTP  = 70                 // 组内任一告警 risk_score ≥ 此值视为潜在真阳，跳过建议
	autoTuningSampleCap  = 5                  // 每条建议保留的示例告警 ID 上限
	autoTuningConfFactor = 15                 // 置信度 = min(100, hits×factor)
)

// StartAutoTuningScheduler 启动自动调优聚合调度器（P2-B）。
//
// 每 autoTuningInterval 扫近 autoTuningLookback 内被 resolve/ignore 的 CEL 告警，
// 按 (rule_id, exe) 聚合，反复被判误报且无潜在真阳的模式 → 生成 pending 建议。
// 建议仅供人审采纳，不自动生效（避免自动制造检测盲区）。
func StartAutoTuningScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(autoTuningInterval)
	defer ticker.Stop()

	logger.Info("自动调优聚合调度器已启动", zap.Duration("interval", autoTuningInterval))

	// 启动时立即跑一次
	processAutoTuning(db, logger)

	for range ticker.C {
		processAutoTuning(db, logger)
	}
}

// tuningGroup (rule_id, exe) 聚合中间态。
type tuningGroup struct {
	ruleID       string
	ruleName     string
	exe          string
	category     string
	severity     string
	hits         int
	maxRisk      int
	sampleIDs    []string
	reasonSample string
	hosts        map[string]struct{}
}

// processAutoTuning 执行一轮聚合并 upsert 建议。
func processAutoTuning(db *gorm.DB, logger *zap.Logger) {
	cutoff := model.ToLocalTime(time.Now().Add(-autoTuningLookback))

	var alerts []model.Alert
	if err := db.
		Where("source = ? AND status IN ? AND updated_at >= ?",
			model.AlertSourceDetection,
			[]model.AlertStatus{model.AlertStatusResolved, model.AlertStatusIgnored},
			cutoff,
		).
		Find(&alerts).Error; err != nil {
		logger.Warn("自动调优查询告警失败", zap.Error(err))
		return
	}
	if len(alerts) == 0 {
		return
	}

	groups := map[string]*tuningGroup{}
	for i := range alerts {
		a := &alerts[i]
		// critical 规则不参与白名单建议：真威胁不应被自动豁免。
		if a.Severity == "critical" {
			continue
		}
		exe := extractExeBasename(a.Actual)
		if exe == "" {
			continue
		}
		key := a.RuleID + "|" + exe
		g := groups[key]
		if g == nil {
			g = &tuningGroup{
				ruleID:   a.RuleID,
				ruleName: a.Title,
				exe:      exe,
				category: a.Category,
				severity: a.Severity,
				hosts:    map[string]struct{}{},
			}
			groups[key] = g
		}
		g.hits++
		if a.RiskScore > g.maxRisk {
			g.maxRisk = a.RiskScore
		}
		g.hosts[a.HostID] = struct{}{}
		if len(g.sampleIDs) < autoTuningSampleCap {
			g.sampleIDs = append(g.sampleIDs, fmt.Sprintf("%d", a.ID))
		}
		if g.reasonSample == "" && a.ResolveReason != "" {
			g.reasonSample = a.ResolveReason
		}
	}

	var created, updated int
	for _, g := range groups {
		// 阈值 + 真阳排除：命中不足、或组内出现高风险/真阳告警的模式不建议白名单。
		if g.hits < autoTuningMinHits || g.maxRisk >= autoTuningMaxRiskTP {
			continue
		}
		// 模式集中在单一主机 → host 维度建议；跨多主机 → 全队列 exe 豁免。
		hostID := ""
		if len(g.hosts) == 1 {
			for h := range g.hosts {
				hostID = h
			}
		}
		if c, isNew := upsertSuggestion(db, logger, g, hostID); c {
			if isNew {
				created++
			} else {
				updated++
			}
		}
	}
	if created > 0 || updated > 0 {
		logger.Info("自动调优建议已更新",
			zap.Int("created", created),
			zap.Int("updated", updated),
			zap.Int("groups", len(groups)),
		)
	}
}

// upsertSuggestion 按 signature 去重 upsert 一条建议。返回 (是否写入, 是否新建)。
// 已被人审 (adopted/dismissed) 的 signature 不再复活，尊重人工决策。
func upsertSuggestion(db *gorm.DB, logger *zap.Logger, g *tuningGroup, hostID string) (bool, bool) {
	signature := fmt.Sprintf("%s|%s|%s|%s", g.ruleID, g.exe, "", hostID)
	confidence := g.hits * autoTuningConfFactor
	if confidence > 100 {
		confidence = 100
	}

	var existing model.AlertWhitelistSuggestion
	err := db.Where("signature = ?", signature).First(&existing).Error
	if err == nil {
		if existing.Status != model.SuggestionStatusPending {
			return false, false // 已人审，不复活
		}
		existing.HitCount = g.hits
		existing.Confidence = confidence
		existing.SampleAlertIDs = g.sampleIDs
		existing.ResolveReasonSample = g.reasonSample
		if err := db.Save(&existing).Error; err != nil {
			logger.Warn("更新自动调优建议失败", zap.String("signature", signature), zap.Error(err))
			return false, false
		}
		return true, false
	}
	if err != gorm.ErrRecordNotFound {
		logger.Warn("查询自动调优建议失败", zap.String("signature", signature), zap.Error(err))
		return false, false
	}

	s := model.AlertWhitelistSuggestion{
		Signature:           signature,
		RuleID:              g.ruleID,
		RuleName:            g.ruleName,
		HostID:              hostID,
		Exe:                 g.exe,
		Category:            g.category,
		Severity:            g.severity,
		HitCount:            g.hits,
		Confidence:          confidence,
		SampleAlertIDs:      g.sampleIDs,
		ResolveReasonSample: g.reasonSample,
		Status:              model.SuggestionStatusPending,
	}
	if err := db.Create(&s).Error; err != nil {
		logger.Warn("创建自动调优建议失败", zap.String("signature", signature), zap.Error(err))
		return false, false
	}
	return true, true
}

// extractExeBasename 从告警 detail(JSON) 提取进程 basename，兼容 exe/comm 字段。
func extractExeBasename(actual string) string {
	if actual == "" {
		return ""
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(actual), &fields); err != nil {
		return ""
	}
	exe := fields["exe"]
	if exe == "" {
		exe = fields["comm"]
	}
	exe = strings.TrimSpace(exe)
	if exe == "" {
		return ""
	}
	return filepath.Base(exe)
}
