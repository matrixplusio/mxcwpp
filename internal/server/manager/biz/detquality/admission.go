package detquality

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// critical 准入的自动降级门槛。
const (
	// AdmissionReviewWindow 只看最近这段时间产生的告警。更早的研判反映的是规则当时的样子。
	AdmissionReviewWindow = 30 * 24 * time.Hour
	// AdmissionMinReviewed 至少研判过这么多条才下结论，与晋级的样本门槛同一个道理。
	AdmissionMinReviewed = MinSamplesForPromotion
)

// admissionRuleIDPattern 约束可登记的规则 ID：与告警 rule_id 的实际取值同形。
var admissionRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// AdmissionView 是一条准入记录加上规则的可读名。
type AdmissionView struct {
	model.RuleCriticalAdmission
	// RuleName 仅 CEL 与攻击链规则有；硬编码检测的 ID 本身就是名字。
	RuleName string `json:"ruleName,omitempty"`
}

// ListCriticalAdmissions 返回全部准入记录。
func (s *Service) ListCriticalAdmissions() ([]AdmissionView, error) {
	var rows []model.RuleCriticalAdmission
	if err := s.db.Order("allowed, rule_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	names, err := s.ruleNames()
	if err != nil {
		return nil, err
	}
	out := make([]AdmissionView, 0, len(rows))
	for i := range rows {
		out = append(out, AdmissionView{RuleCriticalAdmission: rows[i], RuleName: names[rows[i].RuleID]})
	}
	return out, nil
}

// ruleNames 返回 rule_id → 规则名（cel-N / seq-N）。
func (s *Service) ruleNames() (map[string]string, error) {
	type named struct {
		ID   uint
		Name string
	}
	names := make(map[string]string)
	var cel, seq []named
	if err := s.db.Model(&model.DetectionRule{}).Select("id, name").Find(&cel).Error; err != nil {
		return nil, err
	}
	for _, r := range cel {
		names[fmt.Sprintf("cel-%d", r.ID)] = r.Name
	}
	if err := s.db.Model(&model.SequenceRule{}).Select("id, name").Find(&seq).Error; err != nil {
		return nil, err
	}
	for _, r := range seq {
		names[fmt.Sprintf("seq-%d", r.ID)] = r.Name
	}
	return names, nil
}

// SetCriticalAdmission 设定一条规则能否产生 critical 告警。返回变更前的状态。
//
// 两个方向都要写原因：放开意味着这条规则的每次命中都会推送给告警接收人，收回意味着它
// 不再推送，哪个都不该是一次没有记录的点击。
// 对一条有待确认建议的规则再次设为准入，即驳回建议。
func (s *Service) SetCriticalAdmission(ruleID string, allowed bool, reason, actor string) (before bool, err error) {
	if !admissionRuleIDPattern.MatchString(ruleID) {
		return false, errors.New("无效的规则 ID")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return false, errors.New("必须写明原因")
	}
	if len([]rune(reason)) > 500 {
		return false, errors.New("原因过长")
	}
	var existing model.RuleCriticalAdmission
	switch e := s.db.Where("rule_id = ?", ruleID).First(&existing).Error; {
	case e == nil:
		before = existing.Allowed
	case !errors.Is(e, gorm.ErrRecordNotFound):
		return false, e
	}
	// 人做了决定，待确认的建议随之了结：无论是采纳（移出）还是驳回（保留）。
	row := model.RuleCriticalAdmission{
		RuleID: ruleID, Allowed: allowed, Reason: reason, ChangedBy: actor, DecidedAt: model.Now(),
	}
	if err := s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "rule_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"allowed", "reason", "changed_by", "decided_at", "demotion_suggested_at", "demotion_suggestion"}),
	}).Create(&row).Error; err != nil {
		return before, err
	}
	s.logger.Warn("critical 准入已变更",
		zap.String("rule_id", ruleID),
		zap.Bool("from", before),
		zap.Bool("to", allowed),
		zap.String("reason", reason),
		zap.String("actor", actor))
	return before, nil
}

// AdmissionSuggestion 是一条新提出的「建议移出准入」。
type AdmissionSuggestion struct {
	RuleID         string
	RuleName       string
	FalsePositives int64
	Reason         string
}

// SuggestCriticalDemotions 为「被判成误报的次数够多、且没有一条真实威胁」的规则提出移出准入的建议。
//
// 只提建议。恢复或移出都走 SetCriticalAdmission，由有规则管理权限的人决定。
//
// 只数误报，不数良性真阳性：后者是「检测对了，只是这次无害」（红队演练、运维自测），
// 把它算成规则不可信，会让工作正常的高特异规则被调松——反弹 Shell 被演练触发二十次，
// 不说明它不该是 critical。
func (s *Service) SuggestCriticalDemotions(now time.Time) ([]AdmissionSuggestion, error) {
	var rows []model.RuleCriticalAdmission
	if err := s.db.Where("allowed = ? AND demotion_suggested_at IS NULL", true).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	names, err := s.ruleNames()
	if err != nil {
		return nil, err
	}
	windowStart := now.Add(-AdmissionReviewWindow)
	var out []AdmissionSuggestion
	for i := range rows {
		r := &rows[i]
		// 只算这条记录最近一次人工决定之后产生的告警。
		since := windowStart
		if decided := time.Time(r.DecidedAt); decided.After(since) {
			since = decided
		}
		var stat struct {
			FP int64 `gorm:"column:fp"`
			TP int64 `gorm:"column:tp"`
		}
		if err := s.db.Model(&model.Alert{}).
			Select("COALESCE(SUM(CASE WHEN verdict = ? THEN 1 ELSE 0 END), 0) AS fp, "+
				"COALESCE(SUM(CASE WHEN verdict = ? THEN 1 ELSE 0 END), 0) AS tp",
				model.VerdictFalsePositive, model.VerdictTruePositive).
			Where("rule_id = ? AND source = ? AND verdict <> '' AND created_at >= ?",
				r.RuleID, model.AlertSourceDetection, model.ToLocalTime(since)).
			Where(model.IndividualVerdictOnly).
			Scan(&stat).Error; err != nil {
			return out, err
		}
		if stat.FP < AdmissionMinReviewed || stat.TP > 0 {
			continue
		}
		reason := fmt.Sprintf("最近 %d 条告警被研判为误报，没有一条是真实威胁", stat.FP)
		// 带上 decided_at 条件：统计期间有人改过这条记录的话，以人的决定为准。
		res := s.db.Model(&model.RuleCriticalAdmission{}).
			Where("rule_id = ? AND allowed = ? AND decided_at = ? AND demotion_suggested_at IS NULL", r.RuleID, true, r.DecidedAt).
			Updates(map[string]any{
				"demotion_suggested_at": model.ToLocalTime(now),
				"demotion_suggestion":   reason,
			})
		if res.Error != nil {
			return out, res.Error
		}
		if res.RowsAffected == 0 {
			continue
		}
		name := names[r.RuleID]
		if name == "" {
			name = r.RuleID
		}
		s.logger.Warn("建议把规则移出 critical 准入清单，等待人工确认",
			zap.String("rule_id", r.RuleID), zap.Int64("false_positives", stat.FP))
		out = append(out, AdmissionSuggestion{RuleID: r.RuleID, RuleName: name, FalsePositives: stat.FP, Reason: reason})
	}
	return out, nil
}
