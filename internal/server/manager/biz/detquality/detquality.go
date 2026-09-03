// Package detquality 由人工研判结论计算检测质量，并据此决定规则能否晋级。
//
// 此前平台无法回答"检测准不准"。唯一现成的数字是已关闭告警数，而拿它当 precision
// 会把"没人看所以批量关掉"算成检测准确——越是没人管的环境，看起来越准。
//
// 真实 precision 只能来自人工研判结论（true_positive / false_positive /
// benign_true_positive）。这也是规则生命周期存在的意义：晋级由数据回答，
// 不是由人觉得差不多了。
package detquality

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// MinSamplesForPromotion 晋级所需的最少已研判样本数。
//
// 样本太少时 precision 没有意义：3 条里对 3 条不能说明规则可靠，
// 只说明它还没怎么响过。宁可让规则多待一阵，也不要凭 3 个样本放它去打扰值班。
const MinSamplesForPromotion = 20

// MinPrecisionForPromotion 晋级所需的最低精确率。
const MinPrecisionForPromotion = 0.85

// MinShadowObserveDays 影子阶段最短观察天数。
//
// 一天覆盖不到周末与月初结算这类周期性业务，而它们恰恰是误报高发时段：
// 只观察一天就晋级，等于把没见过的场景当成不存在。
const MinShadowObserveDays = 7

// MaxShadowHitsPerDay 影子期允许的日均命中上限。
//
// 超过这个量说明它是噪声规则而不是检测规则——放开后不会让人更安全，
// 只会让人不再看告警。
const MaxShadowHitsPerDay = 50

// Quality 是一条规则的检测质量。
type Quality struct {
	RuleID string `json:"rule_id"`

	TruePositive  int `json:"true_positive"`
	FalsePositive int `json:"false_positive"`
	// BenignTruePositive 检测正确但行为无害。**不计入误报**——
	// 把它算成 FP 会让本来工作正常的规则被错误地调松。
	BenignTruePositive int `json:"benign_true_positive"`
	// Undetermined 尚未研判。它们不参与计算，只用来说明覆盖率。
	Undetermined int `json:"undetermined"`

	// Precision 为 nil 表示样本不足，无法计算。
	//
	// 刻意用指针而非 0：0 会被读成"精确率为零"，而实际含义是"不知道"。
	// 缺失即 UNKNOWN，不是不达标——这与把请求失败渲染成 0 是同一类错误。
	Precision *float64 `json:"precision"`
	// Judged 已研判样本数，即 precision 的分母。
	Judged int `json:"judged"`
}

// Service 计算检测质量并执行规则晋级。
type Service struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewService 构造服务。
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{db: db, logger: logger}
}

// computePrecision 由三类结论算精确率。
//
// benign_true_positive 计入分母但不算错：检测确实命中了它要找的行为，
// 只是该行为在本环境无害。把它排除在外会高估精确率，算成误报又会低估。
func computePrecision(tp, fp, benign int) *float64 {
	judged := tp + fp + benign
	if judged < MinSamplesForPromotion {
		return nil
	}
	p := float64(tp+benign) / float64(judged)
	return &p
}

// QualityWindowDays 统计窗口。
//
// 只看近期研判：一条规则半年前的表现不能证明它今天仍然准确——环境变了、
// 白名单变了、规则本身可能也被改过。
const QualityWindowDays = 90

// RuleQuality 计算指定规则的检测质量。
//
// 事件与告警之间是 incidents.alert_ids（JSON 数组存 alerts.id），不是外键，
// 所以交集在 Go 里算：JSON 函数在 MySQL 与测试用的 sqlite 上语法不一致，
// 写死任一方都会让这段逻辑只在其中一处被验证过。
func (s *Service) RuleQuality(ruleID string) (*Quality, error) {
	if strings.TrimSpace(ruleID) == "" {
		return nil, errors.New("规则 ID 不能为空")
	}

	// 该规则产生过的告警 ID。
	var alertIDs []uint
	if err := s.db.Model(&model.Alert{}).Where("rule_id = ?", ruleID).
		Pluck("id", &alertIDs).Error; err != nil {
		return nil, fmt.Errorf("查询规则告警失败: %w", err)
	}
	q := &Quality{RuleID: ruleID}
	if len(alertIDs) == 0 {
		return q, nil
	}
	owned := make(map[string]bool, len(alertIDs))
	for _, id := range alertIDs {
		owned[strconv.FormatUint(uint64(id), 10)] = true
	}

	since := model.ToLocalTime(time.Now().AddDate(0, 0, -QualityWindowDays))
	var incidents []model.Incident
	if err := s.db.Select("incident_id, verdict, alert_ids").
		Where("created_at >= ?", since).
		Find(&incidents).Error; err != nil {
		return nil, fmt.Errorf("查询事件失败: %w", err)
	}

	for i := range incidents {
		if !containsAny(incidents[i].AlertIDs, owned) {
			continue
		}
		switch incidents[i].Verdict {
		case model.VerdictTruePositive:
			q.TruePositive++
		case model.VerdictFalsePositive:
			q.FalsePositive++
		case model.VerdictBenignTruePositive:
			q.BenignTruePositive++
		default:
			q.Undetermined++
		}
	}
	q.Judged = q.TruePositive + q.FalsePositive + q.BenignTruePositive
	q.Precision = computePrecision(q.TruePositive, q.FalsePositive, q.BenignTruePositive)
	return q, nil
}

// containsAny 判断事件的告警成员里是否有属于该规则的。
func containsAny(ids model.StringArray, owned map[string]bool) bool {
	for _, id := range ids {
		if owned[id] {
			return true
		}
	}
	return false
}

// PromotionDecision 说明一条规则能否晋级以及原因。
type PromotionDecision struct {
	RuleID   string   `json:"rule_id"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Eligible bool     `json:"eligible"`
	Reasons  []string `json:"reasons"`
	Quality  *Quality `json:"quality"`
	// Shadow 影子期观测量，仅 shadow → context 这一跳有值。
	Shadow *model.RuleShadowStat `json:"shadow,omitempty"`
}

// shadowStat 读取规则的影子期观测量，没有记录时返回 nil。
func (s *Service) shadowStat(ruleID string) (*model.RuleShadowStat, error) {
	var stat model.RuleShadowStat
	err := s.db.Where("rule_id = ?", ruleID).First(&stat).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询影子统计失败: %w", err)
	}
	return &stat, nil
}

// EvaluatePromotion 判断规则是否满足晋级条件。
//
// 不满足时给出具体原因而不只是拒绝：运维要知道差在样本量还是精确率，
// 否则只能反复点击试探。
func (s *Service) EvaluatePromotion(rule *model.DetectionRule) (*PromotionDecision, error) {
	next := model.NextRuleStage(rule.Stage)
	d := &PromotionDecision{
		RuleID: fmt.Sprintf("cel-%d", rule.ID),
		From:   rule.Stage,
		To:     next,
	}
	if next == "" {
		d.Reasons = append(d.Reasons, "已处于最高阶段")
		return d, nil
	}

	q, err := s.RuleQuality(d.RuleID)
	if err != nil {
		return nil, err
	}
	d.Quality = q

	// 每一跳看的证据不同，因为每一跳能拿到的证据本来就不同。
	switch rule.Stage {
	case model.RuleStageDraft:
		// draft → shadow 不需要数据：影子阶段本就是为了收集数据，
		// 要求它先有数据是循环依赖。
		d.Eligible = true
		return d, nil

	case model.RuleStageShadow:
		// shadow → context 看命中量，不看精确率。
		//
		// 影子规则不产生告警，也就不产生事件与研判结论——若这一跳也要求精确率，
		// 影子规则永远凑不齐样本，会被卡死在影子阶段。这一跳要回答的是
		// "它到底会响多少次"，噪声规则在这里就该被拦下。
		stat, err := s.shadowStat(d.RuleID)
		if err != nil {
			return nil, err
		}
		d.Shadow = stat
		observedDays := 0.0
		if stat != nil {
			observedDays = time.Since(stat.ObservedSince.Time()).Hours() / 24
		}
		if stat == nil || observedDays < MinShadowObserveDays {
			d.Reasons = append(d.Reasons, fmt.Sprintf(
				"影子观察 %.1f 天，少于要求的 %d 天", observedDays, MinShadowObserveDays))
		} else if perDay := float64(stat.Hits) / observedDays; perDay > MaxShadowHitsPerDay {
			d.Reasons = append(d.Reasons, fmt.Sprintf(
				"影子期日均命中 %.0f 次，超过噪声上限 %d 次（先降噪再晋级，否则放开后会淹没值班）",
				perDay, MaxShadowHitsPerDay))
		}

	default:
		// context → alert 才要求精确率：上下文阶段的命中会参与事件聚合，
		// 因而能拿到人工研判结论。到这一跳，"准不准"终于有据可依。
		if q.Judged < MinSamplesForPromotion {
			d.Reasons = append(d.Reasons, fmt.Sprintf(
				"已研判样本 %d 条，少于晋级所需的 %d 条（样本太少时精确率没有意义）",
				q.Judged, MinSamplesForPromotion))
		}
		if q.Precision == nil {
			if q.Judged >= MinSamplesForPromotion {
				d.Reasons = append(d.Reasons, "样本不足，精确率无法计算")
			}
		} else if *q.Precision < MinPrecisionForPromotion {
			d.Reasons = append(d.Reasons, fmt.Sprintf(
				"精确率 %.1f%%，低于晋级门槛 %.0f%%",
				*q.Precision*100, MinPrecisionForPromotion*100))
		}
	}

	d.Eligible = len(d.Reasons) == 0
	return d, nil
}

// PromoteRule 晋级规则。不满足条件时拒绝并返回原因。
func (s *Service) PromoteRule(ruleID uint, actor string) (*PromotionDecision, error) {
	var rule model.DetectionRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		return nil, err
	}
	d, err := s.EvaluatePromotion(&rule)
	if err != nil {
		return nil, err
	}
	if !d.Eligible {
		return d, fmt.Errorf("规则不满足晋级条件: %s", strings.Join(d.Reasons, "；"))
	}
	if err := s.db.Model(&model.DetectionRule{}).Where("id = ?", ruleID).
		Update("stage", d.To).Error; err != nil {
		return nil, err
	}
	s.logger.Warn("检测规则已晋级",
		zap.Uint("rule_id", ruleID),
		zap.String("from", d.From),
		zap.String("to", d.To),
		zap.String("actor", actor))
	return d, nil
}

// DemoteRule 降级规则。
//
// 降级不设门槛：噪声规则该能被立刻按下去，让它先停止打扰值班再慢慢查。
// 晋级要证据，降级不需要——两个方向的代价不对称。
func (s *Service) DemoteRule(ruleID uint, to, reason, actor string) error {
	if _, ok := map[string]bool{
		model.RuleStageDraft: true, model.RuleStageShadow: true,
		model.RuleStageContext: true, model.RuleStageAlert: true,
	}[to]; !ok {
		return fmt.Errorf("无效的阶段: %s", to)
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("降级必须写明原因")
	}
	if err := s.db.Model(&model.DetectionRule{}).Where("id = ?", ruleID).
		Update("stage", to).Error; err != nil {
		return err
	}
	s.logger.Warn("检测规则已降级",
		zap.Uint("rule_id", ruleID),
		zap.String("to", to),
		zap.String("reason", reason),
		zap.String("actor", actor))
	return nil
}
