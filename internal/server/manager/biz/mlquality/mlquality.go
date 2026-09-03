// Package mlquality 由人工研判结论评估 ML 异常检测的质量，并据此决定它能否升档。
//
// ML 异常检测此前无法回答"它准不准"。异常分数是模型的自我评价，不是正确性证据——
// 一个把整个环境都判成异常的模型，平均分数会很好看。
//
// 唯一可用的口径是人工研判：anomaly_alerts.status 的 confirmed / false_positive。
// 尚未研判的（open）不参与计算，它们既不是对也不是错，只是没人看过。
package mlquality

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// QualityWindowDays 统计窗口。
const QualityWindowDays = 30

// MinSamplesForPromotion 升档所需的最少已研判样本数。
const MinSamplesForPromotion = 30

// MinPrecisionForContext 升到 context 档所需的最低精确率。
//
// context 档的信号会进入 SOC 的分析上下文，错的多了会污染研判思路，
// 但不会直接把人叫醒，因此门槛低于告警档。
const MinPrecisionForContext = 0.70

// MinPrecisionForRanking 升到 ranking 档所需的最低精确率。
//
// 高于 context：ranking 会改变分析师**先看到什么**。排错顺序的代价不是多看一条，
// 而是把真实威胁推到列表后面——在告警多到看不完的环境里，排在后面等于没被看到。
const MinPrecisionForRanking = 0.80

// MinSamplesForRanking 升到 ranking 档所需的最少已研判样本数。
const MinSamplesForRanking = 50

// Quality 是 ML 异常检测的质量。
type Quality struct {
	Confirmed     int `json:"confirmed"`
	FalsePositive int `json:"false_positive"`
	// Open 尚未研判。不参与精确率，只说明覆盖率。
	Open int `json:"open"`

	// Precision 为 nil 表示样本不足、无法计算。
	//
	// 与检测规则同样的口径：缺失是"不知道"，不是 0，更不是"不达标"。
	Precision *float64 `json:"precision"`
	Judged    int      `json:"judged"`

	// ByPattern 按关联模式拆分。
	//
	// 总体精确率会掩盖单个模式的塌陷：线上出现过一个 c2_beacon 模式独自贡献
	// 三千多条误报的情况，而总体数字当时看起来并不刺眼。
	ByPattern map[string]PatternQuality `json:"by_pattern"`
}

// PatternQuality 是单个模式的质量。
type PatternQuality struct {
	Confirmed     int      `json:"confirmed"`
	FalsePositive int      `json:"false_positive"`
	Precision     *float64 `json:"precision"`
}

// Service 计算 ML 质量并把关档位提升。
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

// precisionOf 计算精确率，样本不足返回 nil。
func precisionOf(confirmed, falsePositive, minSamples int) *float64 {
	judged := confirmed + falsePositive
	if judged < minSamples {
		return nil
	}
	p := float64(confirmed) / float64(judged)
	return &p
}

// Measure 统计窗口内的 ML 异常检测质量。
func (s *Service) Measure() (*Quality, error) {
	since := model.ToLocalTime(time.Now().AddDate(0, 0, -QualityWindowDays))

	type row struct {
		PatternName string
		Status      string
		N           int
	}
	var rows []row
	// GROUP BY 必须重复整个表达式，不能用 SELECT 里的别名。
	//
	// MySQL 默认开启 only_full_group_by，按别名分组会被判为
	// "alert_type 不在 GROUP BY 中"（Error 1055）直接拒绝；而 sqlite 接受别名分组。
	// 单测跑在 sqlite 上因而全绿，真库上第一次调用就 500 —— 两边必须用同一种写法。
	const patternExpr = "COALESCE(NULLIF(pattern_name, ''), alert_type)"
	err := s.db.Model(&model.AnomalyAlert{}).
		Select(patternExpr+" AS pattern_name, status, COUNT(*) AS n").
		Where("created_at >= ?", since).
		Group(patternExpr + ", status").Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("统计异常告警研判结论失败: %w", err)
	}

	q := &Quality{ByPattern: make(map[string]PatternQuality)}
	for _, r := range rows {
		pq := q.ByPattern[r.PatternName]
		switch r.Status {
		case "confirmed":
			q.Confirmed += r.N
			pq.Confirmed += r.N
		case "false_positive":
			q.FalsePositive += r.N
			pq.FalsePositive += r.N
		default:
			q.Open += r.N
		}
		q.ByPattern[r.PatternName] = pq
	}
	for name, pq := range q.ByPattern {
		// 单模式用更低的样本门槛：等到某个模式攒够 30 条已研判样本，
		// 它可能已经刷了几千条了。
		pq.Precision = precisionOf(pq.Confirmed, pq.FalsePositive, 10)
		q.ByPattern[name] = pq
	}
	q.Judged = q.Confirmed + q.FalsePositive
	q.Precision = precisionOf(q.Confirmed, q.FalsePositive, MinSamplesForPromotion)
	return q, nil
}

// ModeDecision 说明 ML 档位能否提升。
type ModeDecision struct {
	Current  anomaly.Mode `json:"current"`
	Target   anomaly.Mode `json:"target"`
	Allowed  bool         `json:"allowed"`
	Reasons  []string     `json:"reasons"`
	Quality  *Quality     `json:"quality"`
	Blocking bool         `json:"blocking"`
}

// EvaluateModeChange 判断能否把 ML 异常检测切到目标档位。
//
// 降档（off/shadow）永远允许且不需要证据：出问题时必须能立刻把它按回去。
// 升档必须有人工研判支撑——档位提升意味着让更多人相信这些信号，
// 而"相信"应当基于它此前判对了多少次，不是基于模型自己给的分数。
func (s *Service) EvaluateModeChange(current, target anomaly.Mode) (*ModeDecision, error) {
	d := &ModeDecision{Current: current, Target: target}

	if !modeIsHigher(target, current) {
		d.Allowed = true
		return d, nil
	}

	// alert 档在 1.0 一律不开。1.0 封顶在 ranking。
	//
	// 无监督异常检测给出的是"少见"，不是"恶意"。少见的东西在任何真实环境里
	// 每天都有一堆——季度结算、批量导数、临时扩容都少见。让它直接定罪，
	// 结果就是值班被一堆"确实少见但完全无害"的事情叫醒，然后不再看告警。
	// ML 的位置是排序与佐证，不是定罪——这正是 ranking 档的意义。
	if target == anomaly.ModeAlert {
		d.Reasons = append(d.Reasons,
			"1.0 不开放 alert 档：无监督异常检测给出的是「少见」而不是「恶意」，不能独立定罪")
		d.Blocking = true
		return d, nil
	}

	q, err := s.Measure()
	if err != nil {
		return nil, err
	}
	d.Quality = q

	// 门槛按目标档位区分：越是会影响分析师看到什么的档位，要求越高。
	minSamples, minPrecision := MinSamplesForPromotion, MinPrecisionForContext
	if target == anomaly.ModeRanking {
		minSamples, minPrecision = MinSamplesForRanking, MinPrecisionForRanking
	}

	if q.Judged < minSamples {
		d.Reasons = append(d.Reasons, fmt.Sprintf(
			"已研判样本 %d 条，少于升到 %s 档所需的 %d 条（样本太少时精确率没有意义）",
			q.Judged, target, minSamples))
	}
	if q.Precision != nil && *q.Precision < minPrecision {
		d.Reasons = append(d.Reasons, fmt.Sprintf(
			"精确率 %.1f%%，低于升到 %s 档的门槛 %.0f%%",
			*q.Precision*100, target, minPrecision*100))
	}

	// 单个模式塌陷也要拦：总体精确率会掩盖它，而值班感受到的是那个模式在刷屏。
	for name, pq := range q.ByPattern {
		if pq.Precision != nil && *pq.Precision < 0.5 {
			d.Reasons = append(d.Reasons, fmt.Sprintf(
				"模式 %s 精确率仅 %.0f%%（%d 对 / %d 错），先治理该模式再升档",
				name, *pq.Precision*100, pq.Confirmed, pq.FalsePositive))
		}
	}

	d.Allowed = len(d.Reasons) == 0
	return d, nil
}

// modeIsHigher 判断 target 是否比 current 更放开。
func modeIsHigher(target, current anomaly.Mode) bool {
	return modeRank(target) > modeRank(current)
}

func modeRank(m anomaly.Mode) int {
	switch m {
	case anomaly.ModeOff:
		return 0
	case anomaly.ModeShadow:
		return 1
	case anomaly.ModeContext:
		return 2
	case anomaly.ModeRanking:
		return 3
	case anomaly.ModeAlert:
		return 4
	default:
		// 未知档位按最保守处理：任何切向它的动作都视为降档（允许），
		// 从它切出的动作都视为升档（要证据）。
		return 0
	}
}

// ApplyModeChange 校验后写入档位。
func (s *Service) ApplyModeChange(current, target anomaly.Mode, actor string) (*ModeDecision, error) {
	d, err := s.EvaluateModeChange(current, target)
	if err != nil {
		return nil, err
	}
	if !d.Allowed {
		return d, fmt.Errorf("不允许切换到 %s 档: %s", target, strings.Join(d.Reasons, "；"))
	}
	// 列名是 value，与 LoadMode 读取的字段一致。
	res := s.db.Model(&model.FeatureFlag{}).
		Where("flag_key = ?", model.FlagAnomalyDetectorMode).
		Update("value", string(target))
	if res.Error != nil {
		return nil, fmt.Errorf("写入档位失败: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		// flag 行不存在时 UPDATE 影响 0 行却不报错。若就此返回成功，
		// 调用方会以为档位已改，而 LoadMode 仍然读到旧值——典型的静默成功。
		return nil, fmt.Errorf("档位开关 %s 不存在，未做任何变更", model.FlagAnomalyDetectorMode)
	}
	s.logger.Warn("ML 异常检测档位已变更",
		zap.String("from", string(current)),
		zap.String("to", string(target)),
		zap.String("actor", actor))
	return d, nil
}
