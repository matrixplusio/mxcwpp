package celengine

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// defaultHitBurstThreshold 单 (host, rule) 1min 内命中超过此值开启 10min 静默
	defaultHitBurstThreshold = 50
	// defaultHitRefillWindow 计数窗口
	defaultHitRefillWindow = 1 * time.Minute
	// defaultHitThrottleCapacity LRU 上限 (209 host × 94 rule ≈ 20k，留 2x 余量)
	defaultHitThrottleCapacity = 40000
)

// AlertGenerator 负责将 CEL 引擎匹配结果写入 alerts 表（去重模式）
type AlertGenerator struct {
	db        *gorm.DB
	log       *zap.Logger
	throttler *HitThrottler // (host, rule) 频率限制器
	// dbWhitelist 是 alert_whitelists 表中 exe/cmdline/host 维度条目的原子快照，
	// 由 StartWhitelistReload 周期刷新；热路径零锁读，承接 P2-B 自动调优采纳的 exception。
	dbWhitelist atomic.Pointer[[]model.AlertWhitelist]
	// whitelistGuard 每次加载白名单时构造检查函数，剔除会让检测失效的条目（见 whitelist_guard.go）。
	// rejectedWhitelists 上一次被剔除的条目，只由加载白名单的那一个 goroutine 读写。
	whitelistGuard     func() WhitelistGuard
	rejectedWhitelists map[uint]string
	// hostCreatedAt 是 host_id → created_at 的原子快照，由 StartHostGraceReload 周期刷新。
	// created_at 不可变，缓存即可消除 hostInGrace 每事件一次的 DB 查（详见 host_grace.go）。
	hostCreatedAt atomic.Pointer[map[string]time.Time]
	// fleet 全舰队命中守卫（见 fleet_guard.go）。为空时不启用。
	fleet *fleetGuard
	// shadow 累计影子阶段规则的命中量，周期落库供晋级决策使用。
	shadow *shadowRecorder
	// mlRankCache 是 host_id → ML 排序加权的原子快照（详见 ml_rank.go）。
	// 由 StartRiskCacheReload 周期刷新；只影响告警排序，不产生告警。
	mlRankCache atomic.Pointer[map[string]float64]
	// assetWeightCache（host_id → 资产权重）、correlationBoostCache（host_id → 关联加权）
	// 是风险打分两项输入的原子快照，由 StartRiskCacheReload 周期刷新（详见 risk_cache.go）。
	// 消除 computeRiskScore 每事件两次 DB 查（assetWeight / correlationBoost），避免热路径访问数据库。
	assetWeightCache      atomic.Pointer[map[string]float64]
	correlationBoostCache atomic.Pointer[map[string]float64]
	// onAlert 每新开一条告警时调用（并进已开告警的命中、被抑制的不算），供上层按检测阶段计数。
	// 本包不能反向依赖 engine 的指标，故以回调注入；为空时不计。
	onAlert func(stage, ruleID, severity string)
	// criticalGate 决定规则的告警能否落成 critical（见 critical_gate.go）。为空时不限制。
	criticalGate *CriticalGate
}

// SetCriticalGate 注入 critical 准入判断。须在开始处理事件之前设置。
func (g *AlertGenerator) SetCriticalGate(gate *CriticalGate) {
	g.criticalGate = gate
}

// SetAlertObserver 注入「新开告警」回调。须在开始处理事件之前设置。
func (g *AlertGenerator) SetAlertObserver(fn func(stage, ruleID, severity string)) {
	g.onAlert = fn
}

func (g *AlertGenerator) notifyAlert(stage string, a *model.Alert) {
	if g.onAlert != nil {
		g.onAlert(stage, a.RuleID, a.Severity)
	}
}

// NewAlertGenerator 创建 AlertGenerator
func NewAlertGenerator(db *gorm.DB, logger *zap.Logger) *AlertGenerator {
	g := &AlertGenerator{
		db:        db,
		log:       logger,
		throttler: NewHitThrottler(defaultHitBurstThreshold, defaultHitRefillWindow, defaultHitThrottleCapacity),
		fleet:     newFleetGuard(),
	}
	g.shadow = newShadowRecorder(db, logger)
	g.shadow.StartShadowFlush(shadowFlushInterval)
	// 启动时立即加载一次，后续由 StartWhitelistReload / StartHostGraceReload / StartRiskCacheReload 周期刷新
	g.reloadDBWhitelist()
	g.reloadHostCreatedAt()
	g.reloadAssetWeightCache()
	g.reloadCorrelationBoostCache()
	g.reloadMLRankCache()
	return g
}

// Generate 根据匹配的规则和事件字段生成或更新告警
// 去重策略：同一规则 + 同一主机合并为一条告警，累加 HitCount
//
// 告警入库前调用 IsAlertWhitelisted 过滤已知误报模式（反代上游 / 内网通信等），
// 避免 nginx → backend:8888 这种业务流量被 C2 规则刷屏。
func (g *AlertGenerator) Generate(hostID string, matchedRules []model.DetectionRule, fields map[string]string) {
	now := time.Now()
	// 主机上线观察期只取决于主机本身，每次 Generate 查一次即可（单主机），避免在规则循环里重复查。
	hostGraced := g.hostInGrace(hostID, now)
	for i := range matchedRules {
		rule := &matchedRules[i]
		// 低保真单信号规则降级为 indicator：不独立出告警(否则在繁忙业务负载上刷屏,
		// 高频外连/DNS/枚举类单条规则命中量极大)。事件仍经 anomaly/storyline 关联,
		// 多信号关联命中才升级为告警(CrowdStrike IOA 模型)。
		// 生命周期阶段先于一切其他判断：draft 不该被评估，shadow/context
		// 不该独立告警。放在后面等于让未验证的规则先打扰到人再补救。
		if !rule.AlertsIndependently() {
			if rule.Stage == model.RuleStageShadow && g.shadow != nil {
				// 影子命中必须留痕，否则它永远凑不齐晋级所需的观察数据，
				// 会卡死在影子阶段。
				g.shadow.record(fmt.Sprintf("cel-%d", rule.ID), hostID)
			}
			continue
		}
		if rule.IsLowFidelity() {
			continue
		}
		// detect-only 上线观察期：新增非内置规则 / 新上线主机的命中降级 indicator 不告警,
		// 给环境留调 exception 的窗口(critical 规则豁免,真威胁不等)。见 detectonly.go。
		if inGrace, dim := graceDecision(rule, hostGraced, now); inGrace {
			g.log.Debug("CEL 告警处于上线观察期已降级 indicator",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("host_id", hostID),
				zap.String("grace_dim", dim),
			)
			continue
		}
		if ok, reason := IsAlertWhitelisted(rule, fields); ok {
			g.log.Debug("CEL 告警命中白名单已抑制",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("host_id", hostID),
				zap.String("reason", reason),
				zap.String("exe", fields["exe"]),
				zap.String("dst_ip", fields["dst_ip"]),
			)
			continue
		}
		// 抑制规则(alert_whitelists 的 exe/cmdline/host 维度)：命中照常记录为 suppressed 告警，
		// 不进处置队列、不通知，但留下计数并供事件关联作上下文——丢弃会让被抑制的活动彻底不可见。
		sb := suppressBy{rule: g.matchDBWhitelist(fmt.Sprintf("cel-%d", rule.ID), hostID, categorize(rule), rule.Severity, fields)}
		if sb.rule == nil {
			ruleKey := fmt.Sprintf("cel-%d", rule.ID)
			sb.fleet = g.checkFleet(ruleKey, rule.Name, g.criticalGate.Cap(ruleKey, rule.Severity), hostID, now)
		}
		if g.throttler != nil {
			ruleKey := fmt.Sprintf("cel-%d", rule.ID)
			if !g.throttler.Allow(hostID, ruleKey, now) {
				// 不打印日志，避免日志洪水；throttle 统计走 metrics（后续接入）
				continue
			}
		}
		if err := g.upsertAlert(hostID, rule, fields, sb); err != nil {
			g.log.Error("CEL 检测告警 upsert 失败",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("host_id", hostID),
				zap.Error(err),
			)
		}
	}
}

// upsertAlert 把命中落到 cel-{ruleID}-{hostID} 分组：并入仍开着的告警，或新建（首次 / 复发）。
func (g *AlertGenerator) upsertAlert(hostID string, rule *model.DetectionRule, fields map[string]string, sb suppressBy) error {
	// 脱敏后存储：对 cmdline 中的凭据进行遮蔽
	masked := make(map[string]string, len(fields))
	for k, v := range fields {
		masked[k] = v
	}
	sanitize.Fields(masked)

	groupKey := fmt.Sprintf("cel-%d-%s", rule.ID, hostID)
	now := model.ToLocalTime(time.Now())
	// 只压告警落库的级别。风险分、观察期豁免、自动响应仍按规则声明的级别走：
	// 那些回答的是「这类行为有多危险」，准入回答的是「这条规则的命中有多可信」。
	severity := g.criticalGate.Cap(fmt.Sprintf("cel-%d", rule.ID), rule.Severity)
	// 被压过级的要留痕：只存压后的级别的话，没人看得出这条告警的规则本来声明的是 critical。
	if severity != rule.Severity {
		masked["declared_severity"] = rule.Severity
	}
	detail, err := json.Marshal(masked)
	if err != nil {
		return fmt.Errorf("序列化告警详情失败: %w", err)
	}

	created, err := model.UpsertGroupedAlert(g.db, sb.groupKey(groupKey), func() model.Alert {
		return sb.apply(model.Alert{
			HostID:         hostID,
			RuleID:         fmt.Sprintf("cel-%d", rule.ID),
			Source:         model.AlertSourceDetection,
			Severity:       severity,
			RiskScore:      g.computeRiskScore(hostID, rule),
			Category:       categorize(rule),
			ATTCKTechnique: rule.MitreID,
			ATTCKTactic:    tacticFromTechnique(rule.MitreID),
			Title:          rule.Name,
			Description:    rule.Description,
			Actual:         string(detail),
			Status:         model.AlertStatusActive,
			HitCount:       1,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		})
	}, func(existing *model.Alert) error {
		return g.refreshExistingAlert(existing, now, string(detail), masked)
	})
	if err != nil {
		return err
	}
	if created == nil || sb.active() {
		return nil
	}
	alert := *created
	g.notifyAlert("cel_rule", &alert)

	g.log.Info("CEL 检测告警生成",
		zap.Uint("rule_id", rule.ID),
		zap.String("rule_name", rule.Name),
		zap.String("host_id", hostID),
		zap.String("severity", severity),
	)

	g.forwardToSIEM(&alert, masked)

	return nil
}

// refreshExistingAlert 对已存在告警做命中更新：last_seen/hit_count/actual，必要时重新激活，
// 并做 SIEM 转发。通知由 manager 统一出口从告警表桥接：只在首次与复发时发，不再按节流重复。首次命中查到已存在、以及并发 INSERT 冲突回退两条路径复用。
func (g *AlertGenerator) refreshExistingAlert(existing *model.Alert, now model.LocalTime, detail string, masked map[string]string) error {
	updates := map[string]any{
		"last_seen_at": now,
		"hit_count":    gorm.Expr("hit_count + 1"),
		"actual":       detail,
		// 重算风险分：关联升级(同主机多类告警)会随攻击链推进抬高分值(IOA)
		"risk_score": g.computeRiskScoreForExisting(existing),
	}
	// 只有仍开着的告警会走到这里（model.UpsertGroupedAlert 保证）：关闭过的告警不再改写，
	// 复发由分组生成新告警。被抑制的告警照常累计，但不通知。
	if err := g.db.Model(existing).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新告警失败: %w", err)
	}
	g.forwardToSIEM(existing, masked)
	return nil
}

// forwardToSIEM 将告警转发到 SIEM 系统
func (g *AlertGenerator) forwardToSIEM(alert *model.Alert, fields map[string]string) {
	// 统一走 alertbus 的外发出口，不再每条告警起一个 goroutine 去抢同一把锁——
	// 告警风暴下那会堆出大量阻塞协程。外发本身是有界异步队列，满则丢弃并计量。
	//
	// EgressOnly：alerts 表这条链路的通知由 AgentCenter 内联与 Manager 定时器负责，
	// 此处只保证客户 SIEM 收到记录，不重复通知。
	alertbus.Publish(alertbus.Event{
		Category:    model.NotifyCategoryDetection,
		Source:      "cel_rule",
		HostID:      alert.HostID,
		Hostname:    fields["hostname"],
		IP:          fields["src_ip"],
		Severity:    alert.Severity,
		Title:       alert.Title,
		Description: alert.Description,
		DedupKey:    alert.ResultID,
		RefTable:    "alerts",
		RefID:       alert.ResultID,
		EgressOnly:  true,
	})
}

// AttackChainCategory 攻击链(序列)命中的告警分类，供 incident 关联识别为强信号
const AttackChainCategory = "attack_chain"

// IOCHitCategory 威胁情报命中告警分类
const IOCHitCategory = "ioc_hit"

// iocHitTitle 按 IOC 类型给标题(与内置 CEL ioc_hit 规则语义一致)
func iocHitTitle(iocType string) string {
	switch iocType {
	case "ip":
		return "IOC 碰撞 - 恶意 IP 通信"
	case "hash":
		return "IOC 碰撞 - 恶意文件哈希"
	case "url":
		return "IOC 碰撞 - 恶意 URL 访问"
	default:
		return "IOC 碰撞 - 威胁情报命中"
	}
}

// iocSeverityAndRisk 按 IOC 类型的天然置信度给告警 severity + risk_score，
// 替代"一律 critical/85"（IP 类共享/CDN/复用多，置信度天然低于 hash 精确命中）。
//   - hash：文件哈希精确匹配恶意样本，高置信 → critical
//   - url ：URL 命中，较高置信 → high
//   - ip  ：IP 易因共享云 IP/CDN/历史复用误伤，降级 → high（并已结合方向抑制入站）
func iocSeverityAndRisk(iocType string) (severity string, risk int) {
	switch iocType {
	case "hash":
		return "critical", 90
	case "url":
		return "high", 72
	case "ip":
		return "high", 65
	default:
		return "high", 60
	}
}

// iocInboundSuppressed 判断 IOC 命中是否因入站方向被抑制。
// 公网服务被全网扫描,源 IP 恰在情报库=背景噪音,非本机主动外联 C2;仅出站(本机 → 恶意 IP)
// 才是真 C2 指标。仅对 ip 类命中生效(hash/url 无方向语义)。方向字段缺失时不抑制(保守保留告警)。
func iocInboundSuppressed(iocType, direction string) bool {
	return iocType == "ip" && direction == "inbound"
}

// GenerateFromIOC 服务端 IOC 匹配命中 → 生成/更新 ioc_hit 告警。
// 命中字段写入 ioc_match/ioc_type/ioc_value,前端研判可溯源命中来源。尊重白名单。
func (g *AlertGenerator) GenerateFromIOC(hostID, iocType, iocValue string, fields map[string]string) {
	// 入站 IP 命中抑制：公网服务被全网扫描,源 IP 恰在情报库=背景噪音,
	// 非本机主动外联 C2。仅出站(本机 → 恶意 IP)才是真 C2 指标。避免公网面主机被扫描刷屏。
	// hash/url 命中无方向语义,不受此限。
	if iocInboundSuppressed(iocType, fields["direction"]) {
		return
	}
	ruleKey := "ioc-" + iocType
	sb := suppressBy{rule: g.matchDBWhitelist(ruleKey, hostID, IOCHitCategory, "critical", fields)}

	masked := make(map[string]string, len(fields)+3)
	for k, v := range fields {
		masked[k] = v
	}
	masked["ioc_match"] = "true"
	masked["ioc_type"] = iocType
	masked["ioc_value"] = iocValue
	sanitize.Fields(masked)
	detail, _ := json.Marshal(masked)

	groupKey := fmt.Sprintf("ioc-%s-%s-%s", iocType, iocValue, hostID)
	now := model.ToLocalTime(time.Now())

	iocSeverity, iocRisk := iocSeverityAndRisk(iocType)
	iocSeverity = g.criticalGate.Cap(ruleKey, iocSeverity)
	created, err := model.UpsertGroupedAlert(g.db, sb.groupKey(groupKey), func() model.Alert {
		return sb.apply(model.Alert{
			HostID:         hostID,
			RuleID:         ruleKey,
			Source:         model.AlertSourceDetection,
			Severity:       iocSeverity,
			RiskScore:      iocRisk,
			Category:       IOCHitCategory,
			ATTCKTechnique: "T1071",
			ATTCKTactic:    tacticFromTechnique("T1071"),
			Title:          iocHitTitle(iocType),
			Description:    "外联/访问命中威胁情报库的恶意 " + iocType + ":" + iocValue,
			Actual:         string(detail),
			Status:         model.AlertStatusActive,
			HitCount:       1,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		})
	}, func(existing *model.Alert) error {
		return g.refreshExistingAlert(existing, now, string(detail), masked)
	})
	if err != nil {
		g.log.Warn("写入 IOC 告警失败", zap.String("group_key", groupKey), zap.Error(err))
		return
	}
	if created == nil || sb.active() {
		return
	}
	alert := *created
	g.notifyAlert("ioc", &alert)
	g.log.Info("IOC 命中告警生成", zap.String("ioc_type", iocType), zap.String("ioc_value", iocValue), zap.String("host_id", hostID))
	g.forwardToSIEM(&alert, masked)
}

// ConfirmedSourceRuleID 已确认攻击源连入告警的规则 ID，供通知按规则订阅。
const ConfirmedSourceRuleID = "ioc-confirmed-source"

// GenerateFromConfirmedSource 自有情报库里的已确认攻击源向本机发起了连接 → 生成/更新 critical 告警。
//
// 与 GenerateFromIOC 分开：那边的入站 IP 命中一律抑制，因为外部 feed 里的地址打到公网服务上
// 只是全网扫描的背景噪声。这里的地址是我们自己研判确认过的攻击者，它再出现就是事件本身。
// 仍尊重白名单，误录入时有办法止损。
func (g *AlertGenerator) GenerateFromConfirmedSource(hostID, ip string, fields map[string]string) {
	// 同一来源对同一主机的连接可以很密（爆破、扫描），逐条刷新告警只是在打数据库；
	// 第一条已经把事情说清了，后面的按频率放行即可。
	if g.throttler != nil && !g.throttler.Allow(hostID, ConfirmedSourceRuleID+"-"+ip, time.Now()) {
		return
	}
	sb := suppressBy{rule: g.matchDBWhitelist(ConfirmedSourceRuleID, hostID, IOCHitCategory, "critical", fields)}

	masked := make(map[string]string, len(fields)+3)
	for k, v := range fields {
		masked[k] = v
	}
	masked["ioc_match"] = "true"
	masked["ioc_type"] = "ip"
	masked["ioc_value"] = ip
	sanitize.Fields(masked)
	detail, _ := json.Marshal(masked)

	groupKey := fmt.Sprintf("ioc-confirmed-%s-%s", ip, hostID)
	now := model.ToLocalTime(time.Now())
	created, err := model.UpsertGroupedAlert(g.db, sb.groupKey(groupKey), func() model.Alert {
		return sb.apply(model.Alert{
			HostID:         hostID,
			RuleID:         ConfirmedSourceRuleID,
			Source:         model.AlertSourceDetection,
			Severity:       "critical",
			RiskScore:      95,
			Category:       IOCHitCategory,
			ATTCKTechnique: "T1046",
			ATTCKTactic:    tacticFromTechnique("T1046"),
			Title:          "已确认攻击源连入 - " + ip,
			Description: "自有情报库里的已确认攻击源 " + ip + " 向本机发起了连接。" +
				"这个来源此前已被研判为真实攻击，再次出现应立即核对它访问了什么，并考虑在边界封禁。",
			Actual:      string(detail),
			Status:      model.AlertStatusActive,
			HitCount:    1,
			FirstSeenAt: now,
			LastSeenAt:  now,
		})
	}, func(existing *model.Alert) error {
		return g.refreshExistingAlert(existing, now, string(detail), masked)
	})
	if err != nil {
		g.log.Warn("写入已确认攻击源告警失败", zap.String("group_key", groupKey), zap.Error(err))
		return
	}
	if created == nil || sb.active() {
		return
	}
	alert := *created
	g.notifyAlert("ioc", &alert)
	g.log.Warn("已确认攻击源连入", zap.String("ip", ip), zap.String("host_id", hostID))
	g.forwardToSIEM(&alert, masked)
}

// sequenceRiskScore 攻击链命中风险分：多步关联=高置信，按严重度给高基线分
func sequenceRiskScore(severity string) int {
	switch severity {
	case "critical":
		return 90
	case "high":
		return 78
	case "medium":
		return 62
	default:
		return 50
	}
}

// GenerateFromSequence 为攻击链(序列)命中生成/更新告警并落 alerts 表。
// 攻击链是多步关联的高置信检测，以 category=attack_chain 标记，供 incident 关联识别为强 IOA 信号。
// 仍尊重用户研判/调优学到的 DB 白名单(同规则+主机被判误报)→ 命中即抑制，使研判学习对攻击链同样闭环。
func (g *AlertGenerator) GenerateFromSequence(hostID string, rule model.SequenceRule, fields map[string]string) {
	seqRuleID := fmt.Sprintf("seq-%d", rule.ID)
	sb := suppressBy{rule: g.matchDBWhitelist(seqRuleID, hostID, AttackChainCategory, rule.Severity, fields)}
	if sb.rule == nil {
		sb.fleet = g.checkFleet(seqRuleID, rule.Name, g.criticalGate.Cap(seqRuleID, rule.Severity), hostID, time.Now())
	}

	masked := make(map[string]string, len(fields))
	for k, v := range fields {
		masked[k] = v
	}
	sanitize.Fields(masked)
	detail, _ := json.Marshal(masked)

	groupKey := fmt.Sprintf("seq-%d-%s", rule.ID, hostID)
	now := model.ToLocalTime(time.Now())
	severity := g.criticalGate.Cap(seqRuleID, rule.Severity)

	created, err := model.UpsertGroupedAlert(g.db, sb.groupKey(groupKey), func() model.Alert {
		return sb.apply(model.Alert{
			HostID:         hostID,
			RuleID:         fmt.Sprintf("seq-%d", rule.ID),
			Source:         model.AlertSourceDetection,
			Severity:       severity,
			RiskScore:      sequenceRiskScore(rule.Severity),
			Category:       AttackChainCategory,
			ATTCKTechnique: rule.MitreID,
			ATTCKTactic:    tacticFromTechnique(rule.MitreID),
			Title:          rule.Name,
			Description:    rule.Description,
			Actual:         string(detail),
			Status:         model.AlertStatusActive,
			HitCount:       1,
			FirstSeenAt:    now,
			LastSeenAt:     now,
		})
	}, func(existing *model.Alert) error {
		return g.refreshExistingAlert(existing, now, string(detail), masked)
	})
	if err != nil {
		g.log.Warn("写入攻击链告警失败", zap.String("group_key", groupKey), zap.Error(err))
		return
	}
	if created == nil || sb.active() {
		return
	}
	alert := *created
	g.notifyAlert("sequence", &alert)

	g.log.Info("攻击链告警生成",
		zap.Uint("rule_id", rule.ID),
		zap.String("rule_name", rule.Name),
		zap.String("host_id", hostID),
		zap.String("severity", severity),
	)
	g.forwardToSIEM(&alert, masked)
}

// suppressBy 说明一次命中为什么不进处置队列：命中了某条抑制规则，或被全舰队守卫降级。
type suppressBy struct {
	rule  *model.AlertWhitelist
	fleet bool
}

func (sb suppressBy) active() bool { return sb.rule != nil || sb.fleet }

// groupKey 被抑制的命中单独成组，不并进人在处置的告警。
func (sb suppressBy) groupKey(groupKey string) string {
	if !sb.active() {
		return groupKey
	}
	return model.SuppressedGroupKey(groupKey)
}

// apply 把新建告警标记为 suppressed；由抑制规则压下的记下规则 ID。
func (sb suppressBy) apply(a model.Alert) model.Alert {
	if !sb.active() {
		return a
	}
	a.Status = model.AlertStatusSuppressed
	if sb.rule != nil {
		id := sb.rule.ID
		a.SuppressionID = &id
	}
	return a
}

// categorize 根据规则信息确定告警分类
func categorize(rule *model.DetectionRule) string {
	if rule.Category != "" {
		return rule.Category
	}
	if rule.MitreID != "" {
		return "mitre:" + rule.MitreID
	}
	return "cel-detection"
}
