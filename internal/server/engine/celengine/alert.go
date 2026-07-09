package celengine

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/siem"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

// notifyThrottleWindow 通知节流窗口：同一告警在此时间内不重复发送通知
const notifyThrottleWindow = 30 * time.Minute

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
	db            *gorm.DB
	log           *zap.Logger
	siemForwarder *siem.Forwarder // SIEM 转发器（可选）
	throttler     *HitThrottler   // (host, rule) 频率限制器
	// dbWhitelist 是 alert_whitelists 表中 exe/cmdline/host 维度条目的原子快照，
	// 由 StartWhitelistReload 周期刷新；热路径零锁读，承接 P2-B 自动调优采纳的 exception。
	dbWhitelist atomic.Pointer[[]model.AlertWhitelist]
	// hostCreatedAt 是 host_id → created_at 的原子快照，由 StartHostGraceReload 周期刷新。
	// created_at 不可变，缓存即可消除 hostInGrace 每事件一次的 DB 查（详见 host_grace.go）。
	hostCreatedAt atomic.Pointer[map[string]time.Time]
}

// NewAlertGenerator 创建 AlertGenerator
func NewAlertGenerator(db *gorm.DB, logger *zap.Logger) *AlertGenerator {
	g := &AlertGenerator{
		db:        db,
		log:       logger,
		throttler: NewHitThrottler(defaultHitBurstThreshold, defaultHitRefillWindow, defaultHitThrottleCapacity),
	}
	// 启动时立即加载一次，后续由 StartWhitelistReload / StartHostGraceReload 周期刷新
	g.reloadDBWhitelist()
	g.reloadHostCreatedAt()
	return g
}

// SetSIEMForwarder 设置 SIEM 转发器
func (g *AlertGenerator) SetSIEMForwarder(f *siem.Forwarder) {
	g.siemForwarder = f
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
		// 实测高频外连/DNS/枚举类单条 hit 数十万)。事件仍经 anomaly/storyline 关联,
		// 多信号关联命中才升级为告警(CrowdStrike IOA 模型)。
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
		// DB 白名单(exe/cmdline/host 维度)：P2-B 自动调优经人审采纳的 exception。
		// 与编译内置白名单同语义(命中即抑制)，但运行时可增删,经原子快照零锁读热路径。
		if ok, reason := g.matchDBWhitelist(fmt.Sprintf("cel-%d", rule.ID), hostID, categorize(rule), rule.Severity, fields); ok {
			g.log.Debug("CEL 告警命中 DB 白名单已抑制(自动调优采纳)",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("host_id", hostID),
				zap.String("reason", reason),
				zap.String("exe", fields["exe"]),
			)
			continue
		}
		if g.throttler != nil {
			ruleKey := fmt.Sprintf("cel-%d", rule.ID)
			if !g.throttler.Allow(hostID, ruleKey, now) {
				// 不打印日志，避免日志洪水；throttle 统计走 metrics（后续接入）
				continue
			}
		}
		if err := g.upsertAlert(hostID, rule, fields); err != nil {
			g.log.Error("CEL 检测告警 upsert 失败",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("host_id", hostID),
				zap.Error(err),
			)
		}
	}
}

// upsertAlert 查找已有告警并更新，不存在则创建
// ResultID = cel-{ruleID}-{hostID}（固定，不含 timestamp）
func (g *AlertGenerator) upsertAlert(hostID string, rule *model.DetectionRule, fields map[string]string) error {
	// 脱敏后存储：对 cmdline 中的凭据进行遮蔽
	masked := make(map[string]string, len(fields))
	for k, v := range fields {
		masked[k] = v
	}
	sanitize.Fields(masked)

	detail, err := json.Marshal(masked)
	if err != nil {
		return fmt.Errorf("序列化告警详情失败: %w", err)
	}

	resultID := fmt.Sprintf("cel-%d-%s", rule.ID, hostID)
	now := model.ToLocalTime(time.Now())

	// 尝试查找已有告警
	var existing model.Alert
	err = g.db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		return g.refreshExistingAlert(&existing, now, string(detail), masked)
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("查询告警失败: %w", err)
	}

	// 不存在 → 创建新告警
	alert := model.Alert{
		ResultID:    resultID,
		HostID:      hostID,
		RuleID:      fmt.Sprintf("cel-%d", rule.ID),
		Source:      model.AlertSourceDetection,
		Severity:    rule.Severity,
		RiskScore:   g.computeRiskScore(hostID, rule),
		Category:    categorize(rule),
		Title:       rule.Name,
		Description: rule.Description,
		Actual:      string(detail),
		Status:      model.AlertStatusActive,
		HitCount:    1,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	if err := g.db.Create(&alert).Error; err != nil {
		// 并发竞争：另一 worker 已插入同 result_id（SELECT 与 INSERT 之间的 TOCTOU）。
		// 转为更新路径，避免丢失命中计数并消除 duplicate key 报错。
		if isDuplicateKeyErr(err) {
			var raced model.Alert
			if e := g.db.Where("result_id = ?", resultID).First(&raced).Error; e == nil {
				return g.refreshExistingAlert(&raced, now, string(detail), masked)
			}
		}
		return fmt.Errorf("写入 alerts 表失败: %w", err)
	}

	g.log.Info("CEL 检测告警生成",
		zap.Uint("rule_id", rule.ID),
		zap.String("rule_name", rule.Name),
		zap.String("host_id", hostID),
		zap.String("severity", rule.Severity),
	)

	g.sendNotification(&alert)
	g.forwardToSIEM(&alert, masked)

	return nil
}

// refreshExistingAlert 对已存在告警做命中更新：last_seen/hit_count/actual，必要时重新激活，
// 并按节流发送通知 + SIEM 转发。首次命中查到已存在、以及并发 INSERT 冲突回退两条路径复用。
func (g *AlertGenerator) refreshExistingAlert(existing *model.Alert, now model.LocalTime, detail string, masked map[string]string) error {
	updates := map[string]any{
		"last_seen_at": now,
		"hit_count":    gorm.Expr("hit_count + 1"),
		"actual":       detail,
		// 重算风险分：关联升级(同主机多类告警)会随攻击链推进抬高分值(IOA)
		"risk_score": g.computeRiskScoreForExisting(existing),
	}
	// 仅 resolved(已解决)再命中才重新激活；ignored(已忽略)语义=静音，用户主动忽略后不应被同类事件刷回 active
	if existing.Status == model.AlertStatusResolved {
		updates["status"] = model.AlertStatusActive
		g.log.Info("CEL 告警重新激活",
			zap.String("result_id", existing.ResultID),
			zap.String("prev_status", string(existing.Status)),
		)
	}
	if err := g.db.Model(existing).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新告警失败: %w", err)
	}
	if g.shouldNotify(existing) {
		g.db.Model(existing).Updates(map[string]any{
			"last_notified_at": now,
			"notify_count":     gorm.Expr("notify_count + 1"),
		})
		g.sendNotification(existing)
	}
	g.forwardToSIEM(existing, masked)
	return nil
}

// isDuplicateKeyErr 判断是否 MySQL 唯一键冲突 (errno 1062)。
func isDuplicateKeyErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Duplicate entry")
}

// shouldNotify 判断是否应发送通知（节流）
func (g *AlertGenerator) shouldNotify(alert *model.Alert) bool {
	if alert.LastNotifiedAt == nil {
		return true
	}
	return time.Since(alert.LastNotifiedAt.Time()) > notifyThrottleWindow
}

// sendNotification 异步发送检测告警通知
func (g *AlertGenerator) sendNotification(alert *model.Alert) {
	go func(a *model.Alert) {
		var host model.Host
		hostname, ip := "", ""
		if g.db.Select("hostname, ipv4").First(&host, "host_id = ?", a.HostID).Error == nil {
			hostname = host.Hostname
			if len(host.IPv4) > 0 {
				ip = host.IPv4[0]
			}
		}
		ns := notify.NewNotificationService(g.db, g.log)
		if err := ns.SendDetectionAlertNotification(&notify.DetectionAlertData{
			HostID:      a.HostID,
			Hostname:    hostname,
			IP:          ip,
			RuleName:    a.Title,
			Severity:    a.Severity,
			Category:    a.Category,
			Description: a.Description,
			DetectedAt:  a.FirstSeenAt.Time(),
		}); err != nil {
			g.log.Error("发送检测告警通知失败", zap.Error(err))
		}
	}(alert)
}

// forwardToSIEM 将告警转发到 SIEM 系统
func (g *AlertGenerator) forwardToSIEM(alert *model.Alert, fields map[string]string) {
	if g.siemForwarder == nil {
		return
	}
	go g.siemForwarder.SendAlert(siem.AlertEvent{
		EventID:  "rule_match",
		Name:     alert.Title,
		Severity: alert.Severity,
		HostID:   alert.HostID,
		Hostname: fields["hostname"],
		SourceIP: fields["src_ip"],
		DestIP:   fields["dst_ip"],
		PID:      fields["pid"],
		Exe:      fields["exe"],
		Cmdline:  fields["cmdline"],
		RuleID:   alert.RuleID,
		MITRE:    fields["mitre_id"],
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

// GenerateFromIOC 服务端 IOC 匹配命中 → 生成/更新 ioc_hit 告警。
// 命中字段写入 ioc_match/ioc_type/ioc_value,前端研判可溯源命中来源。尊重白名单。
func (g *AlertGenerator) GenerateFromIOC(hostID, iocType, iocValue string, fields map[string]string) {
	ruleKey := "ioc-" + iocType
	if ok, _ := g.matchDBWhitelist(ruleKey, hostID, IOCHitCategory, "critical", fields); ok {
		return
	}

	masked := make(map[string]string, len(fields)+3)
	for k, v := range fields {
		masked[k] = v
	}
	masked["ioc_match"] = "true"
	masked["ioc_type"] = iocType
	masked["ioc_value"] = iocValue
	sanitize.Fields(masked)
	detail, _ := json.Marshal(masked)

	resultID := fmt.Sprintf("ioc-%s-%s-%s", iocType, iocValue, hostID)
	now := model.ToLocalTime(time.Now())

	var existing model.Alert
	err := g.db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		_ = g.refreshExistingAlert(&existing, now, string(detail), masked)
		return
	}
	if err != gorm.ErrRecordNotFound {
		g.log.Warn("查询 IOC 告警失败", zap.String("result_id", resultID), zap.Error(err))
		return
	}

	alert := model.Alert{
		ResultID:       resultID,
		HostID:         hostID,
		RuleID:         ruleKey,
		Source:         model.AlertSourceDetection,
		Severity:       "critical",
		RiskScore:      85,
		Category:       IOCHitCategory,
		ATTCKTechnique: "T1071",
		Title:          iocHitTitle(iocType),
		Description:    "外联/访问命中威胁情报库的恶意 " + iocType + ":" + iocValue,
		Actual:         string(detail),
		Status:         model.AlertStatusActive,
		HitCount:       1,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
	if err := g.db.Create(&alert).Error; err != nil {
		if isDuplicateKeyErr(err) {
			var raced model.Alert
			if e := g.db.Where("result_id = ?", resultID).First(&raced).Error; e == nil {
				_ = g.refreshExistingAlert(&raced, now, string(detail), masked)
			}
			return
		}
		g.log.Warn("写入 IOC 告警失败", zap.String("result_id", resultID), zap.Error(err))
		return
	}
	g.log.Info("IOC 命中告警生成", zap.String("ioc_type", iocType), zap.String("ioc_value", iocValue), zap.String("host_id", hostID))
	g.sendNotification(&alert)
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
	if ok, reason := g.matchDBWhitelist(seqRuleID, hostID, AttackChainCategory, rule.Severity, fields); ok {
		g.log.Debug("攻击链告警命中白名单已抑制(用户研判/调优学习)",
			zap.String("rule", rule.Name), zap.String("host_id", hostID), zap.String("reason", reason))
		return
	}

	masked := make(map[string]string, len(fields))
	for k, v := range fields {
		masked[k] = v
	}
	sanitize.Fields(masked)
	detail, _ := json.Marshal(masked)

	resultID := fmt.Sprintf("seq-%d-%s", rule.ID, hostID)
	now := model.ToLocalTime(time.Now())

	var existing model.Alert
	err := g.db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		_ = g.refreshExistingAlert(&existing, now, string(detail), masked)
		return
	}
	if err != gorm.ErrRecordNotFound {
		g.log.Warn("查询攻击链告警失败", zap.String("result_id", resultID), zap.Error(err))
		return
	}

	alert := model.Alert{
		ResultID:       resultID,
		HostID:         hostID,
		RuleID:         fmt.Sprintf("seq-%d", rule.ID),
		Source:         model.AlertSourceDetection,
		Severity:       rule.Severity,
		RiskScore:      sequenceRiskScore(rule.Severity),
		Category:       AttackChainCategory,
		ATTCKTechnique: rule.MitreID,
		Title:          rule.Name,
		Description:    rule.Description,
		Actual:         string(detail),
		Status:         model.AlertStatusActive,
		HitCount:       1,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
	if err := g.db.Create(&alert).Error; err != nil {
		if isDuplicateKeyErr(err) {
			var raced model.Alert
			if e := g.db.Where("result_id = ?", resultID).First(&raced).Error; e == nil {
				_ = g.refreshExistingAlert(&raced, now, string(detail), masked)
			}
			return
		}
		g.log.Warn("写入攻击链告警失败", zap.String("result_id", resultID), zap.Error(err))
		return
	}

	g.log.Info("攻击链告警生成",
		zap.Uint("rule_id", rule.ID),
		zap.String("rule_name", rule.Name),
		zap.String("host_id", hostID),
		zap.String("severity", rule.Severity),
	)
	g.sendNotification(&alert)
	g.forwardToSIEM(&alert, masked)
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
