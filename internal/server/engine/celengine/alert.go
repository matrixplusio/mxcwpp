package celengine

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/consumer/sanitize"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/siem"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
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
}

// NewAlertGenerator 创建 AlertGenerator
func NewAlertGenerator(db *gorm.DB, logger *zap.Logger) *AlertGenerator {
	return &AlertGenerator{
		db:        db,
		log:       logger,
		throttler: NewHitThrottler(defaultHitBurstThreshold, defaultHitRefillWindow, defaultHitThrottleCapacity),
	}
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
	for i := range matchedRules {
		rule := &matchedRules[i]
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
	}
	if existing.Status != model.AlertStatusActive {
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
		ns := biz.NewNotificationService(g.db, g.log)
		if err := ns.SendDetectionAlertNotification(&biz.DetectionAlertData{
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
