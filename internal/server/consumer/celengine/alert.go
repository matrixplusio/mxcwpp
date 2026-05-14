package celengine

import (
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AlertGenerator 负责将 CEL 引擎匹配结果写入 alerts 表
type AlertGenerator struct {
	db  *gorm.DB
	log *zap.Logger
}

// NewAlertGenerator 创建 AlertGenerator
func NewAlertGenerator(db *gorm.DB, logger *zap.Logger) *AlertGenerator {
	return &AlertGenerator{
		db:  db,
		log: logger,
	}
}

// Generate 根据匹配的规则和事件字段生成告警并写入数据库
// hostID: 事件来源主机 ID
// matchedRules: CEL 引擎返回的命中规则列表
// fields: 事件原始字段（用于构建告警详情）
func (g *AlertGenerator) Generate(hostID string, matchedRules []model.DetectionRule, fields map[string]string) {
	for _, rule := range matchedRules {
		if err := g.createAlert(hostID, &rule, fields); err != nil {
			g.log.Error("创建 CEL 检测告警失败",
				zap.Uint("rule_id", rule.ID),
				zap.String("rule_name", rule.Name),
				zap.String("host_id", hostID),
				zap.Error(err),
			)
		}
	}
}

// createAlert 创建单条告警记录
func (g *AlertGenerator) createAlert(hostID string, rule *model.DetectionRule, fields map[string]string) error {
	// 构建告警详情 JSON
	detail, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("序列化告警详情失败: %w", err)
	}

	// 生成唯一 ResultID：cel-{ruleID}-{hostID}-{timestamp}
	resultID := fmt.Sprintf("cel-%d-%s-%d", rule.ID, hostID, time.Now().UnixNano())

	now := model.ToLocalTime(time.Now())

	alert := model.Alert{
		ResultID:    resultID,
		HostID:      hostID,
		RuleID:      fmt.Sprintf("cel-%d", rule.ID),
		Source:      model.AlertSourceRuntime,
		Severity:    rule.Severity,
		Category:    categorize(rule),
		Title:       rule.Name,
		Description: rule.Description,
		Actual:      string(detail),
		Status:      model.AlertStatusActive,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	if err := g.db.Create(&alert).Error; err != nil {
		return fmt.Errorf("写入 alerts 表失败: %w", err)
	}

	g.log.Info("CEL 检测告警生成",
		zap.Uint("rule_id", rule.ID),
		zap.String("rule_name", rule.Name),
		zap.String("host_id", hostID),
		zap.String("severity", rule.Severity),
	)

	// 异步发送运行时检测告警通知
	go func(a *model.Alert) {
		// 查询主机信息
		var host model.Host
		hostname, ip := "", ""
		if g.db.Select("hostname, ipv4").First(&host, "host_id = ?", a.HostID).Error == nil {
			hostname = host.Hostname
			if len(host.IPv4) > 0 {
				ip = host.IPv4[0]
			}
		}
		ns := biz.NewNotificationService(g.db, g.log)
		if err := ns.SendRuntimeAlertNotification(&biz.RuntimeAlertData{
			HostID:      a.HostID,
			Hostname:    hostname,
			IP:          ip,
			RuleName:    a.Title,
			Severity:    a.Severity,
			Category:    a.Category,
			Description: a.Description,
			DetectedAt:  a.FirstSeenAt.Time(),
		}); err != nil {
			g.log.Error("发送运行时检测告警通知失败", zap.Error(err))
		}
	}(&alert)

	return nil
}

// categorize 根据规则信息确定告警分类
func categorize(rule *model.DetectionRule) string {
	if rule.Category != "" {
		return rule.Category
	}
	// 有 MITRE ATT&CK ID 时标记为 MITRE 分类
	if rule.MitreID != "" {
		return "mitre:" + rule.MitreID
	}
	return "cel-detection"
}
