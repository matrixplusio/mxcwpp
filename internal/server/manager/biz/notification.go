// Package biz 提供业务逻辑层
package biz

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// NotificationService 通知服务
type NotificationService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewNotificationService 创建通知服务
func NewNotificationService(db *gorm.DB, logger *zap.Logger) *NotificationService {
	return &NotificationService{
		db:     db,
		logger: logger,
	}
}

// resolveFrontendURL 解析告警跳转链接的前端域名。
//
// 优先级：
//  1. system_configs.site_config.SiteDomain（全局，UI 设置→系统设置 "前端访问域名"）
//  2. notification.FrontendURL（每通知单独配置，UI 通知管理）— 兼容历史数据
//  3. ""（不展示"查看详情"按钮）
//
// 历史问题：旧代码只读 notification.FrontendURL，每通知都要单独输入域名；
// 用户在系统设置里填了域名但 Lark/钉钉/Webhook 仍走 IP（因 notification.frontend_url 空）。
// 现统一从全局 SiteDomain 取，notification.FrontendURL 仅作为 fallback。
func (s *NotificationService) resolveFrontendURL(notificationURL string) string {
	if domain := s.loadSiteDomain(); domain != "" {
		return strings.TrimSuffix(domain, "/")
	}
	return strings.TrimSuffix(notificationURL, "/")
}

// loadSiteDomain 从 system_configs.site_config 读 site_domain；失败返空（不阻塞通知发送）。
func (s *NotificationService) loadSiteDomain() string {
	if s.db == nil {
		return ""
	}
	var row systemConfigRow
	if err := s.db.Where("`key` = ? AND category = ?", "site_config", "site").Take(&row).Error; err != nil {
		return ""
	}
	var sc struct {
		SiteDomain string `json:"site_domain"`
	}
	if err := json.Unmarshal([]byte(row.Value), &sc); err != nil {
		return ""
	}
	return strings.TrimSpace(sc.SiteDomain)
}

// AlertData 告警数据（基线安全告警）
type AlertData struct {
	// 主机信息
	HostID       string
	Hostname     string
	IP           string
	OSFamily     string
	OSVersion    string
	BusinessLine string // 业务线

	// 规则信息
	RuleID        string
	RuleName      string
	Category      string
	Severity      string
	Title         string
	Description   string
	Actual        string
	Expected      string
	FixSuggestion string

	// 任务信息
	TaskID    string
	PolicyID  string
	CheckedAt time.Time

	// 前端地址（用于构建跳转链接）
	FrontendURL string
	ResultID    string // 结果ID，用于构建详情链接
}

// AgentOfflineData Agent 离线告警数据
type AgentOfflineData struct {
	HostID       string
	Hostname     string
	IP           string
	OSFamily     string
	OSVersion    string
	LastOnlineAt time.Time
	OfflineAt    time.Time
}

// AgentOnlineData Agent 上线恢复数据
type AgentOnlineData struct {
	HostID       string
	Hostname     string
	IP           string
	OSFamily     string
	OSVersion    string
	OnlineAt     time.Time
	OfflineSince time.Time // 上次离线时间
}

// AlertResolvedData 告警恢复数据
type AlertResolvedData struct {
	// 主机信息
	HostID    string
	Hostname  string
	IP        string
	OSFamily  string
	OSVersion string

	// 规则信息
	RuleID   string
	RuleName string
	Category string
	Severity string
	Title    string

	// 时间信息
	FirstSeenAt time.Time // 告警首次发现时间
	ResolvedAt  time.Time // 告警恢复时间

	// 前端地址
	FrontendURL string
	ResultID    string
}

// SendAlertNotification 发送告警通知（用于新告警）
// 注：此方法只在新告警创建时调用，已存在的告警由定期调度器处理
// 返回值：是否成功发送了至少一个通知，以及错误信息
func (s *NotificationService) SendAlertNotification(alertData *AlertData) (bool, error) {
	// 查询所有启用的、类别为 baseline_alert 的通知配置
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryBaselineAlert).Find(&notifications).Error; err != nil {
		s.logger.Error("查询通知配置失败", zap.Error(err))
		return false, err
	}

	// 过滤出配置了 severities 的通知
	var baselineNotifications []model.Notification
	for _, n := range notifications {
		if len(n.Severities) > 0 {
			baselineNotifications = append(baselineNotifications, n)
		}
	}

	if len(baselineNotifications) == 0 {
		s.logger.Debug("没有找到配置了告警等级的基线告警通知配置")
		return false, nil
	}

	// 过滤匹配的通知配置
	matchedNotifications := s.filterNotifications(baselineNotifications, alertData)

	if len(matchedNotifications) == 0 {
		s.logger.Debug("没有匹配的通知配置",
			zap.String("host_id", alertData.HostID),
			zap.String("severity", alertData.Severity),
		)
		return false, nil
	}

	// 发送通知
	sentCount := 0
	for _, notification := range matchedNotifications {
		if err := s.sendNotification(&notification, alertData); err != nil {
			s.logger.Error("发送通知失败",
				zap.Uint("notification_id", notification.ID),
				zap.String("type", string(notification.Type)),
				zap.Error(err),
			)
			// 继续发送其他通知，不中断
		} else {
			sentCount++
		}
	}

	return sentCount > 0, nil
}

// SendAlertNotificationForAlert 为指定告警发送通知（用于定期告警调度器）
// 返回是否成功发送通知
func (s *NotificationService) SendAlertNotificationForAlert(alert *model.Alert) (bool, error) {
	// 查询主机信息
	var host model.Host
	if err := s.db.First(&host, "host_id = ?", alert.HostID).Error; err != nil {
		return false, fmt.Errorf("查询主机信息失败: %w", err)
	}

	// 查询规则信息
	var rule model.Rule
	if err := s.db.First(&rule, "rule_id = ?", alert.RuleID).Error; err != nil {
		s.logger.Warn("查询规则信息失败", zap.String("rule_id", alert.RuleID), zap.Error(err))
	}

	// 获取主机 IP
	hostIP := ""
	if len(host.IPv4) > 0 {
		hostIP = strings.Join(host.IPv4, ",")
	}

	// 构建告警数据
	alertData := &AlertData{
		HostID:        alert.HostID,
		Hostname:      host.Hostname,
		IP:            hostIP,
		OSFamily:      host.OSFamily,
		OSVersion:     host.OSVersion,
		BusinessLine:  host.BusinessLine, // 添加业务线
		RuleID:        alert.RuleID,
		RuleName:      rule.Title,
		Category:      alert.Category,
		Severity:      alert.Severity,
		Title:         alert.Title,
		Description:   rule.Description,
		Actual:        alert.Actual,
		Expected:      alert.Expected,
		FixSuggestion: alert.FixSuggestion,
		PolicyID:      alert.PolicyID,
		CheckedAt:     alert.LastSeenAt.Time(),
		ResultID:      alert.ResultID,
	}

	// 查询所有启用的、配置了 severities 的通知配置（用于基线告警）
	var notifications []model.Notification
	if err := s.db.Where("enabled = ?", true).Find(&notifications).Error; err != nil {
		return false, fmt.Errorf("查询通知配置失败: %w", err)
	}

	// 过滤出配置了 severities 的通知
	var baselineNotifications []model.Notification
	for _, n := range notifications {
		if len(n.Severities) > 0 {
			baselineNotifications = append(baselineNotifications, n)
		}
	}

	if len(baselineNotifications) == 0 {
		return false, nil
	}

	// 过滤匹配的通知配置
	matchedNotifications := s.filterNotifications(baselineNotifications, alertData)

	sent := false
	for _, notification := range matchedNotifications {
		if err := s.sendNotification(&notification, alertData); err != nil {
			s.logger.Error("发送通知失败",
				zap.Uint("notification_id", notification.ID),
				zap.Error(err),
			)
		} else {
			sent = true
		}
	}

	return sent, nil
}

// filterNotifications 过滤匹配的通知配置
func (s *NotificationService) filterNotifications(
	notifications []model.Notification,
	alertData *AlertData,
) []model.Notification {
	var matched []model.Notification

	for _, notification := range notifications {
		// 检查通知等级
		if !s.matchSeverity(notification.Severities, alertData.Severity) {
			continue
		}

		// 检查主机范围
		if !s.matchScope(&notification, alertData) {
			continue
		}

		matched = append(matched, notification)
	}

	return matched
}

// matchSeverity 检查严重级别是否匹配
func (s *NotificationService) matchSeverity(notificationSeverities []string, alertSeverity string) bool {
	for _, sev := range notificationSeverities {
		if sev == alertSeverity {
			return true
		}
	}
	return false
}

// matchScope 检查主机范围是否匹配
func (s *NotificationService) matchScope(notification *model.Notification, alertData *AlertData) bool {
	switch notification.Scope {
	case model.NotificationScopeGlobal:
		return true

	case model.NotificationScopeHostTags:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		// TODO: 需要查询主机的标签，这里暂时返回 true
		return true

	case model.NotificationScopeBusinessLine:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		// 查询主机的业务线
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", alertData.HostID).Error; err != nil {
			return false
		}
		for _, bl := range scopeValue.BusinessLines {
			if host.BusinessLine == bl {
				return true
			}
		}
		return false

	case model.NotificationScopeSpecified:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		for _, hostID := range scopeValue.HostIDs {
			if hostID == alertData.HostID {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// sendNotification 发送单个通知
func (s *NotificationService) sendNotification(
	notification *model.Notification,
	alertData *AlertData,
) error {
	var message map[string]interface{}

	if notification.Type == model.NotificationTypeLark {
		// Lark 使用卡片消息
		message = s.buildLarkAlertCard(notification, alertData)
	} else {
		// Webhook 使用 JSON 格式
		message = s.buildWebhookAlert(alertData)
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	// 发送 HTTP 请求
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(notification.Config.WebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return fmt.Errorf("服务器返回状态码: %d，响应: %s", resp.StatusCode, bodyStr)
	}

	return nil
}

// BuildLarkAlertCardForTest 构建 Lark 告警卡片消息（用于测试，公开方法）
func (s *NotificationService) BuildLarkAlertCardForTest(
	notification *model.Notification,
	alertData *AlertData,
) map[string]interface{} {
	return s.buildLarkAlertCard(notification, alertData)
}

// buildLarkAlertCard 构建 Lark 告警卡片消息（参考 Elkeid 模板）
func (s *NotificationService) buildLarkAlertCard(
	notification *model.Notification,
	alertData *AlertData,
) map[string]interface{} {
	// 构建业务线显示文本
	businessLineText := alertData.BusinessLine
	if businessLineText == "" {
		businessLineText = "未设置"
	}

	// 构建告警描述（包含 IP 和业务线）
	description := fmt.Sprintf(
		"矩阵云安全平台检测到您的资产存在疑似【%s】基线风险，请及时处理。\n\n"+
			"**主机名称：** %s\n"+
			"**主机 IP：** %s\n"+
			"**业务线：** %s\n"+
			"**告警时间：** %s",
		alertData.RuleName,
		alertData.Hostname,
		alertData.IP,
		businessLineText,
		alertData.CheckedAt.Format("2006-01-02 15:04:05"),
	)

	// 构建原始数据（参考 Elkeid 格式）
	rawData := map[string]interface{}{
		"alert_type":     "基线安全告警",
		"hostname":       alertData.Hostname,
		"host_id":        alertData.HostID,
		"ip":             alertData.IP,
		"business_line":  alertData.BusinessLine,
		"os":             alertData.OSFamily + " " + alertData.OSVersion,
		"rule_id":        alertData.RuleID,
		"rule_name":      alertData.RuleName,
		"category":       alertData.Category,
		"severity":       alertData.Severity,
		"actual":         alertData.Actual,
		"expected":       alertData.Expected,
		"fix_suggestion": alertData.FixSuggestion,
		"time":           alertData.CheckedAt.Format(time.RFC3339),
	}

	// 构建原始数据文本（按固定顺序显示）
	rawDataLines := []string{
		fmt.Sprintf(`"alert_type": "%v"`, rawData["alert_type"]),
		fmt.Sprintf(`"hostname": "%v"`, rawData["hostname"]),
		fmt.Sprintf(`"host_id": "%v"`, rawData["host_id"]),
		fmt.Sprintf(`"ip": "%v"`, rawData["ip"]),
		fmt.Sprintf(`"business_line": "%v"`, rawData["business_line"]),
		fmt.Sprintf(`"os": "%v"`, rawData["os"]),
		fmt.Sprintf(`"rule_id": "%v"`, rawData["rule_id"]),
		fmt.Sprintf(`"rule_name": "%v"`, rawData["rule_name"]),
		fmt.Sprintf(`"category": "%v"`, rawData["category"]),
		fmt.Sprintf(`"severity": "%v"`, rawData["severity"]),
		fmt.Sprintf(`"actual": "%v"`, rawData["actual"]),
		fmt.Sprintf(`"expected": "%v"`, rawData["expected"]),
		fmt.Sprintf(`"fix_suggestion": "%v"`, rawData["fix_suggestion"]),
		fmt.Sprintf(`"time": "%v"`, rawData["time"]),
	}
	rawDataText := "原始数据如下:\n" + strings.Join(rawDataLines, "\n")

	// 构建跳转 URL：优先全局 site_domain，回退 notification.FrontendURL
	alertURL := ""
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		resultID := alertData.ResultID
		if resultID == "" {
			resultID = alertData.RuleID
		}
		alertURL = fmt.Sprintf("%s/alerts?result_id=%s", base, resultID)
	}

	// 构建卡片元素
	elements := []map[string]interface{}{
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": description,
			},
		},
		{
			"tag": "hr",
		},
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": rawDataText,
			},
		},
	}

	// 如果有前端地址，添加跳转按钮
	if alertURL != "" {
		elements = append(elements, map[string]interface{}{
			"tag": "action",
			"actions": []map[string]interface{}{
				{
					"tag": "button",
					"text": map[string]interface{}{
						"tag":     "plain_text",
						"content": "查看详情",
					},
					"type": "primary",
					"multi_url": map[string]interface{}{
						"url":         alertURL,
						"android_url": alertURL,
						"ios_url":     alertURL,
						"pc_url":      alertURL,
					},
				},
			},
		})
	}

	// 构建卡片消息
	card := map[string]interface{}{
		"config": map[string]interface{}{
			"wide_screen_mode": true,
		},
		"header": map[string]interface{}{
			"title": map[string]interface{}{
				"tag":     "plain_text",
				"content": "矩阵云安全平台告警通知",
			},
			"template": s.getSeverityTemplate(alertData.Severity), // 根据严重级别选择模板颜色
		},
		"elements": elements,
	}

	message := map[string]interface{}{
		"msg_type": "interactive",
		"card":     card,
	}

	// Lark 需要签名
	if notification.Config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := s.generateLarkSign(notification.Config.Secret, timestamp)
		if err == nil {
			message["timestamp"] = timestamp
			message["sign"] = sign
		}
	}

	return message
}

// buildWebhookAlert 构建 Webhook 告警消息
func (s *NotificationService) buildWebhookAlert(alertData *AlertData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":     "baseline_risk",
		"status":         "firing", // firing 或 resolved
		"host_id":        alertData.HostID,
		"hostname":       alertData.Hostname,
		"ip":             alertData.IP,
		"business_line":  alertData.BusinessLine, // 业务线
		"os_family":      alertData.OSFamily,
		"os_version":     alertData.OSVersion,
		"rule_id":        alertData.RuleID,
		"rule_name":      alertData.RuleName,
		"category":       alertData.Category,
		"severity":       alertData.Severity,
		"title":          alertData.Title,
		"actual":         alertData.Actual,
		"expected":       alertData.Expected,
		"fix_suggestion": alertData.FixSuggestion,
		"checked_at":     alertData.CheckedAt.Format(time.RFC3339),
		"url":            alertData.FrontendURL,
	}
}

// getSeverityTemplate 根据严重级别获取模板颜色
func (s *NotificationService) getSeverityTemplate(severity string) string {
	switch severity {
	case "critical":
		return "red" // 红色
	case "high":
		return "orange" // 橙色
	case "medium":
		return "blue" // 蓝色
	case "low":
		return "grey" // 灰色
	default:
		return "blue"
	}
}

// generateLarkSign 生成 Lark Webhook 签名
func (s *NotificationService) generateLarkSign(secret, timestamp string) (string, error) {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(stringToSign))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// SendAlertResolvedNotification 发送告警恢复通知
func (s *NotificationService) SendAlertResolvedNotification(resolvedData *AlertResolvedData) error {
	// 查询所有启用的、配置了 severities 的通知配置（用于基线告警）
	var notifications []model.Notification
	if err := s.db.Where("enabled = ?", true).Find(&notifications).Error; err != nil {
		s.logger.Error("查询通知配置失败", zap.Error(err))
		return err
	}

	// 过滤出配置了 severities 的通知
	var baselineNotifications []model.Notification
	for _, n := range notifications {
		if len(n.Severities) > 0 {
			baselineNotifications = append(baselineNotifications, n)
		}
	}

	if len(baselineNotifications) == 0 {
		s.logger.Debug("没有找到配置了告警等级的通知配置")
		return nil
	}

	// 过滤匹配的通知配置
	matchedNotifications := s.filterResolvedNotifications(baselineNotifications, resolvedData)

	// 发送通知
	for _, notification := range matchedNotifications {
		if err := s.sendResolvedNotification(&notification, resolvedData); err != nil {
			s.logger.Error("发送告警恢复通知失败",
				zap.Uint("notification_id", notification.ID),
				zap.String("type", string(notification.Type)),
				zap.Error(err),
			)
		}
	}

	return nil
}

// filterResolvedNotifications 过滤匹配的恢复通知配置
func (s *NotificationService) filterResolvedNotifications(
	notifications []model.Notification,
	resolvedData *AlertResolvedData,
) []model.Notification {
	var matched []model.Notification

	for _, notification := range notifications {
		// 检查严重级别是否匹配
		if !s.matchSeverity(notification.Severities, resolvedData.Severity) {
			continue
		}

		// 检查主机范围
		alertData := &AlertData{HostID: resolvedData.HostID}
		if !s.matchScope(&notification, alertData) {
			continue
		}

		matched = append(matched, notification)
	}

	return matched
}

// sendResolvedNotification 发送单个告警恢复通知
func (s *NotificationService) sendResolvedNotification(
	notification *model.Notification,
	resolvedData *AlertResolvedData,
) error {
	var message map[string]interface{}

	if notification.Type == model.NotificationTypeLark {
		message = s.buildLarkResolvedCard(notification, resolvedData)
	} else {
		message = s.buildWebhookResolved(resolvedData)
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(notification.Config.WebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return fmt.Errorf("服务器返回状态码: %d，响应: %s", resp.StatusCode, bodyStr)
	}

	s.logger.Info("告警恢复通知发送成功",
		zap.String("host_id", resolvedData.HostID),
		zap.String("rule_id", resolvedData.RuleID),
	)

	return nil
}

// buildLarkResolvedCard 构建 Lark 告警恢复卡片消息
func (s *NotificationService) buildLarkResolvedCard(
	notification *model.Notification,
	resolvedData *AlertResolvedData,
) map[string]interface{} {
	// 计算持续时间
	duration := resolvedData.ResolvedAt.Sub(resolvedData.FirstSeenAt)
	durationStr := formatDuration(duration)

	// 构建恢复描述
	description := fmt.Sprintf(
		"✅ **告警已恢复**\n\n"+
			"矩阵云安全平台检测到您的资产【%s】的基线风险已修复。\n\n"+
			"**规则名称：** %s\n"+
			"**风险等级：** %s\n"+
			"**首次发现：** %s\n"+
			"**恢复时间：** %s\n"+
			"**持续时长：** %s",
		resolvedData.Hostname,
		resolvedData.RuleName,
		getSeverityLabel(resolvedData.Severity),
		resolvedData.FirstSeenAt.Format("2006-01-02 15:04:05"),
		resolvedData.ResolvedAt.Format("2006-01-02 15:04:05"),
		durationStr,
	)

	// 构建卡片元素
	elements := []map[string]interface{}{
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": description,
			},
		},
	}

	// 构建卡片消息
	card := map[string]interface{}{
		"config": map[string]interface{}{
			"wide_screen_mode": true,
		},
		"header": map[string]interface{}{
			"title": map[string]interface{}{
				"tag":     "plain_text",
				"content": "✅ 基线告警恢复通知",
			},
			"template": "green", // 绿色表示恢复
		},
		"elements": elements,
	}

	message := map[string]interface{}{
		"msg_type": "interactive",
		"card":     card,
	}

	// Lark 需要签名
	if notification.Config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := s.generateLarkSign(notification.Config.Secret, timestamp)
		if err == nil {
			message["timestamp"] = timestamp
			message["sign"] = sign
		}
	}

	return message
}

// buildWebhookResolved 构建 Webhook 告警恢复消息
func (s *NotificationService) buildWebhookResolved(resolvedData *AlertResolvedData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":    "baseline_risk",
		"status":        "resolved",
		"host_id":       resolvedData.HostID,
		"hostname":      resolvedData.Hostname,
		"ip":            resolvedData.IP,
		"os_family":     resolvedData.OSFamily,
		"os_version":    resolvedData.OSVersion,
		"rule_id":       resolvedData.RuleID,
		"rule_name":     resolvedData.RuleName,
		"category":      resolvedData.Category,
		"severity":      resolvedData.Severity,
		"title":         resolvedData.Title,
		"first_seen_at": resolvedData.FirstSeenAt.Format(time.RFC3339),
		"resolved_at":   resolvedData.ResolvedAt.Format(time.RFC3339),
	}
}

// formatDuration 格式化持续时间
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d分钟", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%d天%d小时", days, hours)
}

// getSeverityLabel 获取严重级别标签
func getSeverityLabel(severity string) string {
	switch severity {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return severity
	}
}

// SendAgentOfflineNotification 发送 Agent 离线通知
func (s *NotificationService) SendAgentOfflineNotification(offlineData *AgentOfflineData) error {
	// 查询所有启用的、类别为 agent_offline 的通知配置
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryAgentOffline).Find(&notifications).Error; err != nil {
		s.logger.Error("查询通知配置失败", zap.Error(err))
		return err
	}

	if len(notifications) == 0 {
		s.logger.Debug("没有找到启用的 Agent 离线通知配置")
		return nil
	}

	// 过滤匹配的通知配置（检查主机范围）
	matchedNotifications := s.filterAgentOfflineNotifications(notifications, offlineData)

	// 发送通知
	for _, notification := range matchedNotifications {
		if err := s.sendAgentOfflineNotification(&notification, offlineData); err != nil {
			s.logger.Error("发送 Agent 离线通知失败",
				zap.Uint("notification_id", notification.ID),
				zap.String("type", string(notification.Type)),
				zap.Error(err),
			)
			// 继续发送其他通知，不中断
		}
	}

	return nil
}

// filterAgentOfflineNotifications 过滤匹配的 Agent 离线通知配置
func (s *NotificationService) filterAgentOfflineNotifications(
	notifications []model.Notification,
	offlineData *AgentOfflineData,
) []model.Notification {
	var matched []model.Notification

	for _, notification := range notifications {
		// 检查主机范围（Agent 离线通知不检查严重级别）
		if !s.matchAgentOfflineScope(&notification, offlineData) {
			continue
		}

		matched = append(matched, notification)
	}

	return matched
}

// matchAgentOfflineScope 检查主机范围是否匹配（Agent 离线场景）
func (s *NotificationService) matchAgentOfflineScope(notification *model.Notification, offlineData *AgentOfflineData) bool {
	switch notification.Scope {
	case model.NotificationScopeGlobal:
		return true

	case model.NotificationScopeHostTags:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		// TODO: 需要查询主机的标签，这里暂时返回 true
		return true

	case model.NotificationScopeBusinessLine:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		// 查询主机的业务线
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", offlineData.HostID).Error; err != nil {
			return false
		}
		for _, bl := range scopeValue.BusinessLines {
			if host.BusinessLine == bl {
				return true
			}
		}
		return false

	case model.NotificationScopeSpecified:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		for _, hostID := range scopeValue.HostIDs {
			if hostID == offlineData.HostID {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// sendAgentOfflineNotification 发送单个 Agent 离线通知
func (s *NotificationService) sendAgentOfflineNotification(
	notification *model.Notification,
	offlineData *AgentOfflineData,
) error {
	var message map[string]interface{}

	if notification.Type == model.NotificationTypeLark {
		// Lark 使用卡片消息
		message = s.buildLarkAgentOfflineCard(notification, offlineData)
	} else {
		// Webhook 使用 JSON 格式
		message = s.buildWebhookAgentOffline(offlineData)
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	// 发送 HTTP 请求
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(notification.Config.WebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return fmt.Errorf("服务器返回状态码: %d，响应: %s", resp.StatusCode, bodyStr)
	}

	s.logger.Info("Agent 离线通知发送成功",
		zap.String("host_id", offlineData.HostID),
		zap.String("hostname", offlineData.Hostname),
	)

	return nil
}

// buildLarkAgentOfflineCard 构建 Lark Agent 离线卡片消息
func (s *NotificationService) buildLarkAgentOfflineCard(
	notification *model.Notification,
	offlineData *AgentOfflineData,
) map[string]interface{} {
	// 构建告警描述
	description := fmt.Sprintf(
		"矩阵云安全平台检测到您的主机 Agent 已离线。\n\n"+
			"**主机名称：** %s\n"+
			"**主机 IP：** %s\n"+
			"**操作系统：** %s %s\n"+
			"**离线时间：** %s\n\n"+
			"请及时检查主机网络连接或 Agent 服务状态。",
		offlineData.Hostname,
		offlineData.IP,
		offlineData.OSFamily,
		offlineData.OSVersion,
		offlineData.OfflineAt.Format("2006-01-02 15:04:05"),
	)

	// 构建跳转 URL：优先全局 site_domain
	hostURL := ""
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		hostURL = fmt.Sprintf("%s/assets/hosts?host_id=%s", base, offlineData.HostID)
	}

	// 构建卡片元素
	elements := []map[string]interface{}{
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": description,
			},
		},
	}

	// 如果有前端地址，添加跳转按钮
	if hostURL != "" {
		elements = append(elements, map[string]interface{}{
			"tag": "hr",
		})
		elements = append(elements, map[string]interface{}{
			"tag": "action",
			"actions": []map[string]interface{}{
				{
					"tag": "button",
					"text": map[string]interface{}{
						"tag":     "plain_text",
						"content": "查看主机详情",
					},
					"type": "primary",
					"multi_url": map[string]interface{}{
						"url":         hostURL,
						"android_url": hostURL,
						"ios_url":     hostURL,
						"pc_url":      hostURL,
					},
				},
			},
		})
	}

	// 构建卡片消息
	card := map[string]interface{}{
		"config": map[string]interface{}{
			"wide_screen_mode": true,
		},
		"header": map[string]interface{}{
			"title": map[string]interface{}{
				"tag":     "plain_text",
				"content": "⚠️ Agent 离线告警",
			},
			"template": "orange", // 橙色警告
		},
		"elements": elements,
	}

	message := map[string]interface{}{
		"msg_type": "interactive",
		"card":     card,
	}

	// Lark 需要签名
	if notification.Config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := s.generateLarkSign(notification.Config.Secret, timestamp)
		if err == nil {
			message["timestamp"] = timestamp
			message["sign"] = sign
		}
	}

	return message
}

// buildWebhookAgentOffline 构建 Webhook Agent 离线消息
func (s *NotificationService) buildWebhookAgentOffline(offlineData *AgentOfflineData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":     "agent_offline",
		"host_id":        offlineData.HostID,
		"hostname":       offlineData.Hostname,
		"ip":             offlineData.IP,
		"os_family":      offlineData.OSFamily,
		"os_version":     offlineData.OSVersion,
		"last_online_at": offlineData.LastOnlineAt.Format(time.RFC3339),
		"offline_at":     offlineData.OfflineAt.Format(time.RFC3339),
	}
}

// SendAgentOnlineNotification 发送 Agent 上线恢复通知
func (s *NotificationService) SendAgentOnlineNotification(onlineData *AgentOnlineData) error {
	// 查询所有启用的、类别为 agent_offline 的通知配置
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryAgentOffline).Find(&notifications).Error; err != nil {
		s.logger.Error("查询通知配置失败", zap.Error(err))
		return err
	}

	if len(notifications) == 0 {
		s.logger.Debug("没有找到启用的 Agent 离线通知配置，跳过上线恢复通知")
		return nil
	}

	// 过滤匹配的通知配置（检查主机范围）
	matchedNotifications := s.filterAgentOnlineNotifications(notifications, onlineData)

	// 发送通知
	for _, notification := range matchedNotifications {
		if err := s.sendAgentOnlineNotification(&notification, onlineData); err != nil {
			s.logger.Error("发送 Agent 上线恢复通知失败",
				zap.Uint("notification_id", notification.ID),
				zap.String("type", string(notification.Type)),
				zap.Error(err),
			)
			// 继续发送其他通知，不中断
		}
	}

	return nil
}

// filterAgentOnlineNotifications 过滤匹配的 Agent 上线恢复通知配置
func (s *NotificationService) filterAgentOnlineNotifications(
	notifications []model.Notification,
	onlineData *AgentOnlineData,
) []model.Notification {
	var matched []model.Notification

	for _, notification := range notifications {
		// 检查主机范围
		if !s.matchAgentOnlineScope(&notification, onlineData) {
			continue
		}

		matched = append(matched, notification)
	}

	return matched
}

// matchAgentOnlineScope 检查主机范围是否匹配（Agent 上线场景）
func (s *NotificationService) matchAgentOnlineScope(notification *model.Notification, onlineData *AgentOnlineData) bool {
	switch notification.Scope {
	case model.NotificationScopeGlobal:
		return true

	case model.NotificationScopeBusinessLine:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		// 需要查询主机的业务线
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", onlineData.HostID).Error; err != nil {
			return false
		}
		for _, bl := range scopeValue.BusinessLines {
			if bl == host.BusinessLine {
				return true
			}
		}
		return false

	case model.NotificationScopeHostTags:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		// 需要查询主机的标签
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", onlineData.HostID).Error; err != nil {
			return false
		}
		for _, tag := range scopeValue.Tags {
			for _, hostTag := range host.Tags {
				if tag == hostTag {
					return true
				}
			}
		}
		return false

	case model.NotificationScopeSpecified:
		// 解析 scope_value
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		for _, hostID := range scopeValue.HostIDs {
			if hostID == onlineData.HostID {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// sendAgentOnlineNotification 发送单个 Agent 上线恢复通知
func (s *NotificationService) sendAgentOnlineNotification(
	notification *model.Notification,
	onlineData *AgentOnlineData,
) error {
	var message map[string]interface{}

	switch notification.Type {
	case model.NotificationTypeLark:
		message = s.buildLarkAgentOnlineCard(notification, onlineData)
	case model.NotificationTypeWebhook:
		message = s.buildWebhookAgentOnline(onlineData)
	default:
		return fmt.Errorf("不支持的通知类型: %s", notification.Type)
	}

	// 发送 HTTP 请求
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %w", err)
	}

	resp, err := http.Post(notification.Config.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return fmt.Errorf("服务器返回状态码: %d，响应: %s", resp.StatusCode, bodyStr)
	}

	s.logger.Info("Agent 上线恢复通知发送成功",
		zap.String("host_id", onlineData.HostID),
		zap.String("hostname", onlineData.Hostname),
	)

	return nil
}

// buildLarkAgentOnlineCard 构建 Lark Agent 上线恢复卡片消息
func (s *NotificationService) buildLarkAgentOnlineCard(
	notification *model.Notification,
	onlineData *AgentOnlineData,
) map[string]interface{} {
	// 计算离线时长
	offlineDuration := onlineData.OnlineAt.Sub(onlineData.OfflineSince)
	durationStr := formatDuration(offlineDuration)

	// 构建告警描述
	description := fmt.Sprintf(
		"矩阵云安全平台检测到您的主机 Agent 已恢复上线。\n\n"+
			"**主机名称：** %s\n"+
			"**主机 IP：** %s\n"+
			"**操作系统：** %s %s\n"+
			"**上线时间：** %s\n"+
			"**离线时长：** %s",
		onlineData.Hostname,
		onlineData.IP,
		onlineData.OSFamily,
		onlineData.OSVersion,
		onlineData.OnlineAt.Format("2006-01-02 15:04:05"),
		durationStr,
	)

	elements := []map[string]interface{}{
		{
			"tag": "div",
			"text": map[string]interface{}{
				"tag":     "lark_md",
				"content": description,
			},
		},
		{
			"tag": "hr",
		},
	}

	// 添加查看详情按钮：优先全局 site_domain
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		elements = append(elements, map[string]interface{}{
			"tag": "action",
			"actions": []map[string]interface{}{
				{
					"tag": "button",
					"text": map[string]interface{}{
						"tag":     "plain_text",
						"content": "查看主机详情",
					},
					"type": "primary",
					"url":  fmt.Sprintf("%s/hosts/%s", base, onlineData.HostID),
				},
			},
		})
	}

	card := map[string]interface{}{
		"config": map[string]interface{}{
			"wide_screen_mode": true,
		},
		"header": map[string]interface{}{
			"title": map[string]interface{}{
				"tag":     "plain_text",
				"content": "✅ Agent 恢复上线",
			},
			"template": "green", // 绿色表示恢复
		},
		"elements": elements,
	}

	message := map[string]interface{}{
		"msg_type": "interactive",
		"card":     card,
	}

	// Lark 需要签名
	if notification.Config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := s.generateLarkSign(notification.Config.Secret, timestamp)
		if err == nil {
			message["timestamp"] = timestamp
			message["sign"] = sign
		}
	}

	return message
}

// buildWebhookAgentOnline 构建 Webhook Agent 上线恢复消息
func (s *NotificationService) buildWebhookAgentOnline(onlineData *AgentOnlineData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":    "agent_online",
		"host_id":       onlineData.HostID,
		"hostname":      onlineData.Hostname,
		"ip":            onlineData.IP,
		"os_family":     onlineData.OSFamily,
		"os_version":    onlineData.OSVersion,
		"online_at":     onlineData.OnlineAt.Format(time.RFC3339),
		"offline_since": onlineData.OfflineSince.Format(time.RFC3339),
	}
}

// ============================================================
// 通用辅助方法
// ============================================================

// matchScopeByHostID 根据主机ID匹配主机范围（通用版，不依赖 AlertData）
func (s *NotificationService) matchScopeByHostID(notification *model.Notification, hostID string) bool {
	switch notification.Scope {
	case model.NotificationScopeGlobal:
		return true
	case model.NotificationScopeHostTags:
		return true // TODO: 标签匹配
	case model.NotificationScopeBusinessLine:
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", hostID).Error; err != nil {
			return false
		}
		for _, bl := range scopeValue.BusinessLines {
			if host.BusinessLine == bl {
				return true
			}
		}
		return false
	case model.NotificationScopeSpecified:
		var scopeValue model.ScopeValueData
		if err := json.Unmarshal([]byte(notification.ScopeValue), &scopeValue); err != nil {
			return false
		}
		for _, hid := range scopeValue.HostIDs {
			if hid == hostID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// postWebhook 发送 Webhook POST 请求（通用）
func (s *NotificationService) postWebhook(webhookURL string, message map[string]interface{}) error {
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return fmt.Errorf("服务器返回状态码: %d，响应: %s", resp.StatusCode, bodyStr)
	}
	return nil
}

// buildLarkCardMessage 构建 Lark 卡片消息框架（通用）
func (s *NotificationService) buildLarkCardMessage(
	notification *model.Notification,
	title, template string,
	elements []map[string]interface{},
) map[string]interface{} {
	card := map[string]interface{}{
		"config": map[string]interface{}{"wide_screen_mode": true},
		"header": map[string]interface{}{
			"title":    map[string]interface{}{"tag": "plain_text", "content": title},
			"template": template,
		},
		"elements": elements,
	}
	message := map[string]interface{}{"msg_type": "interactive", "card": card}
	if notification.Config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := s.generateLarkSign(notification.Config.Secret, timestamp)
		if err == nil {
			message["timestamp"] = timestamp
			message["sign"] = sign
		}
	}
	return message
}

// larkActionButton 构建 Lark 跳转按钮元素
func larkActionButton(text, url string) map[string]interface{} {
	return map[string]interface{}{
		"tag": "action",
		"actions": []map[string]interface{}{
			{
				"tag":  "button",
				"text": map[string]interface{}{"tag": "plain_text", "content": text},
				"type": "primary",
				"multi_url": map[string]interface{}{
					"url": url, "android_url": url, "ios_url": url, "pc_url": url,
				},
			},
		},
	}
}

// larkTextDiv 构建 Lark lark_md 文本 div
func larkTextDiv(content string) map[string]interface{} {
	return map[string]interface{}{
		"tag":  "div",
		"text": map[string]interface{}{"tag": "lark_md", "content": content},
	}
}

// larkHR 分割线
func larkHR() map[string]interface{} {
	return map[string]interface{}{"tag": "hr"}
}

// ============================================================
// 病毒查杀告警通知
// ============================================================

// VirusAlertData 病毒告警数据
type VirusAlertData struct {
	HostID      string
	Hostname    string
	IP          string
	FilePath    string
	ThreatName  string
	ThreatType  string // virus, trojan, worm, ransomware, rootkit, miner, backdoor
	Severity    string
	FileHash    string
	Action      string // detected, quarantined, deleted
	DetectedAt  time.Time
	FrontendURL string
}

// SendVirusAlertNotification 发送病毒告警通知
func (s *NotificationService) SendVirusAlertNotification(data *VirusAlertData) error {
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryVirusAlert).Find(&notifications).Error; err != nil {
		return err
	}
	for _, n := range notifications {
		if len(n.Severities) > 0 && !s.matchSeverity(n.Severities, data.Severity) {
			continue
		}
		if !s.matchScopeByHostID(&n, data.HostID) {
			continue
		}
		var msg map[string]interface{}
		if n.Type == model.NotificationTypeLark {
			msg = s.buildLarkVirusCard(&n, data)
		} else {
			msg = s.buildWebhookVirus(data)
		}
		if err := s.postWebhook(n.Config.WebhookURL, msg); err != nil {
			s.logger.Error("发送病毒告警通知失败", zap.Uint("notification_id", n.ID), zap.Error(err))
		}
	}
	return nil
}

// threatTypeText 威胁类型中文
func threatTypeText(t string) string {
	m := map[string]string{
		"virus": "病毒", "trojan": "木马", "worm": "蠕虫", "ransomware": "勒索软件",
		"rootkit": "Rootkit", "miner": "挖矿程序", "backdoor": "后门", "other": "其他威胁",
	}
	if v, ok := m[t]; ok {
		return v
	}
	return t
}

func (s *NotificationService) buildLarkVirusCard(notification *model.Notification, data *VirusAlertData) map[string]interface{} {
	desc := fmt.Sprintf(
		"矩阵云安全平台在您的主机上检测到恶意文件，请及时处理。\n\n"+
			"**威胁名称：** %s\n"+
			"**威胁类型：** %s\n"+
			"**主机名称：** %s\n"+
			"**主机 IP：** %s\n"+
			"**文件路径：** %s\n"+
			"**文件哈希：** %s\n"+
			"**处置状态：** %s\n"+
			"**检测时间：** %s",
		data.ThreatName, threatTypeText(data.ThreatType),
		data.Hostname, data.IP, data.FilePath, data.FileHash,
		data.Action, data.DetectedAt.Format("2006-01-02 15:04:05"),
	)
	elements := []map[string]interface{}{larkTextDiv(desc)}
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		url := fmt.Sprintf("%s/virus/scan", base)
		elements = append(elements, larkHR(), larkActionButton("查看详情", url))
	}
	return s.buildLarkCardMessage(notification, "🦠 病毒查杀告警", s.getSeverityTemplate(data.Severity), elements)
}

func (s *NotificationService) buildWebhookVirus(data *VirusAlertData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":  "virus",
		"host_id":     data.HostID,
		"hostname":    data.Hostname,
		"ip":          data.IP,
		"file_path":   data.FilePath,
		"threat_name": data.ThreatName,
		"threat_type": data.ThreatType,
		"severity":    data.Severity,
		"file_hash":   data.FileHash,
		"action":      data.Action,
		"detected_at": data.DetectedAt.Format(time.RFC3339),
	}
}

// ============================================================
// 文件完整性告警通知
// ============================================================

// FIMAlertData 文件完整性告警数据
type FIMAlertData struct {
	HostID      string
	Hostname    string
	IP          string
	FilePath    string
	ChangeType  string // added, removed, changed
	Category    string // binary, config, auth, log
	Severity    string
	DetectedAt  time.Time
	FrontendURL string
}

// SendFIMAlertNotification 发送文件完整性告警通知
func (s *NotificationService) SendFIMAlertNotification(data *FIMAlertData) error {
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryFIMAlert).Find(&notifications).Error; err != nil {
		return err
	}
	for _, n := range notifications {
		if len(n.Severities) > 0 && !s.matchSeverity(n.Severities, data.Severity) {
			continue
		}
		if !s.matchScopeByHostID(&n, data.HostID) {
			continue
		}
		var msg map[string]interface{}
		if n.Type == model.NotificationTypeLark {
			msg = s.buildLarkFIMCard(&n, data)
		} else {
			msg = s.buildWebhookFIM(data)
		}
		if err := s.postWebhook(n.Config.WebhookURL, msg); err != nil {
			s.logger.Error("发送 FIM 告警通知失败", zap.Uint("notification_id", n.ID), zap.Error(err))
		}
	}
	return nil
}

// changeTypeText 变更类型中文
func changeTypeText(t string) string {
	m := map[string]string{"added": "新增", "removed": "删除", "changed": "变更"}
	if v, ok := m[t]; ok {
		return v
	}
	return t
}

// fimCategoryText 文件类别中文
func fimCategoryText(c string) string {
	m := map[string]string{"binary": "二进制文件", "config": "配置文件", "auth": "认证文件", "log": "日志文件", "other": "其他"}
	if v, ok := m[c]; ok {
		return v
	}
	return c
}

func (s *NotificationService) buildLarkFIMCard(notification *model.Notification, data *FIMAlertData) map[string]interface{} {
	desc := fmt.Sprintf(
		"矩阵云安全平台检测到关键文件变更，请确认是否为合法操作。\n\n"+
			"**主机名称：** %s\n"+
			"**主机 IP：** %s\n"+
			"**文件路径：** %s\n"+
			"**变更类型：** %s\n"+
			"**文件类别：** %s\n"+
			"**检测时间：** %s",
		data.Hostname, data.IP, data.FilePath,
		changeTypeText(data.ChangeType), fimCategoryText(data.Category),
		data.DetectedAt.Format("2006-01-02 15:04:05"),
	)
	elements := []map[string]interface{}{larkTextDiv(desc)}
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		url := fmt.Sprintf("%s/fim?host_id=%s", base, data.HostID)
		elements = append(elements, larkHR(), larkActionButton("查看详情", url))
	}
	return s.buildLarkCardMessage(notification, "📁 文件完整性告警", s.getSeverityTemplate(data.Severity), elements)
}

func (s *NotificationService) buildWebhookFIM(data *FIMAlertData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":  "fim",
		"host_id":     data.HostID,
		"hostname":    data.Hostname,
		"ip":          data.IP,
		"file_path":   data.FilePath,
		"change_type": data.ChangeType,
		"category":    data.Category,
		"severity":    data.Severity,
		"detected_at": data.DetectedAt.Format(time.RFC3339),
	}
}

// ============================================================
// CEL 规则检测告警通知
// ============================================================

// DetectionAlertData 检测告警数据
type DetectionAlertData struct {
	HostID      string
	Hostname    string
	IP          string
	RuleName    string
	Severity    string
	Category    string
	MitreID     string
	Description string
	DetectedAt  time.Time
	FrontendURL string
}

// SendDetectionAlertNotification 发送检测告警通知
func (s *NotificationService) SendDetectionAlertNotification(data *DetectionAlertData) error {
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryDetection).Find(&notifications).Error; err != nil {
		return err
	}
	for _, n := range notifications {
		if len(n.Severities) > 0 && !s.matchSeverity(n.Severities, data.Severity) {
			continue
		}
		if !s.matchScopeByHostID(&n, data.HostID) {
			continue
		}
		var msg map[string]interface{}
		if n.Type == model.NotificationTypeLark {
			msg = s.buildLarkDetectionCard(&n, data)
		} else {
			msg = s.buildWebhookDetection(data)
		}
		if err := s.postWebhook(n.Config.WebhookURL, msg); err != nil {
			s.logger.Error("发送检测告警通知失败", zap.Uint("notification_id", n.ID), zap.Error(err))
		}
	}
	return nil
}

func (s *NotificationService) buildLarkDetectionCard(notification *model.Notification, data *DetectionAlertData) map[string]interface{} {
	mitreInfo := ""
	if data.MitreID != "" {
		mitreInfo = fmt.Sprintf("\n**MITRE ATT&CK：** %s", data.MitreID)
	}
	desc := fmt.Sprintf(
		"矩阵云安全平台检测引擎触发安全告警。\n\n"+
			"**规则名称：** %s\n"+
			"**告警分类：** %s%s\n"+
			"**主机名称：** %s\n"+
			"**主机 IP：** %s\n"+
			"**检测时间：** %s",
		data.RuleName, data.Category, mitreInfo,
		data.Hostname, data.IP,
		data.DetectedAt.Format("2006-01-02 15:04:05"),
	)
	elements := []map[string]interface{}{larkTextDiv(desc)}
	if data.Description != "" {
		elements = append(elements, larkHR(), larkTextDiv("**规则说明：**\n"+data.Description))
	}
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		url := fmt.Sprintf("%s/detection/alerts?host_id=%s", base, data.HostID)
		elements = append(elements, larkHR(), larkActionButton("查看详情", url))
	}
	return s.buildLarkCardMessage(notification, "🛡️ 检测告警", s.getSeverityTemplate(data.Severity), elements)
}

func (s *NotificationService) buildWebhookDetection(data *DetectionAlertData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":  "detection",
		"host_id":     data.HostID,
		"hostname":    data.Hostname,
		"ip":          data.IP,
		"rule_name":   data.RuleName,
		"severity":    data.Severity,
		"category":    data.Category,
		"mitre_id":    data.MitreID,
		"description": data.Description,
		"detected_at": data.DetectedAt.Format(time.RFC3339),
	}
}

// ============================================================
// K8s 安全告警通知
// ============================================================

// KubeAlertData K8s 安全告警数据
type KubeAlertData struct {
	ClusterName string
	Severity    string
	AlarmType   string // container_escape, abnormal_process, privilege_escalation, reverse_shell
	Title       string // [K8S-001] kubectl exec 进入容器
	Description string
	Message     string // 可读的告警摘要
	Namespace   string
	Target      string
	FrontendURL string
}

// alarmTypeText K8s 告警类型中文
func alarmTypeText(t string) string {
	m := map[string]string{
		"container_escape":     "容器逃逸",
		"abnormal_process":     "异常进程",
		"abnormal_network":     "异常网络",
		"file_tamper":          "文件篡改",
		"privilege_escalation": "权限提升",
		"reverse_shell":        "反弹 Shell",
		"crypto_mining":        "挖矿行为",
	}
	if v, ok := m[t]; ok {
		return v
	}
	return t
}

// SendKubeAlertNotification 发送 K8s 安全告警通知
func (s *NotificationService) SendKubeAlertNotification(data *KubeAlertData) error {
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryKubeAlert).Find(&notifications).Error; err != nil {
		return err
	}
	for _, n := range notifications {
		if len(n.Severities) > 0 && !s.matchSeverity(n.Severities, data.Severity) {
			continue
		}
		// K8s 告警不按主机维度过滤，只检查 scope=global
		// 如果将来有多集群可以按集群名过滤
		var msg map[string]interface{}
		if n.Type == model.NotificationTypeLark {
			msg = s.buildLarkKubeCard(&n, data)
		} else {
			msg = s.buildWebhookKube(data)
		}
		if err := s.postWebhook(n.Config.WebhookURL, msg); err != nil {
			s.logger.Error("发送 K8s 告警通知失败", zap.Uint("notification_id", n.ID), zap.Error(err))
		}
	}
	return nil
}

func (s *NotificationService) buildLarkKubeCard(notification *model.Notification, data *KubeAlertData) map[string]interface{} {
	nsInfo := ""
	if data.Namespace != "" {
		nsInfo = fmt.Sprintf("\n**Namespace：** %s", data.Namespace)
	}
	targetInfo := ""
	if data.Target != "" {
		targetInfo = fmt.Sprintf("\n**影响对象：** %s", data.Target)
	}
	desc := fmt.Sprintf(
		"矩阵云安全平台 K8s 审计检测引擎触发安全告警。\n\n"+
			"**告警标题：** %s\n"+
			"**告警类型：** %s\n"+
			"**集群：** %s%s%s",
		data.Title, alarmTypeText(data.AlarmType),
		data.ClusterName, nsInfo, targetInfo,
	)
	elements := []map[string]interface{}{larkTextDiv(desc)}
	if data.Message != "" {
		elements = append(elements, larkHR(), larkTextDiv("**告警详情：**\n"+data.Message))
	}
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		url := fmt.Sprintf("%s/kube/alarms", base)
		elements = append(elements, larkHR(), larkActionButton("查看详情", url))
	}
	return s.buildLarkCardMessage(notification, "☸️ K8s 安全告警", s.getSeverityTemplate(data.Severity), elements)
}

func (s *NotificationService) buildWebhookKube(data *KubeAlertData) map[string]interface{} {
	return map[string]interface{}{
		"alert_type":   "kube_alarm",
		"cluster_name": data.ClusterName,
		"severity":     data.Severity,
		"alarm_type":   data.AlarmType,
		"title":        data.Title,
		"description":  data.Description,
		"message":      data.Message,
		"namespace":    data.Namespace,
		"target":       data.Target,
	}
}

// ============================================================
// 漏洞通报通知
// ============================================================

// SendVulnBulletinNotification 发送漏洞通报通知
func (s *NotificationService) SendVulnBulletinNotification(bulletin *model.VulnBulletin) error {
	var notifications []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, model.NotifyCategoryVulnBulletin).
		Find(&notifications).Error; err != nil {
		return err
	}

	sentCount := 0
	for _, n := range notifications {
		// 通报不按严重级别二次过滤，等级控制已在通报配置中完成

		var msg map[string]interface{}
		if n.Type == model.NotificationTypeLark {
			msg = s.buildLarkBulletinCard(&n, bulletin)
		} else {
			msg = s.buildWebhookBulletin(bulletin)
		}
		if err := s.postWebhook(n.Config.WebhookURL, msg); err != nil {
			s.logger.Error("发送漏洞通报通知失败", zap.Uint("notification_id", n.ID), zap.Error(err))
			continue
		}
		sentCount++
	}

	if sentCount > 0 {
		// 更新通报状态和通知追踪
		now := model.Now()
		s.db.Model(bulletin).Updates(map[string]interface{}{
			"status":           model.BulletinStatusNotified,
			"notified_at":      &now,
			"last_notified_at": &now,
			"notify_count":     bulletin.NotifyCount + 1,
		})
	}

	return nil
}

// buildLarkBulletinCard 构建飞书漏洞通报卡片
func (s *NotificationService) buildLarkBulletinCard(notification *model.Notification, b *model.VulnBulletin) map[string]interface{} {
	// 优先级标题和颜色
	priorityLabel := bulletinPriorityLabel(b.Priority)
	template := bulletinPriorityTemplate(b.Priority)
	title := fmt.Sprintf("%s %s 漏洞通报 · %s", bulletinPriorityEmoji(b.Priority), priorityLabel, b.BulletinNo)

	// 攻击向量中文
	avText := attackVectorLabel(b.AttackVector)
	// 漏洞类型中文
	vtText := vulnTypeLabel(b.VulnType)

	// 基础信息段
	info := fmt.Sprintf(
		"矩阵云安全平台检测到安全漏洞，请及时处理。\n\n"+
			"**漏洞编号：** %s\n"+
			"**受影响组件：** %s\n"+
			"**漏洞类型：** %s\n"+
			"**CVSS 评分：** %.1f (%s)\n"+
			"**攻击向量：** %s",
		b.CveID, b.Component, vtText,
		b.CvssScore, getSeverityLabel(b.Severity), avText,
	)

	elements := []map[string]interface{}{larkTextDiv(info), larkHR()}

	// 影响范围段
	impact := fmt.Sprintf(
		"**影响资产：** %d 台\n"+
			"**影响版本：** %s",
		b.AffectedAssets, defaultStr(b.AffectedVersions, "未知"),
	)
	elements = append(elements, larkTextDiv(impact), larkHR())

	// 威胁情报段
	kevText := "否"
	if b.InKEV {
		kevText = "是 (CISA KEV)"
	}
	expText := "否"
	if b.HasExploit {
		expText = "是"
	}
	intel := fmt.Sprintf(
		"**在野利用：** %s\n"+
			"**公开 EXP：** %s",
		kevText, expText,
	)
	elements = append(elements, larkTextDiv(intel), larkHR())

	// 修复建议段
	fixText := defaultStr(b.FixSuggestion, "暂无修复建议")
	if b.FixedVersion != "" {
		fixText = fmt.Sprintf("升级至 %s 及以上", b.FixedVersion)
	}
	fix := fmt.Sprintf("**修复建议：** %s", fixText)
	if b.Workaround != "" {
		fix += fmt.Sprintf("\n**临时缓解：** %s", b.Workaround)
	}
	elements = append(elements, larkTextDiv(fix), larkHR())

	// SLA 段
	sla := ""
	if b.SLAAckDeadline != nil {
		sla += fmt.Sprintf("**确认截止：** %s\n", b.SLAAckDeadline.String())
	}
	if b.SLAResolveDeadline != nil {
		sla += fmt.Sprintf("**修复截止：** %s", b.SLAResolveDeadline.String())
	}
	if sla != "" {
		elements = append(elements, larkTextDiv(sla), larkHR())
	}

	// 底部元信息
	meta := fmt.Sprintf("漏洞来源：%s　·　通报状态：%s",
		defaultStr(b.Source, "未知"), bulletinStatusLabel(b.Status))
	elements = append(elements, larkTextDiv(meta))

	// 跳转按钮：优先全局 site_domain
	if base := s.resolveFrontendURL(notification.FrontendURL); base != "" {
		url := fmt.Sprintf("%s/vuln-bulletins/%d", base, b.ID)
		elements = append(elements, larkActionButton("查看详情", url))
	}

	return s.buildLarkCardMessage(notification, title, template, elements)
}

// buildWebhookBulletin 构建 Webhook 通报消息
func (s *NotificationService) buildWebhookBulletin(b *model.VulnBulletin) map[string]interface{} {
	msg := map[string]interface{}{
		"alert_type":        "vuln_bulletin",
		"bulletin_no":       b.BulletinNo,
		"priority":          b.Priority,
		"cve_id":            b.CveID,
		"component":         b.Component,
		"vuln_type":         b.VulnType,
		"severity":          b.Severity,
		"cvss_score":        b.CvssScore,
		"cvss_vector":       b.CvssVector,
		"attack_vector":     b.AttackVector,
		"affected_assets":   b.AffectedAssets,
		"affected_versions": b.AffectedVersions,
		"fixed_version":     b.FixedVersion,
		"fix_suggestion":    b.FixSuggestion,
		"has_exploit":       b.HasExploit,
		"in_kev":            b.InKEV,
		"source":            b.Source,
		"status":            b.Status,
		"description":       b.Description,
	}
	if b.SLAAckDeadline != nil {
		msg["sla_ack_deadline"] = b.SLAAckDeadline.Time().Format(time.RFC3339)
	}
	if b.SLAResolveDeadline != nil {
		msg["sla_resolve_deadline"] = b.SLAResolveDeadline.Time().Format(time.RFC3339)
	}
	return msg
}

// ---- 通报辅助函数 ----

func bulletinPriorityLabel(p string) string {
	switch p {
	case model.BulletinPriorityP0:
		return "P0 紧急"
	case model.BulletinPriorityP1:
		return "P1 高"
	case model.BulletinPriorityP2:
		return "P2 中"
	case model.BulletinPriorityP3:
		return "P3 低"
	default:
		return p
	}
}

func bulletinPriorityEmoji(p string) string {
	switch p {
	case model.BulletinPriorityP0:
		return "🚨"
	case model.BulletinPriorityP1:
		return "🔴"
	case model.BulletinPriorityP2:
		return "🟡"
	case model.BulletinPriorityP3:
		return "🔵"
	default:
		return "🔔"
	}
}

func bulletinPriorityTemplate(p string) string {
	switch p {
	case model.BulletinPriorityP0:
		return "red"
	case model.BulletinPriorityP1:
		return "orange"
	case model.BulletinPriorityP2:
		return "blue"
	case model.BulletinPriorityP3:
		return "grey"
	default:
		return "blue"
	}
}

func bulletinStatusLabel(s string) string {
	switch s {
	case model.BulletinStatusPending:
		return "待处理"
	case model.BulletinStatusNotified:
		return "已通知"
	case model.BulletinStatusAcknowledged:
		return "已确认"
	case model.BulletinStatusResolved:
		return "已修复"
	case model.BulletinStatusIgnored:
		return "已忽略"
	default:
		return s
	}
}

func attackVectorLabel(av string) string {
	switch av {
	case model.AttackVectorNetwork:
		return "网络"
	case model.AttackVectorAdjacent:
		return "相邻网络"
	case model.AttackVectorLocal:
		return "本地"
	case model.AttackVectorPhysical:
		return "物理"
	default:
		return "未知"
	}
}

func vulnTypeLabel(vt string) string {
	switch vt {
	case model.VulnTypeRCE:
		return "远程代码执行 (RCE)"
	case model.VulnTypeLPE:
		return "本地提权 (LPE)"
	case model.VulnTypeDoS:
		return "拒绝服务 (DoS)"
	case model.VulnTypeInfoDisclosure:
		return "信息泄露"
	case model.VulnTypeAuthBypass:
		return "认证绕过"
	case model.VulnTypeXSS:
		return "跨站脚本 (XSS)"
	case model.VulnTypeSQLi:
		return "SQL 注入"
	case model.VulnTypeSSRF:
		return "服务端请求伪造 (SSRF)"
	case model.VulnTypeOther:
		return "其他"
	case model.VulnTypeUnknown:
		return "未知"
	default:
		return vt
	}
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// ============================================================
// 测试通知辅助方法（公开，供 API 层调用）
// ============================================================

// BuildTestLarkCard 构建测试用的飞书卡片（根据通知类别选择不同模板）
func (s *NotificationService) BuildTestLarkCard(notification *model.Notification, category model.NotifyCategory) map[string]interface{} {
	now := time.Now()
	switch category {
	case model.NotifyCategoryVirusAlert:
		return s.buildLarkVirusCard(notification, &VirusAlertData{
			HostID: "test-host-001", Hostname: "测试主机", IP: "192.168.1.100",
			FilePath: "/tmp/malware.elf", ThreatName: "Trojan.Linux.Generic",
			ThreatType: "trojan", Severity: "high", FileHash: "a1b2c3d4e5f6...",
			Action: "quarantined", DetectedAt: now, FrontendURL: notification.FrontendURL,
		})
	case model.NotifyCategoryFIMAlert:
		return s.buildLarkFIMCard(notification, &FIMAlertData{
			HostID: "test-host-001", Hostname: "测试主机", IP: "192.168.1.100",
			FilePath: "/etc/passwd", ChangeType: "changed", Category: "auth",
			Severity: "high", DetectedAt: now, FrontendURL: notification.FrontendURL,
		})
	case model.NotifyCategoryDetection:
		return s.buildLarkDetectionCard(notification, &DetectionAlertData{
			HostID: "test-host-001", Hostname: "测试主机", IP: "192.168.1.100",
			RuleName: "检测可疑进程执行", Severity: "high", Category: "process",
			MitreID: "T1059", Description: "检测到可疑的命令执行行为",
			DetectedAt: now, FrontendURL: notification.FrontendURL,
		})
	case model.NotifyCategoryKubeAlert:
		return s.buildLarkKubeCard(notification, &KubeAlertData{
			ClusterName: "测试集群", Severity: "critical",
			AlarmType: "container_escape", Title: "[K8S-005] 创建特权容器",
			Description: "检测到创建特权容器", Namespace: "default",
			Message: "用户 admin 在命名空间 default 中创建了特权容器 Pod test-pod",
			Target:  "pods/test-pod", FrontendURL: notification.FrontendURL,
		})
	default:
		// baseline_alert 和 agent_offline 使用原有逻辑
		return nil
	}
}
