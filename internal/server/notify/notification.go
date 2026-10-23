// Package notify 提供告警/事件通知派发（邮件/Webhook/Lark），跨服务共享。
package notify

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

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// NotificationService 通知服务
type NotificationService struct {
	db     *gorm.DB
	logger *zap.Logger
	// httpClient 统一出口（DeliverEvent）使用；nil 时用 SSRF 安全客户端
	httpClient *http.Client
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
// siteConfigRow 解析 system_configs 表中的 site_config 行（仅本包内部用）。
type siteConfigRow struct {
	Key   string `gorm:"column:key"`
	Value string `gorm:"column:value"`
}

func (siteConfigRow) TableName() string { return "system_configs" }

func (s *NotificationService) loadSiteDomain() string {
	if s.db == nil {
		return ""
	}
	var row siteConfigRow
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

// AlertData 渠道匹配所需的告警属性（等级、所属主机）。
type AlertData struct {
	HostID   string
	Severity string
}

// alertCenterURL 告警中心链接；带告警 ID 时前端直接打开这条告警的详情。
// 路径必须是前端真实存在的页面，否则会退回首页（TestNotificationLinksExist 钉住）。
func alertCenterURL(base string, alertID uint) string {
	if alertID == 0 {
		return base + "/alert-center/alerts"
	}
	return fmt.Sprintf("%s/alert-center/alerts?id=%d", base, alertID)
}

// alertSourceCategory 告警表各来源对应的通知类别。
func alertSourceCategory(source string) model.NotifyCategory {
	switch source {
	case model.AlertSourceDetection:
		return model.NotifyCategoryDetection
	case model.AlertSourcePrometheusInfra:
		return model.NotifyCategoryInfraAlert
	case model.AlertSourceFIM:
		return model.NotifyCategoryFIMAlert
	case model.AlertSourceVirus:
		return model.NotifyCategoryVirusAlert
	case model.AlertSourceKube:
		return model.NotifyCategoryKubeAlert
	case model.AlertSourceAgent:
		return model.NotifyCategoryAgentOffline
	case model.AlertSourceBehavior:
		return model.NotifyCategoryBehaviorAlert // 灰度类别，由统一出口按 notify_categories 判断
	default: // baseline、vulnerability 及历史上未填来源的告警
		return model.NotifyCategoryBaselineAlert
	}
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

// hostTagsMatch 判断主机标签是否命中通知配置要求的标签。
// 采用 OR 语义：主机命中任一配置标签即视为匹配，与业务线/指定主机范围的"任一命中"约定一致。
// 配置标签为空时不匹配任何主机（避免空条件退化为全量分发）。
func hostTagsMatch(hostTags, requiredTags []string) bool {
	for _, want := range requiredTags {
		for _, have := range hostTags {
			if want == have {
				return true
			}
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
		// 查询主机的标签
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", alertData.HostID).Error; err != nil {
			return false
		}
		return hostTagsMatch(host.Tags, scopeValue.Tags)

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

// postWith 用指定客户端 POST 一条消息；非 200 视为失败。
func (s *NotificationService) postWith(client *http.Client, webhookURL string, message map[string]interface{}) error {
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		// 不能用 %v 直接带上 err：它的文本里有完整的 webhook 地址，令牌就在地址里。
		return fmt.Errorf("发送请求失败: %s", sendErrorText(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		// 对端的响应体可能回显请求地址，或只回显其中的路径、令牌
		return fmt.Errorf("服务器返回状态码: %d，响应: %s", resp.StatusCode, redactFor(webhookURL, bodyStr))
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

// ClaimAlertNotification 原子地占用一条告警的一次通知机会。
//
// alerts 有两个通知触发：AgentCenter 在告警产生时立即通知（首次），Manager 定时器
// 补发从未通知成功的、并对仍活跃的做周期重复提醒。两者靠 last_notified_at 协调，
// 但原先都是"先发送、后写回"，中间存在窗口：新告警的内联 goroutine 尚未写回时，
// 定时器扫到 last_notified_at IS NULL 就会把同一条再发一次。
//
// 改为"先占用、后发送"：用带条件的 UPDATE 抢占，RowsAffected==0 表示已被另一方占走，
// 直接跳过。占用后若发送失败，这次机会被消耗，但告警仍是 active，下个周期
// last_notified_at 会早于 cutoff 而重新可被占用——退化成延迟一个周期，不会丢失。
// 相比之下重复打扰值班是更难接受的一侧。
//
// notBefore 语义：仅当 last_notified_at 为空或早于该时刻时占用成功。
func ClaimAlertNotification(db *gorm.DB, alertID uint, notBefore time.Time) (bool, error) {
	now := model.Now()
	res := db.Model(&model.Alert{}).
		Where("id = ?", alertID).
		Where("last_notified_at IS NULL OR last_notified_at < ?", notBefore).
		Updates(map[string]interface{}{
			"last_notified_at": &now,
			"notify_count":     gorm.Expr("notify_count + 1"),
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}
