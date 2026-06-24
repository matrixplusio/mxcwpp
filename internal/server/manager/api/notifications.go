// Package api 提供 HTTP API 处理器
package api

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

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/common/ssrf"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// NotificationsHandler 通知管理 API 处理器
type NotificationsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewNotificationsHandler 创建通知处理器
func NewNotificationsHandler(db *gorm.DB, logger *zap.Logger) *NotificationsHandler {
	return &NotificationsHandler{
		db:     db,
		logger: logger,
	}
}

// ListNotifications 获取通知列表
// GET /api/v1/notifications
func (h *NotificationsHandler) ListNotifications(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	enabled := c.Query("enabled")
	keyword := c.Query("keyword")

	query := h.db.Model(&model.Notification{})

	if enabled != "" {
		enabledBool := enabled == "true"
		query = query.Where("enabled = ?", enabledBool)
	}

	if keyword != "" {
		pattern := "%" + keyword + "%"
		query = query.Where("name LIKE ? OR description LIKE ?", pattern, pattern)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询通知总数失败", zap.Error(err))
		InternalError(c, "查询通知列表失败")
		return
	}

	var notifications []model.Notification
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&notifications).Error; err != nil {
		h.logger.Error("查询通知列表失败", zap.Error(err))
		InternalError(c, "查询通知列表失败")
		return
	}

	SuccessPaginated(c, total, notifications)
}

// GetNotification 获取通知详情
// GET /api/v1/notifications/:id
func (h *NotificationsHandler) GetNotification(c *gin.Context) {
	id, err := h.parseID(c.Param("id"))
	if err != nil {
		BadRequest(c, "无效的通知ID")
		return
	}

	var notification model.Notification
	if err := h.db.First(&notification, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "通知不存在")
			return
		}
		h.logger.Error("查询通知失败", zap.Error(err))
		InternalError(c, "查询通知失败")
		return
	}

	Success(c, notification)
}

// CreateNotificationRequest 创建通知请求
type CreateNotificationRequest struct {
	Name           string                   `json:"name" binding:"required"`
	Description    string                   `json:"description"`
	NotifyCategory model.NotifyCategory     `json:"notify_category" binding:"required"`
	Enabled        bool                     `json:"enabled"`
	Type           model.NotificationType   `json:"type" binding:"required"`
	Severities     []string                 `json:"severities"`
	Scope          model.NotificationScope  `json:"scope" binding:"required"`
	ScopeValue     model.ScopeValueData     `json:"scope_value"`
	FrontendURL    string                   `json:"frontend_url"`
	Config         model.NotificationConfig `json:"config" binding:"required"`
}

// CreateNotification 创建通知
// POST /api/v1/notifications
func (h *NotificationsHandler) CreateNotification(c *gin.Context) {
	var req CreateNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if err := h.validateNotificationRequest(&req); err != nil {
		BadRequest(c, "请求参数校验失败")
		return
	}

	scopeValueJSON, err := json.Marshal(req.ScopeValue)
	if err != nil {
		BadRequest(c, "主机范围值格式错误")
		return
	}

	notification := model.Notification{
		Name:           req.Name,
		Description:    req.Description,
		NotifyCategory: req.NotifyCategory,
		Enabled:        req.Enabled,
		Type:           req.Type,
		Severities:     model.StringArray(req.Severities),
		Scope:          req.Scope,
		ScopeValue:     string(scopeValueJSON),
		FrontendURL:    req.FrontendURL,
		Config:         req.Config,
	}

	if err := h.db.Create(&notification).Error; err != nil {
		h.logger.Error("创建通知失败", zap.Error(err))
		InternalError(c, "创建通知失败")
		return
	}

	SuccessWithMessage(c, "创建成功", notification)
}

// UpdateNotificationRequest 更新通知请求
type UpdateNotificationRequest struct {
	Name           string                    `json:"name"`
	Description    string                    `json:"description"`
	NotifyCategory model.NotifyCategory      `json:"notify_category"`
	Enabled        *bool                     `json:"enabled"`
	Type           model.NotificationType    `json:"type"`
	Severities     []string                  `json:"severities"`
	Scope          model.NotificationScope   `json:"scope"`
	ScopeValue     *model.ScopeValueData     `json:"scope_value"`
	FrontendURL    string                    `json:"frontend_url"`
	Config         *model.NotificationConfig `json:"config"`
}

// UpdateNotification 更新通知
// PUT /api/v1/notifications/:id
func (h *NotificationsHandler) UpdateNotification(c *gin.Context) {
	id, err := h.parseID(c.Param("id"))
	if err != nil {
		BadRequest(c, "无效的通知ID")
		return
	}

	var req UpdateNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	// 防 SSRF：更新时若带 Webhook 地址，校验不得指向内网/回环/元数据
	if req.Config != nil && req.Config.WebhookURL != "" {
		if err := ssrf.ValidateURL(req.Config.WebhookURL); err != nil {
			BadRequest(c, "Webhook 地址不合法")
			return
		}
	}

	var notification model.Notification
	if err := h.db.First(&notification, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "通知不存在")
			return
		}
		h.logger.Error("查询通知失败", zap.Error(err))
		InternalError(c, "查询通知失败")
		return
	}

	h.updateNotificationFields(&notification, &req)

	if err := h.db.Save(&notification).Error; err != nil {
		h.logger.Error("更新通知失败", zap.Error(err))
		InternalError(c, "更新通知失败")
		return
	}

	SuccessWithMessage(c, "更新成功", notification)
}

// DeleteNotification 删除通知
// DELETE /api/v1/notifications/:id
func (h *NotificationsHandler) DeleteNotification(c *gin.Context) {
	id, err := h.parseID(c.Param("id"))
	if err != nil {
		BadRequest(c, "无效的通知ID")
		return
	}

	var notification model.Notification
	if err := h.db.First(&notification, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "通知不存在")
			return
		}
		h.logger.Error("查询通知失败", zap.Error(err))
		InternalError(c, "查询通知失败")
		return
	}

	if err := h.db.Delete(&notification).Error; err != nil {
		h.logger.Error("删除通知失败", zap.Error(err))
		InternalError(c, "删除通知失败")
		return
	}

	SuccessMessage(c, "删除成功")
}

// TestNotificationRequest 测试通知请求
type TestNotificationRequest struct {
	Type           model.NotificationType   `json:"type" binding:"required"`
	Config         model.NotificationConfig `json:"config" binding:"required"`
	FrontendURL    string                   `json:"frontend_url"`    // 可选，用于测试跳转链接
	NotificationID *uint                    `json:"notification_id"` // 可选，如果提供则使用完整的通知配置
	NotifyCategory model.NotifyCategory     `json:"notify_category"` // 可选，指定测试的通知类别
}

// TestNotification 测试通知
// POST /api/v1/notifications/test
func (h *NotificationsHandler) TestNotification(c *gin.Context) {
	var req TestNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if req.Config.WebhookURL == "" {
		BadRequest(c, "Webhook URL 不能为空")
		return
	}

	var testMessage map[string]interface{}

	// 对于 Lark 类型，始终使用完整的告警模板
	if req.Type == model.NotificationTypeLark {
		// 创建模拟的通知对象
		notification := model.Notification{
			Name:        "测试通知",
			Type:        req.Type,
			FrontendURL: req.FrontendURL,
			Config:      req.Config,
		}

		// 如果提供了通知ID，查询完整的通知信息
		if req.NotificationID != nil {
			var dbNotification model.Notification
			if err := h.db.First(&dbNotification, *req.NotificationID).Error; err == nil {
				notification.Name = dbNotification.Name
				if req.FrontendURL == "" {
					notification.FrontendURL = dbNotification.FrontendURL
				}
				// 自动使用通知的类别
				if req.NotifyCategory == "" {
					req.NotifyCategory = dbNotification.NotifyCategory
				}
			}
		}

		notificationService := biz.NewNotificationService(h.db, h.logger)

		// 根据通知类别使用不同的模拟数据
		if card := notificationService.BuildTestLarkCard(&notification, req.NotifyCategory); card != nil {
			testMessage = card
		} else {
			// 默认：基线告警模拟数据
			alertData := &biz.AlertData{
				HostID:        "test-host-001",
				Hostname:      "测试主机",
				IP:            "192.168.1.100",
				OSFamily:      "rocky",
				OSVersion:     "9.0",
				RuleID:        "TEST_RULE_001",
				RuleName:      "测试规则：禁止 root 远程登录",
				Category:      "ssh",
				Severity:      "high",
				Title:         "禁止 root 远程登录",
				Description:   "SSH 配置应禁止 root 用户远程登录",
				Actual:        "yes",
				Expected:      "no",
				FixSuggestion: "修改 /etc/ssh/sshd_config，设置 PermitRootLogin no",
				TaskID:        "test-task-001",
				PolicyID:      "test-policy-001",
				CheckedAt:     time.Now(),
				FrontendURL:   notification.FrontendURL,
				ResultID:      "test-result-001",
			}
			testMessage = notificationService.BuildLarkAlertCardForTest(&notification, alertData)
		}
	} else {
		// Webhook 类型使用简单的测试消息
		testMessage = h.buildTestMessage(req.Type, req.Config)
	}

	body, err := json.Marshal(testMessage)
	if err != nil {
		h.logger.Error("序列化消息失败", zap.Error(err))
		InternalError(c, "序列化消息失败")
		return
	}

	if err := h.sendTestNotification(req.Config.WebhookURL, body); err != nil {
		h.logger.Error("发送测试通知失败", zap.Error(err))
		errMsg := err.Error()

		// 对于客户端错误（连接错误、4xx 错误），返回 400
		// 对于服务器错误（5xx），返回 500
		if strings.Contains(errMsg, "无法连接") ||
			strings.Contains(errMsg, "连接超时") ||
			strings.Contains(errMsg, "无法解析") ||
			strings.Contains(errMsg, "Webhook 地址不存在") ||
			strings.Contains(errMsg, "Webhook 认证失败") ||
			strings.Contains(errMsg, "Webhook 返回错误") {
			BadRequest(c, errMsg)
		} else {
			InternalError(c, "发送测试通知失败: "+errMsg)
		}
		return
	}

	SuccessMessage(c, "测试通知发送成功")
}

// 辅助方法

// parseID 解析ID参数
func (h *NotificationsHandler) parseID(idStr string) (uint, error) {
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}

// validateNotificationRequest 验证通知请求
func (h *NotificationsHandler) validateNotificationRequest(req *CreateNotificationRequest) error {
	if req.Type != model.NotificationTypeLark && req.Type != model.NotificationTypeWebhook {
		return fmt.Errorf("无效的通知类型，支持 lark 或 webhook")
	}

	if req.Config.WebhookURL == "" {
		return fmt.Errorf("Webhook URL 不能为空")
	}
	// 防 SSRF：拒绝指向内网/回环/云元数据的 Webhook 地址
	if err := ssrf.ValidateURL(req.Config.WebhookURL); err != nil {
		return fmt.Errorf("Webhook 地址不合法: %w", err)
	}

	return nil
}

// updateNotificationFields 更新通知字段
func (h *NotificationsHandler) updateNotificationFields(
	notification *model.Notification,
	req *UpdateNotificationRequest,
) {
	if req.Name != "" {
		notification.Name = req.Name
	}
	if req.Description != "" {
		notification.Description = req.Description
	}
	if req.NotifyCategory != "" {
		notification.NotifyCategory = req.NotifyCategory
	}
	if req.Enabled != nil {
		notification.Enabled = *req.Enabled
	}
	if req.Type != "" {
		if req.Type == model.NotificationTypeLark || req.Type == model.NotificationTypeWebhook {
			notification.Type = req.Type
		}
	}
	if req.Severities != nil {
		notification.Severities = model.StringArray(req.Severities)
	}
	if req.Scope != "" {
		notification.Scope = req.Scope
	}
	if req.ScopeValue != nil {
		scopeValueJSON, _ := json.Marshal(req.ScopeValue)
		notification.ScopeValue = string(scopeValueJSON)
	}
	if req.FrontendURL != "" {
		notification.FrontendURL = req.FrontendURL
	}
	if req.Config != nil {
		if req.Config.WebhookURL != "" {
			notification.Config = *req.Config
		}
	}
}

// buildTestMessage 构建测试消息
func (h *NotificationsHandler) buildTestMessage(
	notificationType model.NotificationType,
	config model.NotificationConfig,
) map[string]interface{} {
	if notificationType == model.NotificationTypeLark {
		// Lark 使用卡片消息格式
		return h.buildLarkCardMessage(
			"测试通知",
			"这是一条测试通知消息，用于验证通知配置是否正确。",
			map[string]interface{}{
				"test_time": time.Now().Format("2006-01-02 15:04:05"),
				"type":      "test_notification",
			},
			config,
		)
	}

	// Webhook 使用简单文本格式
	return map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": "这是一条测试通知消息，用于验证通知配置是否正确。\n时间: " +
				time.Now().Format("2006-01-02 15:04:05"),
		},
	}
}

// buildLarkCardMessage 构建 Lark 卡片消息（参考 Elkeid 模板）
func (h *NotificationsHandler) buildLarkCardMessage(
	title string,
	description string,
	rawData map[string]interface{},
	config model.NotificationConfig,
) map[string]interface{} {
	// 构建原始数据文本（参考 Elkeid 格式）
	rawDataLines := []string{}
	for k, v := range rawData {
		rawDataLines = append(rawDataLines, fmt.Sprintf(`"%s": "%v"`, k, v))
	}
	rawDataText := "原始数据如下:\n" + strings.Join(rawDataLines, "\n")

	// 构建卡片消息（参考 Elkeid 模板）
	card := map[string]interface{}{
		"config": map[string]interface{}{
			"wide_screen_mode": true,
		},
		"header": map[string]interface{}{
			"title": map[string]interface{}{
				"tag":     "plain_text",
				"content": "矩阵云安全平台告警通知", // 参考 Elkeid 的标题
			},
			"template": "red", // 红色模板，参考 Elkeid
		},
		"elements": []map[string]interface{}{
			{
				"tag": "div",
				"text": map[string]interface{}{
					"tag":     "lark_md",
					"content": description,
				},
			},
			{
				"tag": "hr", // 分隔线
			},
			{
				"tag": "div",
				"text": map[string]interface{}{
					"tag":     "lark_md",
					"content": rawDataText,
				},
			},
		},
	}

	message := map[string]interface{}{
		"msg_type": "interactive",
		"card":     card,
	}

	// Lark 需要签名
	if config.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sign, err := h.generateLarkSign(config.Secret, timestamp)
		if err == nil {
			message["timestamp"] = timestamp
			message["sign"] = sign
		}
	}

	return message
}

// sendTestNotification 发送测试通知
func (h *NotificationsHandler) sendTestNotification(webhookURL string, body []byte) error {
	// 防 SSRF：先校验地址，再用带 dial 期 IP 复查的安全客户端发送
	if err := ssrf.ValidateURL(webhookURL); err != nil {
		return fmt.Errorf("Webhook 地址不合法: %w", err)
	}
	client := ssrf.NewSafeClient(10 * time.Second)

	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		// 提供更友好的错误信息
		if strings.Contains(err.Error(), "connection refused") {
			return fmt.Errorf("无法连接到 Webhook 地址，请检查 URL 是否正确")
		}
		if strings.Contains(err.Error(), "timeout") {
			return fmt.Errorf("连接超时，请检查网络或 Webhook 地址")
		}
		if strings.Contains(err.Error(), "no such host") {
			return fmt.Errorf("无法解析 Webhook 地址，请检查 URL 是否正确")
		}
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 读取响应体以便提供更详细的错误信息
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}

		// 根据状态码返回不同的错误类型
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// 4xx 错误是客户端错误，返回更友好的提示
			if resp.StatusCode == 404 {
				return fmt.Errorf("Webhook 地址不存在（404），请检查 URL 是否正确")
			}
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return fmt.Errorf("Webhook 认证失败（%d），请检查 Secret 是否正确", resp.StatusCode)
			}
			return fmt.Errorf("Webhook 返回错误（%d）: %s", resp.StatusCode, bodyStr)
		}
		// 5xx 错误是服务器错误
		return fmt.Errorf("Webhook 服务器错误（%d）: %s", resp.StatusCode, bodyStr)
	}

	return nil
}

// generateLarkSign 生成 Lark Webhook 签名
func (h *NotificationsHandler) generateLarkSign(secret, timestamp string) (string, error) {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(stringToSign))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
