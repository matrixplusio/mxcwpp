// Package api 提供 HTTP API 处理器
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/common/ssrf"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
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
		// 校验信息本身就是给用户看的（缺等级、地址指向内网等），笼统的「校验失败」让人无从改起
		BadRequest(c, err.Error())
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
	if len(notification.Severities) == 0 {
		BadRequest(c, errNoSeverity)
		return
	}

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

	// 测试与真实告警走同一套模板与发送（notify.DeliverEvent）：测试能发即真实告警能发。
	// 此前测试另有一套卡片与客户端，曾出现测试成功、真实告警从未发出去。
	notification := model.Notification{
		Name:        "测试通知",
		Type:        req.Type,
		FrontendURL: req.FrontendURL,
		Config:      req.Config,
	}
	category := req.NotifyCategory
	if req.NotificationID != nil {
		var dbNotification model.Notification
		if err := h.db.First(&dbNotification, *req.NotificationID).Error; err == nil {
			notification.Name = dbNotification.Name
			if req.FrontendURL == "" {
				notification.FrontendURL = dbNotification.FrontendURL
			}
			if category == "" {
				category = dbNotification.NotifyCategory
			}
		}
	}

	// 防 SSRF：先校验地址，发送时的安全客户端还会在建连时按实际 IP 复查
	if err := ssrf.ValidateURL(req.Config.WebhookURL); err != nil {
		BadRequest(c, "webhook 地址不合法: "+err.Error())
		return
	}

	svc := notify.NewNotificationService(h.db, h.logger)
	if err := svc.DeliverEvent(&notification, notify.SampleEvent(category)); err != nil {
		h.logger.Error("发送测试通知失败", zap.Error(err))
		msg, clientSide := friendlyWebhookError(err)
		if clientSide {
			BadRequest(c, msg)
		} else {
			InternalError(c, "发送测试通知失败: "+msg)
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

// errNoSeverity 统一出口只把告警发给配置了对应等级的渠道：一个等级都不选等于收不到任何告警，
// 而且没有任何提示。旧的几条发送路径对「没选等级」理解不一（有的当全部、有的当不发），统一后按不发处理。
const errNoSeverity = "至少选择一个告警等级，否则这条通知收不到任何告警"

// validateNotificationRequest 验证通知请求
func (h *NotificationsHandler) validateNotificationRequest(req *CreateNotificationRequest) error {
	if req.Type != model.NotificationTypeLark && req.Type != model.NotificationTypeWebhook {
		return fmt.Errorf("无效的通知类型，支持 lark 或 webhook")
	}

	if req.Config.WebhookURL == "" {
		return errors.New("webhook URL 不能为空")
	}
	if len(req.Severities) == 0 {
		return errors.New(errNoSeverity)
	}
	// 防 SSRF：拒绝指向内网/回环/云元数据的 Webhook 地址
	if err := ssrf.ValidateURL(req.Config.WebhookURL); err != nil {
		return fmt.Errorf("webhook 地址不合法: %w", err)
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

// friendlyWebhookError 把发送错误翻成用户能处理的提示；第二个返回值表示是否属于配置问题（地址、认证）。
func friendlyWebhookError(err error) (string, bool) {
	// 返回给前端的文本不带 webhook 地址（令牌在地址里）
	e := notify.RedactURLs(err.Error())
	switch {
	case strings.Contains(e, "connection refused"):
		return "无法连接到 Webhook 地址，请检查 URL 是否正确", true
	case strings.Contains(e, "timeout"):
		return "连接超时，请检查网络或 Webhook 地址", true
	case strings.Contains(e, "no such host"):
		return "无法解析 Webhook 地址，请检查 URL 是否正确", true
	case strings.Contains(e, "拒绝连接受限网段"):
		return "Webhook 地址指向内网或受限网段，已拒绝", true
	case strings.Contains(e, "状态码: 404"):
		return "webhook 地址不存在（404），请检查 URL 是否正确", true
	case strings.Contains(e, "状态码: 401"), strings.Contains(e, "状态码: 403"):
		return "webhook 认证失败，请检查 Secret 是否正确", true
	case strings.Contains(e, "状态码: 4"):
		return "webhook 返回错误：" + e, true
	}
	return e, false
}
