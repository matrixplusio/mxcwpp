package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// isDeviceTrusted 判断 (username, deviceID) 是否为可信设备：
// 成功登录次数达到阈值且最近一次成功在有效期内。
func (h *AuthHandler) isDeviceTrusted(username, deviceID string) bool {
	if deviceID == "" {
		return false
	}
	var dev model.LoginDevice
	if err := h.db.Where("username = ? AND device_id = ?", username, deviceID).First(&dev).Error; err != nil {
		return false
	}
	if dev.SuccessCount < deviceTrustThreshold || dev.LastSuccessAt == nil {
		return false
	}
	return time.Since(time.Time(*dev.LastSuccessAt)) < deviceTrustTTL
}

// loginNeedsCaptcha 风控判定：非可信设备且该用户近期连续失败达到阈值时要求验证码。
// 用户不存在时返回 false，避免通过"是否要验证码"枚举用户名。
func (h *AuthHandler) loginNeedsCaptcha(username, deviceID string) bool {
	if h.isDeviceTrusted(username, deviceID) {
		return false
	}
	var user model.User
	if err := h.db.Select("login_fail_count").Where("username = ?", username).First(&user).Error; err != nil {
		return false
	}
	return user.LoginFailCount >= captchaFailThreshold
}

// recordDeviceSuccess 记录一次成功登录到设备表（成功次数累加、刷新最近成功时间）。
func (h *AuthHandler) recordDeviceSuccess(username, deviceID string) {
	if deviceID == "" {
		return
	}
	now := model.Now()
	dev := model.LoginDevice{Username: username, DeviceID: deviceID, SuccessCount: 1, LastSuccessAt: &now}
	if err := h.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "username"}, {Name: "device_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"success_count":   gorm.Expr("success_count + 1"),
			"last_success_at": now,
		}),
	}).Create(&dev).Error; err != nil {
		h.logger.Warn("记录登录设备失败", zap.String("username", username), zap.Error(err))
	}
}

// LoginPrecheckRequest 登录预检请求
type LoginPrecheckRequest struct {
	Username string `json:"username" binding:"required"`
	DeviceID string `json:"device_id"`
}

// LoginPrecheck 返回该用户名+设备当前是否需要图形验证码，供前端决定是否展示验证码。
// POST /api/v1/auth/login-precheck
func (h *AuthHandler) LoginPrecheck(c *gin.Context) {
	var req LoginPrecheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 参数不全时保守要求验证码
		Success(c, gin.H{"need_captcha": true})
		return
	}
	Success(c, gin.H{"need_captcha": h.loginNeedsCaptcha(req.Username, req.DeviceID)})
}
