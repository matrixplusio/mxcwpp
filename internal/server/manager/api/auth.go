// Package api 提供 HTTP API 处理器
package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mojocn/base64Captcha"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/common/tenant"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// captchaStore 验证码内存存储（自带过期清理，默认 10 分钟过期，每分钟清理一次）
var captchaStore = base64Captcha.DefaultMemStore

const (
	jwtIssuer = "mxsec-platform"

	// 登录安全策略
	maxLoginFailCount = 5                // 最大连续失败次数（达到即锁定，硬底线）
	lockDuration      = 15 * time.Minute // 锁定时长

	// 登录风控（自适应验证码 + 可信设备）
	captchaFailThreshold = 2                   // 连续失败 ≥ 此值且非可信设备才要求验证码
	deviceTrustThreshold = 3                   // 同设备成功登录 ≥ 此值即视为可信设备
	deviceTrustTTL       = 30 * 24 * time.Hour // 可信设备有效期
)

// AuthHandler 是认证 API 处理器
type AuthHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	secret []byte // JWT 密钥

	// JWT 黑名单（批4，默认关）：登出时把 token jti 写 Redis，AuthMiddleware 校验，
	// 实现"注销/禁用即失效"。未启用时 token 仍在签发有效期内不可吊销。
	redis            *redis.Client
	blacklistEnabled bool
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(db *gorm.DB, logger *zap.Logger, secret []byte) *AuthHandler {
	return &AuthHandler{
		db:     db,
		logger: logger,
		secret: secret,
	}
}

// EnableJWTBlacklist 启用登出 JWT 黑名单（需 Redis）。rdb 为 nil 时不启用。
func (h *AuthHandler) EnableJWTBlacklist(rdb *redis.Client) {
	h.redis = rdb
	h.blacklistEnabled = rdb != nil
}

// jwtBlacklistKey 返回 jti 在 Redis 黑名单中的 key。
func jwtBlacklistKey(jti string) string {
	return "jwt:bl:" + jti
}

// isTokenBlacklisted 查 token jti 是否已登出。Redis 抖动时 fail-open（放行），避免锁死全站。
func (h *AuthHandler) isTokenBlacklisted(c *gin.Context, jti string) bool {
	if !h.blacklistEnabled || h.redis == nil || jti == "" {
		return false
	}
	n, err := h.redis.Exists(c.Request.Context(), jwtBlacklistKey(jti)).Result()
	if err != nil {
		h.logger.Warn("查询 JWT 黑名单失败，放行", zap.Error(err))
		return false
	}
	return n > 0
}

// LoginRequest 登录请求
// CaptchaID/CaptchaCode 改为可选：仅在风控判定需要验证码时才校验。
type LoginRequest struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
	DeviceID    string `json:"device_id"` // 浏览器本地生成的设备标识，用于可信设备判定
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

// Claims JWT Claims
//
// v2.0 加入 TenantID / IsPlatformAdmin 字段以支持多租户。
// 旧版 token（仅 Username / Role）解析后 TenantID 自动回填 model.DefaultTenantID，
// 保证升级期间已下发的 token 仍然有效。
type Claims struct {
	Username        string `json:"username"`
	Role            string `json:"role"`
	TenantID        string `json:"tenant_id,omitempty"`
	IsPlatformAdmin bool   `json:"is_platform_admin,omitempty"`
	jwt.RegisteredClaims
}

// GetCaptcha 生成图形验证码
// GET /api/v1/auth/captcha
func (h *AuthHandler) GetCaptcha(c *gin.Context) {
	driver := base64Captcha.NewDriverDigit(80, 240, 5, 0.7, 80)
	captcha := base64Captcha.NewCaptcha(driver, captchaStore)
	id, b64s, _, err := captcha.Generate()
	if err != nil {
		h.logger.Error("生成验证码失败", zap.Error(err))
		InternalError(c, "生成验证码失败")
		return
	}
	Success(c, gin.H{
		"captcha_id":    id,
		"captcha_image": b64s,
	})
}

// Login 用户登录
// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 风控：可信设备或近期无失败时免验证码；非可信设备且连续失败达阈值才要求验证码。
	if h.loginNeedsCaptcha(req.Username, req.DeviceID) {
		if !captchaStore.Verify(req.CaptchaID, req.CaptchaCode, true) {
			// 统一响应封装；data.need_captcha 告知前端展示验证码框
			BadRequestWithData(c, "验证码错误或已过期", gin.H{"need_captcha": true})
			return
		}
	}

	// 从数据库查询用户
	var user model.User
	if err := h.db.Where("username = ? AND status = ?", req.Username, model.UserStatusActive).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			Unauthorized(c, "用户名或密码错误")
			return
		}
		h.logger.Error("查询用户失败", zap.Error(err))
		InternalError(c, "登录失败")
		return
	}

	// 检查账户是否被锁定
	if user.LockedUntil != nil && time.Now().Before(time.Time(*user.LockedUntil)) {
		TooManyRequests(c, "账户已被临时锁定，请稍后再试")
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		// 登录失败，递增失败计数
		user.LoginFailCount++
		if user.LoginFailCount >= maxLoginFailCount {
			lockedUntil := model.LocalTime(time.Now().Add(lockDuration))
			user.LockedUntil = &lockedUntil
			h.logger.Warn("用户登录失败次数过多，账户已锁定",
				zap.String("username", user.Username),
				zap.String("ip", c.ClientIP()),
				zap.Duration("lock_duration", lockDuration),
			)
		}
		h.db.Select("login_fail_count", "locked_until").Save(&user)

		Unauthorized(c, "用户名或密码错误")
		return
	}

	// 登录成功，重置失败计数
	user.LoginFailCount = 0
	user.LockedUntil = nil
	loginTime := model.Now()
	user.LastLogin = &loginTime
	if err := h.db.Select("login_fail_count", "locked_until", "last_login").Save(&user).Error; err != nil {
		h.logger.Warn("更新登录状态失败", zap.Error(err))
	}

	// 记录可信设备：累加该设备成功登录次数（达阈值后免验证码）
	h.recordDeviceSuccess(user.Username, req.DeviceID)

	// 生成 JWT Token
	now := time.Now()
	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}
	claims := Claims{
		Username:        user.Username,
		Role:            string(user.Role),
		TenantID:        tenantID,
		IsPlatformAdmin: user.IsPlatformAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   user.Username,
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(h.secret)
	if err != nil {
		h.logger.Error("生成Token失败", zap.Error(err))
		InternalError(c, "登录失败")
		return
	}

	Success(c, gin.H{
		"token": tokenString,
		"user": gin.H{
			"username": user.Username,
			"role":     string(user.Role),
		},
		"need_change_password": user.ForceChangePassword,
	})
}

// Logout 用户登出
// POST /api/v1/auth/logout
//
// JWT 无状态，登出本质是客户端删 token。启用黑名单后额外把 token jti 写 Redis
// （TTL=剩余有效期），令该 token 在到期前即失效，避免登出后 token 仍可用。
func (h *AuthHandler) Logout(c *gin.Context) {
	if h.blacklistEnabled && h.redis != nil {
		if tok, err := extractBearerToken(c); err == nil {
			if claims, err := h.parseToken(tok); err == nil && claims.ID != "" && claims.ExpiresAt != nil {
				ttl := time.Until(claims.ExpiresAt.Time)
				if ttl > 0 {
					if err := h.redis.Set(c.Request.Context(), jwtBlacklistKey(claims.ID), "1", ttl).Err(); err != nil {
						h.logger.Warn("写入 JWT 黑名单失败", zap.Error(err))
					}
				}
			}
		}
	}
	SuccessMessage(c, "登出成功")
}

// extractBearerToken 从 Authorization Header 中提取 Bearer Token
// 严格要求 "Bearer " 前缀，不匹配时返回错误
func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	return token, nil
}

// parseToken 解析并验证 JWT Token，严格检查签名算法为 HS256
func (h *AuthHandler) parseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 严格检查签名算法，防止 Algorithm Confusion Attack
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}
	// 验证 issuer
	if claims.Issuer != jwtIssuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	return claims, nil
}

// GetCurrentUser 获取当前用户信息
// GET /api/v1/auth/me
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	tokenString, err := extractBearerToken(c)
	if err != nil {
		Unauthorized(c, "未授权")
		return
	}

	claims, err := h.parseToken(tokenString)
	if err != nil {
		Unauthorized(c, "Token无效")
		return
	}

	Success(c, gin.H{
		"username": claims.Username,
		"role":     claims.Role,
	})
}

// AuthMiddleware JWT 认证中间件
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := extractBearerToken(c)
		if err != nil {
			UnauthorizedExpired(c, "未授权，请重新登录")
			c.Abort()
			return
		}

		claims, err := h.parseToken(tokenString)
		if err != nil {
			UnauthorizedExpired(c, "登录已过期，请重新登录")
			c.Abort()
			return
		}

		// JWT 黑名单：登出/被禁用的 token 即使未到期也拒绝。
		if h.isTokenBlacklisted(c, claims.ID) {
			UnauthorizedExpired(c, "登录已失效，请重新登录")
			c.Abort()
			return
		}

		// 将用户信息存储到上下文
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		// v2.0: 注入租户身份。旧 token 缺 TenantID 时回填默认租户，
		// 升级期间已下发的 token 仍然有效；新 token 走正常 claims 路径。
		tid := claims.TenantID
		if tid == "" {
			tid = model.DefaultTenantID
		}
		tenant.SetIdentity(c, tenant.Identity{
			ID:              tid,
			IsPlatformAdmin: claims.IsPlatformAdmin,
		})

		c.Next()
	}
}

// RoleMiddleware 角色权限中间件，限制只有指定角色可以访问
// 必须在 AuthMiddleware 之后使用（依赖 context 中的 "role" 字段）
func RoleMiddleware(allowedRoles ...string) gin.HandlerFunc {
	roleSet := make(map[string]struct{}, len(allowedRoles))
	for _, r := range allowedRoles {
		roleSet[r] = struct{}{}
	}
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			Forbidden(c, "权限不足")
			c.Abort()
			return
		}
		if _, ok := roleSet[role.(string)]; !ok {
			Forbidden(c, "权限不足，需要管理员角色")
			c.Abort()
			return
		}
		c.Next()
	}
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ChangePassword 修改当前用户密码
// POST /api/v1/auth/change-password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	// 从上下文获取用户名
	username, exists := c.Get("username")
	if !exists {
		Unauthorized(c, "未授权")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 查询用户
	var user model.User
	if err := h.db.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "用户不存在")
			return
		}
		h.logger.Error("查询用户失败", zap.Error(err))
		InternalError(c, "修改密码失败")
		return
	}

	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		BadRequest(c, "旧密码错误")
		return
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("加密密码失败", zap.Error(err))
		InternalError(c, "修改密码失败")
		return
	}

	// 更新密码并清除强制改密标记
	user.Password = string(hashedPassword)
	user.ForceChangePassword = false
	if err := h.db.Select("password", "force_change_password").Save(&user).Error; err != nil {
		h.logger.Error("更新密码失败", zap.Error(err))
		InternalError(c, "修改密码失败")
		return
	}

	SuccessMessage(c, "密码修改成功")
}
