// Package api 提供 HTTP API 处理器
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// UsersHandler 是用户管理 API 处理器
type UsersHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewUsersHandler 创建用户管理处理器
func NewUsersHandler(db *gorm.DB, logger *zap.Logger) *UsersHandler {
	return &UsersHandler{
		db:     db,
		logger: logger,
	}
}

// ListUsersRequest 用户列表请求
type ListUsersRequest struct {
	Page     int    `form:"page" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Username string `form:"username"`
	Role     string `form:"role"`
	Status   string `form:"status"`
}

// ListUsersResponse 用户列表响应
type ListUsersResponse struct {
	Total int64        `json:"total"`
	Items []model.User `json:"items"`
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=64"`
	Password string `json:"password" binding:"required,min=8"`
	Email    string `json:"email" binding:"omitempty,email"`
	// 角色不再写死 admin/user：内置二者 + 任意已在 role_permissions 中定义的自定义角色
	// (如 auditor)，存在性在 handler 内用 roleExists 校验。
	Role   string `json:"role" binding:"required"`
	Status string `json:"status" binding:"omitempty,oneof=active inactive"`
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Password string `json:"password" binding:"omitempty,min=8"`
	Email    string `json:"email" binding:"omitempty,email"`
	Role     string `json:"role" binding:"omitempty"`
	Status   string `json:"status" binding:"omitempty,oneof=active inactive"`
}

// ListUsers 获取用户列表
// GET /api/v1/users
func (h *UsersHandler) ListUsers(c *gin.Context) {
	var req ListUsersRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 设置默认值
	if req.Page == 0 {
		req.Page = 1
	}
	if req.PageSize == 0 {
		req.PageSize = 20
	}

	// 构建查询
	query := h.db.Model(&model.User{})

	if req.Username != "" {
		query = query.Where("username LIKE ?", "%"+req.Username+"%")
	}
	if req.Role != "" {
		query = query.Where("role = ?", req.Role)
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}

	// 获取总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询用户总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 分页查询
	var users []model.User
	offset := (req.Page - 1) * req.PageSize
	if err := query.Offset(offset).Limit(req.PageSize).Order("created_at DESC").Find(&users).Error; err != nil {
		h.logger.Error("查询用户列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	SuccessPaginated(c, total, users)
}

// GetUser 获取用户详情
// GET /api/v1/users/:id
func (h *UsersHandler) GetUser(c *gin.Context) {
	var user model.User
	if err := h.db.First(&user, c.Param("id")).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "用户不存在")
			return
		}
		h.logger.Error("查询用户失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, user)
}

// CreateUser 创建用户
// POST /api/v1/users
// roleExists 校验角色可用: 内置 admin/user 或已在 role_permissions 中定义的自定义角色 (如 auditor)。
func (h *UsersHandler) roleExists(role string) bool {
	if role == string(model.UserRoleAdmin) || role == string(model.UserRoleUser) {
		return true
	}
	var n int64
	h.db.Model(&model.RolePermission{}).Where("role_code = ?", role).Count(&n)
	return n > 0
}

func (h *UsersHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if !h.roleExists(req.Role) {
		BadRequest(c, "角色不存在: "+req.Role)
		return
	}

	// 检查用户名是否已存在
	var existingUser model.User
	if err := h.db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		BadRequest(c, "用户名已存在")
		return
	} else if err != gorm.ErrRecordNotFound {
		h.logger.Error("查询用户失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("加密密码失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	// 设置默认状态
	status := model.UserStatusActive
	if req.Status != "" {
		status = model.UserStatus(req.Status)
	}

	// 创建用户
	user := &model.User{
		Username: req.Username,
		Password: string(hashedPassword),
		Email:    req.Email,
		Role:     model.UserRole(req.Role),
		Status:   status,
	}

	if err := h.db.Create(user).Error; err != nil {
		h.logger.Error("创建用户失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	SuccessWithMessage(c, "创建成功", user)
}

// UpdateUser 更新用户
// PUT /api/v1/users/:id
func (h *UsersHandler) UpdateUser(c *gin.Context) {
	var user model.User
	if err := h.db.First(&user, c.Param("id")).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "用户不存在")
			return
		}
		h.logger.Error("查询用户失败", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 更新密码（如果提供）
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			h.logger.Error("加密密码失败", zap.Error(err))
			InternalError(c, "更新失败")
			return
		}
		user.Password = string(hashedPassword)
	}

	// 更新其他字段
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		if !h.roleExists(req.Role) {
			BadRequest(c, "角色不存在: "+req.Role)
			return
		}
		user.Role = model.UserRole(req.Role)
	}
	if req.Status != "" {
		user.Status = model.UserStatus(req.Status)
	}

	if err := h.db.Save(&user).Error; err != nil {
		h.logger.Error("更新用户失败", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	SuccessWithMessage(c, "更新成功", user)
}

// DeleteUser 删除用户
// DELETE /api/v1/users/:id
func (h *UsersHandler) DeleteUser(c *gin.Context) {
	var user model.User
	if err := h.db.First(&user, c.Param("id")).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "用户不存在")
			return
		}
		h.logger.Error("查询用户失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	// 不能删除自己
	currentUsername, _ := c.Get("username")
	if user.Username == currentUsername {
		BadRequest(c, "不能删除当前登录用户")
		return
	}

	if err := h.db.Delete(&user).Error; err != nil {
		h.logger.Error("删除用户失败", zap.Error(err))
		InternalError(c, "删除失败")
		return
	}

	SuccessMessage(c, "删除成功")
}
