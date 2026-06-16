// Package api 提供 HTTP API 处理器
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// RBACHandler 权限管理 API 处理器
type RBACHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewRBACHandler 创建权限管理处理器
func NewRBACHandler(db *gorm.DB, logger *zap.Logger) *RBACHandler {
	return &RBACHandler{db: db, logger: logger}
}

// ListPermissions 获取所有权限定义
// GET /api/v1/rbac/permissions
func (h *RBACHandler) ListPermissions(c *gin.Context) {
	var perms []model.Permission
	if err := h.db.Order("id ASC").Find(&perms).Error; err != nil {
		h.logger.Error("查询权限列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	Success(c, perms)
}

// GetRolePermissions 获取指定角色的权限码列表
// GET /api/v1/rbac/roles/:role/permissions
func (h *RBACHandler) GetRolePermissions(c *gin.Context) {
	roleCode := c.Param("role")
	if roleCode == "" {
		BadRequest(c, "角色不能为空")
		return
	}

	var permCodes []string
	h.db.Model(&model.RolePermission{}).
		Where("role_code = ?", roleCode).
		Pluck("perm_code", &permCodes)

	Success(c, gin.H{
		"role":        roleCode,
		"permissions": permCodes,
	})
}

// UpdateRolePermissionsRequest 更新角色权限请求
type UpdateRolePermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required"`
}

// UpdateRolePermissions 更新指定角色的权限
// PUT /api/v1/rbac/roles/:role/permissions
func (h *RBACHandler) UpdateRolePermissions(c *gin.Context) {
	roleCode := c.Param("role")
	if roleCode == "" {
		BadRequest(c, "角色不能为空")
		return
	}

	// 禁止修改 admin 角色权限
	if roleCode == "admin" {
		BadRequest(c, "不允许修改管理员角色权限")
		return
	}

	var req UpdateRolePermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 验证权限码有效性
	validCodes := make(map[string]bool)
	for _, code := range model.AllPermissionCodes {
		validCodes[string(code)] = true
	}
	for _, code := range req.Permissions {
		if !validCodes[code] {
			BadRequest(c, "无效的权限码: "+code)
			return
		}
	}

	// 事务：删除旧权限 → 插入新权限
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_code = ?", roleCode).Delete(&model.RolePermission{}).Error; err != nil {
			return err
		}
		for _, code := range req.Permissions {
			rp := model.RolePermission{RoleCode: roleCode, PermCode: code}
			if err := tx.Create(&rp).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.logger.Error("更新角色权限失败", zap.String("role", roleCode), zap.Error(err))
		InternalError(c, "更新失败")
		return
	}

	// 失效刷新权限缓存，使新授权立即对写操作放行判定生效。
	ReloadGlobalResolver()

	h.logger.Info("角色权限已更新", zap.String("role", roleCode), zap.Strings("permissions", req.Permissions))
	SuccessMessage(c, "权限更新成功")
}

// ListRoles 获取所有角色及其权限
// GET /api/v1/rbac/roles
func (h *RBACHandler) ListRoles(c *gin.Context) {
	// 获取所有角色码（从 role_permissions + 固定角色）
	roleCodes := []string{"admin", "user"}

	// 查找数据库中其他角色
	var dbRoles []string
	h.db.Model(&model.RolePermission{}).Distinct("role_code").Pluck("role_code", &dbRoles)
	seen := map[string]bool{"admin": true, "user": true}
	for _, r := range dbRoles {
		if !seen[r] {
			roleCodes = append(roleCodes, r)
			seen[r] = true
		}
	}

	type roleInfo struct {
		Code        string   `json:"code"`
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}

	roleNames := map[string]string{
		"admin": "管理员",
		"user":  "普通用户",
	}

	var roles []roleInfo
	for _, code := range roleCodes {
		var permCodes []string
		h.db.Model(&model.RolePermission{}).
			Where("role_code = ?", code).
			Pluck("perm_code", &permCodes)

		name := roleNames[code]
		if name == "" {
			name = code
		}

		roles = append(roles, roleInfo{
			Code:        code,
			Name:        name,
			Permissions: permCodes,
		})
	}

	Success(c, roles)
}
