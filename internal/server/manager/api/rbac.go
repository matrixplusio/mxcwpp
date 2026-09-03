// Package api 提供 HTTP API 处理器
package api

import (
	"regexp"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
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

// actionDisplayName 动作中文名。
var actionDisplayName = map[model.Action]string{
	model.ActionView:    "查看",
	model.ActionManage:  "管理",
	model.ActionRespond: "处置",
}

// ListPermissions 返回「模块 × 动作」权限矩阵定义，供前端 RBAC 页渲染。
// GET /api/v1/rbac/permissions
func (h *RBACHandler) ListPermissions(c *gin.Context) {
	type actionInfo struct {
		Code string `json:"code"` // module:action
		Name string `json:"name"`
	}
	type moduleInfo struct {
		Code    string       `json:"code"`
		Name    string       `json:"name"`
		Actions []actionInfo `json:"actions"`
	}
	out := make([]moduleInfo, 0, len(model.Modules))
	for _, m := range model.Modules {
		mi := moduleInfo{Code: m.Code, Name: m.Name}
		for _, a := range m.Actions {
			mi.Actions = append(mi.Actions, actionInfo{Code: model.Perm(m.Code, a), Name: actionDisplayName[a]})
		}
		out = append(out, mi)
	}
	Success(c, out)
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

	// 验证权限码有效性（module:action）
	validCodes := make(map[string]bool)
	for _, code := range model.AllPermCodes {
		validCodes[code] = true
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
	// 角色码来源：内置角色（固定顺序）+ user + role_permissions 中的其他自定义角色。
	roleCodes := make([]string, 0, len(model.BuiltinRoles)+4)
	seen := map[string]bool{}
	for _, r := range model.BuiltinRoles {
		roleCodes = append(roleCodes, r.Code)
		seen[r.Code] = true
	}
	if !seen["user"] {
		roleCodes = append(roleCodes, "user")
		seen["user"] = true
	}
	// 自定义角色（roles 表，含显示名）
	var custom []model.Role
	h.db.Order("id ASC").Find(&custom)
	customName := map[string]string{}
	for _, r := range custom {
		customName[r.Code] = r.Name
		if !seen[r.Code] {
			roleCodes = append(roleCodes, r.Code)
			seen[r.Code] = true
		}
	}
	// 兜底：role_permissions 里出现但未登记的 role_code
	var dbRoles []string
	h.db.Model(&model.RolePermission{}).Distinct("role_code").Pluck("role_code", &dbRoles)
	for _, r := range dbRoles {
		if !seen[r] {
			roleCodes = append(roleCodes, r)
			seen[r] = true
		}
	}

	type roleInfo struct {
		Code        string   `json:"code"`
		Name        string   `json:"name"`
		ReadOnly    bool     `json:"read_only"`
		Builtin     bool     `json:"builtin"`
		Permissions []string `json:"permissions"`
	}

	var roles []roleInfo
	for _, code := range roleCodes {
		var permCodes []string
		h.db.Model(&model.RolePermission{}).
			Where("role_code = ?", code).
			Pluck("perm_code", &permCodes)

		name := model.BuiltinRoleName(code)
		builtin := name != ""
		if name == "" {
			name = customName[code]
		}
		if code == "user" && name == "" {
			name = "普通用户"
		}
		if name == "" {
			name = code
		}

		roles = append(roles, roleInfo{
			Code:        code,
			Name:        name,
			ReadOnly:    permsReadOnly(code, permCodes),
			Builtin:     builtin,
			Permissions: permCodes,
		})
	}

	Success(c, roles)
}

// permsReadOnly 角色是否只读：不含任何 manage/respond 权限（admin 例外）。
func permsReadOnly(code string, permCodes []string) bool {
	if code == "admin" {
		return false
	}
	for _, p := range permCodes {
		if _, a := model.SplitPerm(p); a == string(model.ActionManage) || a == string(model.ActionRespond) {
			return false
		}
	}
	return true
}

var roleCodeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,19}$`)

// CreateRoleRequest 新建自定义角色。
type CreateRoleRequest struct {
	Code        string   `json:"code" binding:"required"`
	Name        string   `json:"name" binding:"required,min=1,max=100"`
	Permissions []string `json:"permissions"`
}

// CreateRole 新建自定义角色。
// POST /api/v1/rbac/roles
func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	if !roleCodeRe.MatchString(req.Code) {
		BadRequest(c, "角色码须以小写字母开头，仅含小写字母/数字/下划线，2-20 位")
		return
	}
	if req.Code == "admin" || req.Code == "user" || model.BuiltinRoleName(req.Code) != "" {
		BadRequest(c, "角色码与内置角色冲突")
		return
	}
	var existing int64
	h.db.Model(&model.Role{}).Where("code = ?", req.Code).Count(&existing)
	if existing > 0 {
		BadRequest(c, "角色已存在")
		return
	}
	valid := make(map[string]bool, len(model.AllPermCodes))
	for _, code := range model.AllPermCodes {
		valid[code] = true
	}
	for _, p := range req.Permissions {
		if !valid[p] {
			BadRequest(c, "无效的权限码: "+p)
			return
		}
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&model.Role{Code: req.Code, Name: req.Name}).Error; err != nil {
			return err
		}
		for _, p := range req.Permissions {
			if err := tx.Create(&model.RolePermission{RoleCode: req.Code, PermCode: p}).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.logger.Error("创建角色失败", zap.String("role", req.Code), zap.Error(err))
		InternalError(c, "创建失败")
		return
	}
	ReloadGlobalResolver()
	h.logger.Info("自定义角色已创建", zap.String("role", req.Code), zap.String("name", req.Name))
	SuccessWithMessage(c, "创建成功", gin.H{"code": req.Code, "name": req.Name})
}

// DeleteRole 删除自定义角色（内置角色不可删；仍有用户使用时拒绝）。
// DELETE /api/v1/rbac/roles/:role
func (h *RBACHandler) DeleteRole(c *gin.Context) {
	code := c.Param("role")
	if code == "admin" || code == "user" || model.BuiltinRoleName(code) != "" {
		BadRequest(c, "不可删除内置角色")
		return
	}
	var inUse int64
	h.db.Model(&model.User{}).Where("role = ?", code).Count(&inUse)
	if inUse > 0 {
		BadRequest(c, "仍有用户使用该角色，无法删除")
		return
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("code = ?", code).Delete(&model.Role{}).Error; err != nil {
			return err
		}
		return tx.Where("role_code = ?", code).Delete(&model.RolePermission{}).Error
	}); err != nil {
		h.logger.Error("删除角色失败", zap.String("role", code), zap.Error(err))
		InternalError(c, "删除失败")
		return
	}
	ReloadGlobalResolver()
	h.logger.Info("自定义角色已删除", zap.String("role", code))
	SuccessMessage(c, "删除成功")
}
