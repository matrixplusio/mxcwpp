// Package model 提供数据库模型定义
package model

// PermissionCode 权限码
type PermissionCode string

// 权限码常量 — 每个值对应一个可配置的功能模块访问权限
const (
	PermDashboard    PermissionCode = "dashboard"     // 安全概览
	PermAssets       PermissionCode = "assets"        // 资产中心
	PermAlerts       PermissionCode = "alerts"        // 告警中心
	PermBaseline     PermissionCode = "baseline"      // 基线安全
	PermFIM          PermissionCode = "fim"           // 文件完整性
	PermVirus        PermissionCode = "virus"         // 病毒查杀
	PermVuln         PermissionCode = "vuln"          // 漏洞管理
	PermKube         PermissionCode = "kube"          // 容器集群
	PermDetection    PermissionCode = "detection"     // 威胁检测
	PermMonitoring   PermissionCode = "monitoring"    // 系统监控
	PermOperations   PermissionCode = "operations"    // 运维中心
	PermAuditLog     PermissionCode = "audit_log"     // 审计日志
	PermUserManage   PermissionCode = "user_manage"   // 用户管理
	PermSystemConfig PermissionCode = "system_config" // 系统设置
)

// AllPermissionCodes 返回所有权限码（admin 角色默认拥有全部）
var AllPermissionCodes = []PermissionCode{
	PermDashboard, PermAssets, PermAlerts, PermBaseline,
	PermFIM, PermVirus, PermVuln, PermKube,
	PermDetection, PermMonitoring, PermOperations, PermAuditLog,
	PermUserManage, PermSystemConfig,
}

// Permission 权限定义
type Permission struct {
	ID          uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	Code        PermissionCode `gorm:"column:code;type:varchar(50);uniqueIndex;not null" json:"code"`
	Name        string         `gorm:"column:name;type:varchar(100);not null" json:"name"`
	Module      string         `gorm:"column:module;type:varchar(50)" json:"module"`
	Description string         `gorm:"column:description;type:varchar(500)" json:"description"`
}

func (Permission) TableName() string { return "permissions" }

// RolePermission 角色-权限关联
type RolePermission struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	RoleCode string `gorm:"column:role_code;type:varchar(20);not null;index:idx_role_perm,unique" json:"role_code"`
	PermCode string `gorm:"column:perm_code;type:varchar(50);not null;index:idx_role_perm,unique" json:"perm_code"`
}

func (RolePermission) TableName() string { return "role_permissions" }

// BuiltinRole 内置角色定义：商业级 CWPP 的标准角色划分。
//
// 权限是模块级（拥有某模块即可读写该模块）。ReadOnly=true 的角色（审计员/只读用户）
// 的模块权限仅用于前端菜单可见性，后端对其拦截全部写操作（见 EnforceWritePermissions），
// 从而实现"全量可见、只读"。
type BuiltinRole struct {
	Code        string
	Name        string
	ReadOnly    bool
	Permissions []PermissionCode
}

// BuiltinRoles 内置角色单一来源：seed、角色枚举、只读判定共用。
var BuiltinRoles = []BuiltinRole{
	{Code: "admin", Name: "平台超管", ReadOnly: false, Permissions: AllPermissionCodes},
	{Code: "security_admin", Name: "安全管理员", ReadOnly: false, Permissions: []PermissionCode{
		PermDashboard, PermAssets, PermAlerts, PermBaseline, PermFIM,
		PermVirus, PermVuln, PermKube, PermDetection, PermMonitoring, PermAuditLog,
	}},
	{Code: "analyst", Name: "安全分析师", ReadOnly: false, Permissions: []PermissionCode{
		PermDashboard, PermAssets, PermAlerts, PermVuln, PermMonitoring, PermAuditLog,
	}},
	{Code: "ops", Name: "运维", ReadOnly: false, Permissions: []PermissionCode{
		PermDashboard, PermAssets, PermOperations, PermVuln, PermMonitoring, PermBaseline,
	}},
	{Code: "auditor", Name: "审计员", ReadOnly: true, Permissions: AllPermissionCodes},
	{Code: "viewer", Name: "只读用户", ReadOnly: true, Permissions: []PermissionCode{
		PermDashboard, PermAssets, PermAlerts, PermVuln,
	}},
}

var readOnlyRoleSet = func() map[string]bool {
	m := make(map[string]bool, len(BuiltinRoles))
	for _, r := range BuiltinRoles {
		if r.ReadOnly {
			m[r.Code] = true
		}
	}
	return m
}()

// IsReadOnlyRole 判断角色是否为只读角色（后端拦截其全部写操作）。
func IsReadOnlyRole(role string) bool { return readOnlyRoleSet[role] }

// BuiltinRoleName 返回内置角色显示名，非内置返回空串。
func BuiltinRoleName(code string) string {
	for _, r := range BuiltinRoles {
		if r.Code == code {
			return r.Name
		}
	}
	return ""
}
