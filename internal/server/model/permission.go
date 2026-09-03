// Package model 提供数据库模型定义
package model

import (
	"strings"
	"time"
)

// Role 自定义角色（内置角色不入此表，名称取自 BuiltinRoles）。
type Role struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Code      string    `gorm:"column:code;type:varchar(20);uniqueIndex;not null" json:"code"`
	Name      string    `gorm:"column:name;type:varchar(100);not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (Role) TableName() string { return "roles" }

// Action 权限动作。一个模块按动作细分权限（看/改/处置）。
type Action string

const (
	ActionView    Action = "view"    // 查看 / 列表
	ActionManage  Action = "manage"  // 增删改 / 配置
	ActionRespond Action = "respond" // 处置（告警解决/忽略、主机隔离、病毒隔离等）
)

// ModuleDef 功能模块定义及其支持的动作。前端 RBAC 矩阵据此渲染「模块 × 动作」。
type ModuleDef struct {
	Code    string   `json:"code"`
	Name    string   `json:"name"`
	Actions []Action `json:"actions"`
}

// Modules 全部功能模块（单一来源：权限枚举、seed、前端矩阵、菜单共用）。
var Modules = []ModuleDef{
	{"dashboard", "安全概览", []Action{ActionView}},
	{"assets", "资产中心", []Action{ActionView, ActionManage}},
	{"alerts", "告警中心", []Action{ActionView, ActionRespond, ActionManage}},
	{"vuln", "漏洞管理", []Action{ActionView, ActionManage}},
	{"baseline", "基线安全", []Action{ActionView, ActionManage}},
	{"fim", "文件完整性", []Action{ActionView, ActionManage}},
	{"virus", "病毒查杀", []Action{ActionView, ActionRespond, ActionManage}},
	{"kube", "容器集群", []Action{ActionView, ActionManage}},
	{"detection", "威胁检测", []Action{ActionView, ActionManage}},
	{"operations", "运维中心", []Action{ActionView, ActionManage}},
	{"monitoring", "系统监控", []Action{ActionView, ActionManage}},
	{"audit_log", "审计日志", []Action{ActionView}},
	{"user_manage", "用户管理", []Action{ActionView, ActionManage}},
	{"system_config", "系统设置", []Action{ActionView, ActionManage}},
}

// Perm 拼 "module:action" 权限码。
func Perm(module string, a Action) string { return module + ":" + string(a) }

// SplitPerm 拆 "module:action"。无冒号时 action 为空。
func SplitPerm(code string) (module string, action string) {
	if i := strings.IndexByte(code, ':'); i >= 0 {
		return code[:i], code[i+1:]
	}
	return code, ""
}

// ModuleCodes 14 个模块码（菜单/模块枚举用）。
var ModuleCodes = func() []string {
	out := make([]string, 0, len(Modules))
	for _, m := range Modules {
		out = append(out, m.Code)
	}
	return out
}()

// AllPermCodes 全部 "module:action" 权限码（admin 拥有全部 / 内置 seed 用）。
var AllPermCodes = func() []string {
	var out []string
	for _, m := range Modules {
		for _, a := range m.Actions {
			out = append(out, Perm(m.Code, a))
		}
	}
	return out
}()

// moduleActions module → 其支持的动作集（O(1) 查）。
var moduleActions = func() map[string][]Action {
	m := make(map[string][]Action, len(Modules))
	for _, md := range Modules {
		m[md.Code] = md.Actions
	}
	return m
}()

// ModuleHasAction 模块是否支持某动作。
func ModuleHasAction(module string, a Action) bool {
	for _, x := range moduleActions[module] {
		if x == a {
			return true
		}
	}
	return false
}

// Permission 权限定义（permissions 表，存 module:action 元数据）。
type Permission struct {
	ID          uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Code        string `gorm:"column:code;type:varchar(60);uniqueIndex;not null" json:"code"`
	Name        string `gorm:"column:name;type:varchar(100);not null" json:"name"`
	Module      string `gorm:"column:module;type:varchar(50)" json:"module"`
	Description string `gorm:"column:description;type:varchar(500)" json:"description"`
}

func (Permission) TableName() string { return "permissions" }

// RolePermission 角色-权限关联（perm_code = module:action）。
type RolePermission struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	RoleCode string `gorm:"column:role_code;type:varchar(20);not null;index:idx_role_perm,unique" json:"role_code"`
	PermCode string `gorm:"column:perm_code;type:varchar(60);not null;index:idx_role_perm,unique" json:"perm_code"`
}

func (RolePermission) TableName() string { return "role_permissions" }

// --- 内置角色 ---

// BuiltinRole 内置角色定义：商业级 CWPP 的标准角色划分。
type BuiltinRole struct {
	Code        string
	Name        string
	Permissions []string // module:action 码集
}

// perms 构造工具：viewOnly(给若干模块只读 view)，rw(view+manage)，full(view+manage+respond)。
func viewOf(modules ...string) []string {
	out := make([]string, 0, len(modules))
	for _, m := range modules {
		out = append(out, Perm(m, ActionView))
	}
	return out
}

func rwOf(modules ...string) []string {
	out := make([]string, 0, len(modules)*2)
	for _, m := range modules {
		out = append(out, Perm(m, ActionView), Perm(m, ActionManage))
	}
	return out
}

func join(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// allViewCodes 所有模块的 view 码（审计员：全量只读可见）。
func allViewCodes() []string {
	out := make([]string, 0, len(Modules))
	for _, m := range Modules {
		out = append(out, Perm(m.Code, ActionView))
	}
	return out
}

// BuiltinRoles 内置角色单一来源：seed、角色枚举、只读判定共用。
var BuiltinRoles = []BuiltinRole{
	{Code: "admin", Name: "平台超管", Permissions: AllPermCodes},
	{Code: "security_admin", Name: "安全管理员", Permissions: join(
		viewOf("dashboard"),
		rwOf("assets", "baseline", "fim", "kube", "detection", "monitoring"),
		[]string{Perm("alerts", ActionView), Perm("alerts", ActionRespond), Perm("alerts", ActionManage)},
		[]string{Perm("virus", ActionView), Perm("virus", ActionRespond), Perm("virus", ActionManage)},
		rwOf("vuln"),
		viewOf("audit_log"),
	)},
	{Code: "analyst", Name: "安全分析师", Permissions: join(
		viewOf("dashboard", "assets", "monitoring", "audit_log"),
		[]string{Perm("alerts", ActionView), Perm("alerts", ActionRespond)}, // 看 + 处置告警，不改告警策略
		[]string{Perm("virus", ActionView), Perm("virus", ActionRespond)},
		rwOf("vuln"),
	)},
	{Code: "ops", Name: "运维", Permissions: join(
		viewOf("dashboard", "monitoring"),
		rwOf("assets", "operations", "vuln", "baseline"),
	)},
	{Code: "auditor", Name: "审计员", Permissions: allViewCodes()}, // 全量只读
	{Code: "viewer", Name: "只读用户", Permissions: viewOf("dashboard", "assets", "alerts", "vuln")},
}

// IsReadOnlyRole 角色是否只读（不含任何 manage/respond 权限）。由权限集推导，
// 不再单独维护标志。admin 例外（全权，非只读）。
func IsReadOnlyRole(role string) bool {
	if role == string(UserRoleAdmin) {
		return false
	}
	for _, r := range BuiltinRoles {
		if r.Code == role {
			for _, p := range r.Permissions {
				if _, a := SplitPerm(p); a == string(ActionManage) || a == string(ActionRespond) {
					return false
				}
			}
			return true
		}
	}
	// 自定义角色：调用方应基于实际 role_permissions 判定；此处保守返回 false。
	return false
}

// BuiltinRoleName 返回内置角色显示名，非内置返回空串。
func BuiltinRoleName(code string) string {
	for _, r := range BuiltinRoles {
		if r.Code == code {
			return r.Name
		}
	}
	return ""
}
