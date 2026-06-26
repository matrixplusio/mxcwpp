// Package model 提供数据库模型定义
package model

import (
	"path/filepath"
	"strings"
)

// AlertWhitelist 告警白名单模型
// 匹配规则：各字段为空或"*"表示匹配所有，非空则精确匹配。
// SourceIPCIDR 是非告警维度的扩展字段，用于 ScanDetector 等需要按
// 源 IP 段豁免的检测器（如 k8s/GKE node pool 健康探测）。
// Exe/Cmdline 维度供 CEL/EDR 告警路径按进程/命令行豁免（P2-B 自动调优采纳的 exception）。
type AlertWhitelist struct {
	TenantID     string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name         string    `gorm:"column:name;type:varchar(100);not null" json:"name"`           // 白名单描述名称
	RuleID       string    `gorm:"column:rule_id;type:varchar(64)" json:"rule_id"`               // 空或*表示匹配所有规则
	HostID       string    `gorm:"column:host_id;type:varchar(64)" json:"host_id"`               // 空或*表示匹配所有主机
	Category     string    `gorm:"column:category;type:varchar(50)" json:"category"`             // 空或*表示匹配所有类别
	Severity     string    `gorm:"column:severity;type:varchar(20)" json:"severity"`             // 空或*表示匹配所有级别
	Exe          string    `gorm:"column:exe;type:varchar(255)" json:"exe"`                      // 进程 basename，空表示不约束；CEL 路径按 exe/comm basename 匹配
	Cmdline      string    `gorm:"column:cmdline;type:varchar(500)" json:"cmdline"`              // 命令行子串，空表示不约束；CEL 路径按 cmdline 包含匹配
	SourceIPCIDR string    `gorm:"column:source_ip_cidr;type:varchar(64)" json:"source_ip_cidr"` // 源 IP CIDR（如 10.170.2.0/24），供 ScanDetector 等使用
	Reason       string    `gorm:"column:reason;type:text" json:"reason"`                        // 加入白名单的原因
	CreatedBy    string    `gorm:"column:created_by;type:varchar(100)" json:"created_by"`        // 创建人
	CreatedAt    LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt    LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (AlertWhitelist) TableName() string {
	return "alert_whitelists"
}

// Matches 判断白名单条目是否匹配告警
func (w *AlertWhitelist) Matches(ruleID, hostID, category, severity string) bool {
	if !matchField(w.RuleID, ruleID) {
		return false
	}
	if !matchField(w.HostID, hostID) {
		return false
	}
	if !matchField(w.Category, category) {
		return false
	}
	if !matchField(w.Severity, severity) {
		return false
	}
	return true
}

// matchField 判断白名单字段是否匹配目标值（空或"*"匹配所有）
func matchField(whitelistVal, targetVal string) bool {
	if whitelistVal == "" || whitelistVal == "*" {
		return true
	}
	return whitelistVal == targetVal
}

// MatchesAlert 在 CEL/EDR 告警路径判断白名单是否命中（在 Matches 基础上增加 exe/cmdline 维度）。
//
// fields 为告警事件字段（exe/comm/cmdline 等）。匹配语义：
//   - rule/host/category/severity 沿用 matchField（空或"*"匹配所有）。
//   - exe：按 basename 匹配 fields["exe"]（兼容 agent 的 comm）。
//   - cmdline：按子串包含匹配 fields["cmdline"]（大小写不敏感）。
//
// 安全约束：必须至少有 host/exe/cmdline 之一为具体值，否则视为不命中。
// 防止仅按 rule/category 的宽泛条目把整类告警全部抑制（错抑制风险高于漏抑制）。
func (w *AlertWhitelist) MatchesAlert(ruleID, hostID, category, severity string, fields map[string]string) bool {
	if !w.hasConcreteNarrowing() {
		return false
	}
	if !w.Matches(ruleID, hostID, category, severity) {
		return false
	}
	if !matchExeBasename(w.Exe, fields) {
		return false
	}
	if !matchCmdlineContains(w.Cmdline, fields["cmdline"]) {
		return false
	}
	return true
}

// hasConcreteNarrowing 判断条目是否至少约束了 host/exe/cmdline 之一（防全通配误抑制）。
func (w *AlertWhitelist) hasConcreteNarrowing() bool {
	return isConcrete(w.HostID) || isConcrete(w.Exe) || isConcrete(w.Cmdline)
}

func isConcrete(v string) bool {
	return v != "" && v != "*"
}

// matchExeBasename 按 basename 匹配 exe（空白名单值=不约束；兼容 fields["comm"]）。
func matchExeBasename(wlExe string, fields map[string]string) bool {
	if !isConcrete(wlExe) {
		return true
	}
	exe := fields["exe"]
	if exe == "" {
		exe = fields["comm"]
	}
	if exe == "" {
		return false
	}
	return strings.EqualFold(filepath.Base(exe), filepath.Base(wlExe))
}

// matchCmdlineContains 按子串包含匹配 cmdline（空白名单值=不约束；大小写不敏感）。
func matchCmdlineContains(wlCmdline, cmdline string) bool {
	if !isConcrete(wlCmdline) {
		return true
	}
	if cmdline == "" {
		return false
	}
	return strings.Contains(strings.ToLower(cmdline), strings.ToLower(wlCmdline))
}
