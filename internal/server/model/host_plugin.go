// Package model 提供数据库模型定义
package model

import (
	"gorm.io/gorm"
)

// HostPluginStatus 主机插件状态
type HostPluginStatus string

const (
	HostPluginStatusRunning  HostPluginStatus = "running"  // 运行中
	HostPluginStatusStopped  HostPluginStatus = "stopped"  // 已停止
	HostPluginStatusError    HostPluginStatus = "error"    // 错误
	HostPluginStatusUpdating HostPluginStatus = "updating" // 更新中
	HostPluginStatusDormant  HostPluginStatus = "dormant"  // 依赖不可用，定期探测
)

// HostPlugin 主机插件状态表
// 记录每个主机上实际运行的插件版本和状态
type HostPlugin struct {
	TenantID  string           `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint             `gorm:"primaryKey" json:"id"`
	HostID    string           `gorm:"size:64;index;not null" json:"host_id"` // 主机 ID
	Name      string           `gorm:"size:64;not null" json:"name"`          // 插件名称
	Version   string           `gorm:"size:32" json:"version"`                // 实际运行的版本
	Status    HostPluginStatus `gorm:"size:32;default:running" json:"status"` // 插件状态
	StartTime *LocalTime       `json:"start_time,omitempty"`                  // 启动时间
	UpdatedAt LocalTime        `json:"updated_at"`                            // 更新时间
	DeletedAt gorm.DeletedAt   `gorm:"index" json:"-"`                        // 软删除

	// 关联
	Host *Host `gorm:"foreignKey:HostID;references:HostID" json:"host,omitempty"`
}

// TableName 返回表名
func (HostPlugin) TableName() string {
	return "host_plugins"
}

// HostPluginWithLatest 带有最新版本信息的主机插件
type HostPluginWithLatest struct {
	HostPlugin
	LatestVersion string `json:"latest_version"` // 最新可用版本
	NeedUpdate    bool   `json:"need_update"`    // 是否需要更新
}
