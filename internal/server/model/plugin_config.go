// Package model 提供数据库模型定义
package model

import (
	"gorm.io/gorm"
)

// PluginType 插件类型
type PluginType string

const (
	PluginTypeBaseline    PluginType = "baseline"       // 基线检查插件
	PluginTypeCollector   PluginType = "collector"      // 资产采集插件
	PluginTypeFIM         PluginType = "fim"            // 文件完整性监控插件
	PluginTypeScanner     PluginType = "scanner"        // 病毒查杀插件 (ClamAV + YARA-X)
	PluginTypeRemediation PluginType = "remediation"    // 漏洞修复插件
	PluginTypeVirusDB     PluginType = "virus-database" // ClamAV 病毒库（自动更新）
)

// PluginConfig 插件配置表
// 存储可下发给 Agent 的插件配置信息
type PluginConfig struct {
	TenantID     string         `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint           `gorm:"primaryKey" json:"id"`
	Name         string         `gorm:"size:64;uniqueIndex;not null" json:"name"`            // 插件名称 (唯一)
	Type         PluginType     `gorm:"size:32;not null" json:"type"`                        // 插件类型
	Version      string         `gorm:"size:32;not null" json:"version"`                     // 插件版本
	SHA256       string         `gorm:"size:64" json:"sha256"`                               // SHA256 校验和
	Signature    string         `gorm:"size:256" json:"signature"`                           // 签名
	DownloadURLs StringArray    `gorm:"type:json" json:"download_urls"`                      // 下载地址列表 (JSON 数组)
	Detail       string         `gorm:"type:text" json:"detail"`                             // 配置详情 (JSON 字符串)
	RuntimeTypes StringArray    `gorm:"type:json;column:runtime_types" json:"runtime_types"` // 适用运行时类型 (vm/docker/k8s)，空=全平台
	Enabled      bool           `gorm:"default:true" json:"enabled"`                         // 是否启用
	Description  string         `gorm:"size:256" json:"description"`                         // 描述
	CreatedAt    LocalTime      `json:"created_at"`                                          // 创建时间
	UpdatedAt    LocalTime      `json:"updated_at"`                                          // 更新时间
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`                                      // 软删除
}

// TableName 返回表名
func (PluginConfig) TableName() string {
	return "plugin_configs"
}
