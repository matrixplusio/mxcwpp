package model

import "net/url"

// PluginCanary 插件灰度：指定版本只下发给指定主机，其余主机仍用 plugin_configs 的全局版本。
//
// 插件配置是全局一份，改了就是全网；而 agent 每次重连都会拉配置，所以「先设最新版本再慢慢推」
// 并不存在——任何一次重连都会升级。灰度只能按主机覆盖下发内容。
// 每个插件同时只有一条灰度；转正走「设为最新版本」，回滚删除本记录。
type PluginCanary struct {
	TenantID   string      `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint        `gorm:"primaryKey" json:"id"`
	PluginName string      `gorm:"column:plugin_name;size:64;uniqueIndex;not null" json:"plugin_name"`
	Version    string      `gorm:"column:version;size:64;not null" json:"version"`
	SHA256     string      `gorm:"column:sha256;size:64;not null" json:"sha256"`
	Signature  string      `gorm:"column:signature;size:256" json:"signature"`
	HostIDs    StringArray `gorm:"column:host_ids;type:json" json:"host_ids"`
	CreatedBy  string      `gorm:"column:created_by;size:64" json:"created_by"`
	CreatedAt  LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 返回表名
func (PluginCanary) TableName() string { return "plugin_canaries" }

// Covers 主机是否在灰度名单内。
func (c *PluginCanary) Covers(hostID string) bool {
	for _, h := range c.HostIDs {
		if h == hostID {
			return true
		}
	}
	return false
}

// PluginCanaryDownloadURL 灰度版本的下载地址（相对路径，由 AC 按 backend_url 拼完整地址）。
// 不带 version 时下载接口返回最新版本，灰度主机会拿到与 sha256 对不上的包。
func PluginCanaryDownloadURL(name, version string) string {
	return "/api/v1/plugins/download/" + name + "?version=" + url.QueryEscape(version)
}
