// Package model 提供数据库模型定义
package model

// SystemConfig 系统配置模型
type SystemConfig struct {
	TenantID    string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Key         string    `gorm:"column:key;type:varchar(100);not null;uniqueIndex:idx_key_category" json:"key"`                            // 配置键
	Value       string    `gorm:"column:value;type:text" json:"value"`                                                                      // 配置值（JSON 格式）
	Category    string    `gorm:"column:category;type:varchar(50);not null;default:'general';uniqueIndex:idx_key_category" json:"category"` // 配置分类
	Description string    `gorm:"column:description;type:varchar(500)" json:"description"`                                                  // 配置描述
	CreatedAt   LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (SystemConfig) TableName() string {
	return "system_configs"
}

// KubernetesImageConfig Kubernetes 镜像配置
type KubernetesImageConfig struct {
	Repository     string   `json:"repository"`      // 镜像仓库地址
	Versions       []string `json:"versions"`        // 可用版本列表
	DefaultVersion string   `json:"default_version"` // 默认版本
}

// SiteConfig 站点配置
type SiteConfig struct {
	SiteName   string `json:"site_name"`   // 站点名称
	SiteLogo   string `json:"site_logo"`   // Logo URL（相对路径或完整URL）
	SiteDomain string `json:"site_domain"` // 前端访问域名（用于生成安装脚本）
	BackendURL string `json:"backend_url"` // 后端接口地址（用于 Agent 下载更新）
}
