// Package model 提供数据库模型定义
package model

// SystemConfig 系统配置模型
type SystemConfig struct {
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

// AlertConfig 告警配置
type AlertConfig struct {
	// 重复告警通知间隔（分钟）
	// 同一主机同一问题在此间隔内只会通知一次
	RepeatAlertInterval int `json:"repeat_alert_interval"`
	// 是否启用定期汇总（false = 只发首次告警，true = 按间隔定期发送）
	EnablePeriodicSummary bool `json:"enable_periodic_summary"`
}

// DefaultAlertConfig 默认告警配置
func DefaultAlertConfig() AlertConfig {
	return AlertConfig{
		RepeatAlertInterval:   30, // 默认 30 分钟
		EnablePeriodicSummary: true,
	}
}
