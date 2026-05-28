package model

// VulnDataSourceRegion 漏洞源地理分类。
const (
	VulnSourceRegionCN     = "cn"
	VulnSourceRegionGlobal = "global"
)

// VulnDataSourceCategory 漏洞源功能分类。
const (
	VulnSourceCategoryCNOfficial  = "cn_official"  // 中国官方漏洞库（CNNVD/CNVD）
	VulnSourceCategoryOSAdvisory  = "os_advisory"  // OS 厂商 advisory（RHSA/Rocky/USN/Debian/Alpine）
	VulnSourceCategoryCVEMetadata = "cve_metadata" // CVE 元数据（NVD/MITRE/OSV）
	VulnSourceCategoryExploit     = "exploit"      // 0day / 已剥削（CISA KEV / exploit-db）
)

// VulnDataSourceStatus 上次同步状态。
const (
	VulnSourceStatusNever   = "never"
	VulnSourceStatusRunning = "running"
	VulnSourceStatusSuccess = "success"
	VulnSourceStatusFailed  = "failed"
)

// VulnDataSource 漏洞数据源配置 + 同步状态。
//
// UI「漏洞源管理」页面展示并允许 admin 启用/禁用 + 改 base_url + 手动触发同步。
// Coordinator/Scanner 每次 sync 前查 enabled=true 列表，跳过 disabled。
type VulnDataSource struct {
	ID           uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name         string     `gorm:"column:name;type:varchar(64);uniqueIndex;not null" json:"name"`     // slug，如 rhsa
	DisplayName  string     `gorm:"column:display_name;type:varchar(128);not null" json:"displayName"` // UI 展示名
	Region       string     `gorm:"column:region;type:varchar(16);not null;index" json:"region"`       // cn / global
	Category     string     `gorm:"column:category;type:varchar(32);not null;index" json:"category"`   // os_advisory / cve_metadata / exploit / cn_official
	Enabled      bool       `gorm:"column:enabled;default:0;index" json:"enabled"`                     // 启用同步
	BaseURL      string     `gorm:"column:base_url;type:varchar(500)" json:"baseUrl"`                  // 可在 UI 改（如换 CNNVD 镜像）
	APIKeyEnv    string     `gorm:"column:api_key_env;type:varchar(64)" json:"apiKeyEnv,omitempty"`    // 引用 env 变量名（如 NVD_API_KEY）
	Description  string     `gorm:"column:description;type:varchar(500)" json:"description"`           // UI tooltip
	LastSyncAt   *LocalTime `gorm:"column:last_sync_at;type:timestamp" json:"lastSyncAt,omitempty"`
	LastStatus   string     `gorm:"column:last_status;type:varchar(16);default:'never'" json:"lastStatus"` // never / running / success / failed
	LastError    string     `gorm:"column:last_error;type:text" json:"lastError,omitempty"`
	LastCount    int64      `gorm:"column:last_count;default:0" json:"lastCount"` // 上次同步入库 vuln 数
	LastDuration int64      `gorm:"column:last_duration_ms;default:0" json:"lastDurationMs"`
	CreatedAt    LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名。
func (VulnDataSource) TableName() string {
	return "vuln_data_sources"
}
