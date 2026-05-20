package model

// ImageScan 容器镜像扫描记录
type ImageScan struct {
	ID          uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Image       string     `gorm:"column:image;type:varchar(500);not null;index" json:"image"`
	Digest      string     `gorm:"column:digest;type:varchar(100)" json:"digest"`
	OS          string     `gorm:"column:os;type:varchar(50)" json:"os"`
	TotalVulns  int        `gorm:"column:total_vulns;default:0" json:"totalVulns"`
	CriticalCnt int        `gorm:"column:critical_cnt;default:0" json:"criticalCnt"`
	HighCnt     int        `gorm:"column:high_cnt;default:0" json:"highCnt"`
	Status      string     `gorm:"column:status;type:varchar(20);default:'pending'" json:"status"` // pending / scanning / done / failed
	ErrorMsg    string     `gorm:"column:error_msg;type:text" json:"errorMsg"`
	ScannedAt   *LocalTime `gorm:"column:scanned_at;type:timestamp" json:"scannedAt"`
	CreatedAt   LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

// TableName 指定表名
func (ImageScan) TableName() string {
	return "image_scans"
}

// ImageVulnerability 镜像漏洞关联
type ImageVulnerability struct {
	ID           uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ImageScanID  uint   `gorm:"column:image_scan_id;not null;index" json:"imageScanId"`
	VulnID       *uint  `gorm:"column:vuln_id;index" json:"vulnId"`
	CveID        string `gorm:"column:cve_id;type:varchar(50);index" json:"cveId"`
	Package      string `gorm:"column:package;type:varchar(200)" json:"package"`
	Version      string `gorm:"column:version;type:varchar(100)" json:"version"`
	FixedVersion string `gorm:"column:fixed_version;type:varchar(100)" json:"fixedVersion"`
	Severity     string `gorm:"column:severity;type:varchar(20)" json:"severity"`
	Title        string `gorm:"column:title;type:text" json:"title"`
}

// TableName 指定表名
func (ImageVulnerability) TableName() string {
	return "image_vulnerabilities"
}

// ImageRegistry 镜像仓库配置
type ImageRegistry struct {
	ID         uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name       string     `gorm:"column:name;type:varchar(100);not null" json:"name"`
	URL        string     `gorm:"column:url;type:varchar(500);not null" json:"url"`
	Username   string     `gorm:"column:username;type:varchar(100)" json:"username"`
	Password   string     `gorm:"column:password;type:varchar(500)" json:"-"` // JSON 中隐藏
	Insecure   bool       `gorm:"column:insecure;default:false" json:"insecure"`
	ImageCount int        `gorm:"column:image_count;default:0" json:"imageCount"`
	LastSyncAt *LocalTime `gorm:"column:last_sync_at;type:timestamp" json:"lastSyncAt"`
	CreatedAt  LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt  LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (ImageRegistry) TableName() string {
	return "image_registries"
}
