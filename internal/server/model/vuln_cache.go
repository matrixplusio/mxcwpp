package model

// VulnCache 离线漏洞缓存
type VulnCache struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	OsvID     string    `gorm:"column:osv_id;type:varchar(100);uniqueIndex" json:"osvId"`
	RawJSON   string    `gorm:"column:raw_json;type:mediumtext" json:"rawJson"`
	CachedAt  LocalTime `gorm:"column:cached_at;type:timestamp" json:"cachedAt"`
	ExpiredAt LocalTime `gorm:"column:expired_at;type:timestamp" json:"expiredAt"`
}

// TableName 指定表名
func (VulnCache) TableName() string {
	return "vuln_cache"
}

// VulnDBImport 离线漏洞库导入记录
type VulnDBImport struct {
	TenantID   string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	FileName   string    `gorm:"column:file_name;type:varchar(200)" json:"fileName"`
	FileSize   int64     `gorm:"column:file_size" json:"fileSize"`
	SHA256     string    `gorm:"column:sha256;type:varchar(64)" json:"sha256"`
	VulnCount  int       `gorm:"column:vuln_count;default:0" json:"vulnCount"`
	Status     string    `gorm:"column:status;type:varchar(20);default:'importing'" json:"status"` // importing / success / failed
	ImportedAt LocalTime `gorm:"column:imported_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"importedAt"`
}

// TableName 指定表名
func (VulnDBImport) TableName() string {
	return "vuln_db_imports"
}
