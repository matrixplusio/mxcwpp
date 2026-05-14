package model

// QuarantineFile 隔离箱文件
type QuarantineFile struct {
	ID             uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ScanResultID   uint       `gorm:"column:scan_result_id;index" json:"scanResultId"` // 关联的扫描结果 ID（可选）
	HostID         string     `gorm:"column:host_id;type:varchar(64);not null;index" json:"hostId"`
	Hostname       string     `gorm:"column:hostname;type:varchar(200)" json:"hostname"`
	IP             string     `gorm:"column:ip;type:varchar(45)" json:"ip"`
	OriginalPath   string     `gorm:"column:original_path;type:varchar(500);not null" json:"originalPath"` // 原始文件路径
	QuarantinePath string     `gorm:"column:quarantine_path;type:varchar(500)" json:"quarantinePath"`      // 隔离存储路径
	ThreatName     string     `gorm:"column:threat_name;type:varchar(200);not null" json:"threatName"`
	ThreatType     string     `gorm:"column:threat_type;type:varchar(50);not null" json:"threatType"`             // virus, trojan, worm, ransomware, rootkit, miner, backdoor, other
	Severity       string     `gorm:"column:severity;type:varchar(20);not null;default:'medium'" json:"severity"` // critical, high, medium, low
	FileHash       string     `gorm:"column:file_hash;type:varchar(64)" json:"fileHash"`
	FileSize       int64      `gorm:"column:file_size;default:0" json:"fileSize"`
	FilePermission string     `gorm:"column:file_permission;type:varchar(20)" json:"filePermission"`               // 原始文件权限
	FileOwner      string     `gorm:"column:file_owner;type:varchar(100)" json:"fileOwner"`                        // 原始文件属主
	Status         string     `gorm:"column:status;type:varchar(20);not null;default:'quarantined'" json:"status"` // quarantined, restored, deleted
	QuarantinedBy  string     `gorm:"column:quarantined_by;type:varchar(100)" json:"quarantinedBy"`                // 隔离操作人
	QuarantinedAt  LocalTime  `gorm:"column:quarantined_at;type:timestamp" json:"quarantinedAt"`
	RestoredAt     *LocalTime `gorm:"column:restored_at;type:timestamp" json:"restoredAt"`
	DeletedAt      *LocalTime `gorm:"column:deleted_at;type:timestamp" json:"deletedAt"`
	CreatedAt      LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt      LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (QuarantineFile) TableName() string {
	return "quarantine_files"
}
