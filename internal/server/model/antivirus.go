package model

// AntivirusScanTask 病毒查杀扫描任务
type AntivirusScanTask struct {
	ID           uint        `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name         string      `gorm:"column:name;type:varchar(200);not null" json:"name"`
	ScanType     string      `gorm:"column:scan_type;type:varchar(30);not null;default:'quick'" json:"scanType"` // quick(快速), full(全盘), custom(自定义)
	ScanPaths    StringArray `gorm:"column:scan_paths;type:json" json:"scanPaths"`                               // 自定义扫描路径
	HostIDs      StringArray `gorm:"column:host_ids;type:json;not null" json:"hostIds"`                          // 目标主机
	Status       string      `gorm:"column:status;type:varchar(20);not null;default:'pending'" json:"status"`    // pending, running, completed, failed, cancelled
	TotalHosts   int         `gorm:"column:total_hosts;default:0" json:"totalHosts"`
	ScannedHosts int         `gorm:"column:scanned_hosts;default:0" json:"scannedHosts"`
	ThreatCount  int         `gorm:"column:threat_count;default:0" json:"threatCount"`
	CreatedBy    string      `gorm:"column:created_by;type:varchar(100)" json:"createdBy"`
	StartedAt    *LocalTime  `gorm:"column:started_at;type:timestamp" json:"startedAt"`
	FinishedAt   *LocalTime  `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
	CreatedAt    LocalTime   `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    LocalTime   `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`

	// 关联
	Results []AntivirusScanResult `gorm:"foreignKey:TaskID" json:"results,omitempty"`
}

func (AntivirusScanTask) TableName() string {
	return "antivirus_scan_tasks"
}

// AntivirusScanResult 病毒查杀扫描结果
type AntivirusScanResult struct {
	ID         uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	TaskID     uint      `gorm:"column:task_id;not null;index" json:"taskId"`
	HostID     string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"hostId"`
	Hostname   string    `gorm:"column:hostname;type:varchar(200)" json:"hostname"`
	IP         string    `gorm:"column:ip;type:varchar(45)" json:"ip"`
	FilePath   string    `gorm:"column:file_path;type:varchar(500);not null" json:"filePath"`
	ThreatName string    `gorm:"column:threat_name;type:varchar(200);not null" json:"threatName"`
	ThreatType string    `gorm:"column:threat_type;type:varchar(50);not null" json:"threatType"`             // virus, trojan, worm, ransomware, rootkit, miner, backdoor, other
	Severity   string    `gorm:"column:severity;type:varchar(20);not null;default:'medium'" json:"severity"` // critical, high, medium, low
	FileHash   string    `gorm:"column:file_hash;type:varchar(64)" json:"fileHash"`
	FileSize   int64     `gorm:"column:file_size;default:0" json:"fileSize"`
	Action     string    `gorm:"column:action;type:varchar(20);not null;default:'detected'" json:"action"` // detected, quarantined, deleted, ignored
	DetectedAt LocalTime `gorm:"column:detected_at;type:timestamp" json:"detectedAt"`
	CreatedAt  LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt  LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

func (AntivirusScanResult) TableName() string {
	return "antivirus_scan_results"
}
