package model

// FIMBaseline 基线记录（策略+主机维度，唯一约束）
type FIMBaseline struct {
	ID         uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	PolicyID   string     `gorm:"column:policy_id;type:varchar(64);not null;uniqueIndex:udx_fim_bl_policy_host" json:"policy_id"`
	HostID     string     `gorm:"column:host_id;type:varchar(64);not null;uniqueIndex:udx_fim_bl_policy_host" json:"host_id"`
	Hostname   string     `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	Version    int        `gorm:"column:version;type:int;not null;default:1" json:"version"`
	Status     string     `gorm:"column:status;type:varchar(20);not null;default:'pending';index:idx_fim_bl_status" json:"status"` // pending/approved/outdated
	EntryCount int        `gorm:"column:entry_count;type:int;default:0" json:"entry_count"`
	ApprovedBy string     `gorm:"column:approved_by;type:varchar(100)" json:"approved_by"`
	ApprovedAt *LocalTime `gorm:"column:approved_at;type:timestamp" json:"approved_at"`
	TaskID     string     `gorm:"column:task_id;type:varchar(64)" json:"task_id"`
	CreatedAt  LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt  LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (FIMBaseline) TableName() string {
	return "fim_baselines"
}

// FIMBaselineEntry 基线文件条目
type FIMBaselineEntry struct {
	ID         uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	BaselineID uint   `gorm:"column:baseline_id;type:int unsigned;not null;index:idx_fbe_baseline_id" json:"baseline_id"`
	FilePath   string `gorm:"column:file_path;type:varchar(1024);not null;index:idx_fbe_file_path,length:255" json:"file_path"`
	SHA256     string `gorm:"column:sha256;type:varchar(64)" json:"sha256"`
	FileSize   int64  `gorm:"column:file_size;type:bigint" json:"file_size"`
	FileMode   string `gorm:"column:file_mode;type:varchar(10)" json:"file_mode"`
	UID        uint32 `gorm:"column:uid;type:int unsigned" json:"uid"`
	GID        uint32 `gorm:"column:gid;type:int unsigned" json:"gid"`
	MTime      int64  `gorm:"column:mtime;type:bigint" json:"mtime"`
}

// TableName 指定表名
func (FIMBaselineEntry) TableName() string {
	return "fim_baseline_entries"
}
