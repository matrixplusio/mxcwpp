package model

// HostIsolation tracks the network isolation state of a host.
//
// 表是 event-stream 性质: 每次 isolate/release 写一条记录, 不是 host_id 唯一.
// 旧版误把 host_id 设为 uniqueIndex, 导致同一主机第二次 isolate 主键冲突.
// 改为普通 index, 业务唯一性 (一台主机同时只能一条 active 隔离) 由 handler 查 status='active' 保证.
type HostIsolation struct {
	TenantID   string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint       `gorm:"primarykey" json:"id"`
	HostID     string     `gorm:"type:varchar(64);index" json:"host_id"`
	Hostname   string     `gorm:"type:varchar(255)" json:"hostname"`
	Level      string     `gorm:"type:varchar(20);default:none" json:"level"`     // none/selective/standard/complete
	Reason     string     `gorm:"type:varchar(500)" json:"reason"`                // isolation reason
	Timeout    int        `gorm:"default:14400" json:"timeout"`                   // timeout in seconds
	Status     string     `gorm:"type:varchar(20);default:pending" json:"status"` // pending/active/released/failed
	Source     string     `gorm:"type:varchar(50);default:manual" json:"source"`  // manual/auto_response/threat_intel
	CreatedBy  string     `gorm:"type:varchar(100)" json:"created_by"`
	IsolatedAt *LocalTime `json:"isolated_at,omitempty"`
	ReleasedAt *LocalTime `json:"released_at,omitempty"`
	ReleasedBy string     `gorm:"type:varchar(100)" json:"released_by,omitempty"`
	CreatedAt  LocalTime  `json:"created_at"`
	UpdatedAt  LocalTime  `json:"updated_at"`
}

func (HostIsolation) TableName() string { return "host_isolations" }
