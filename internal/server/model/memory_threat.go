package model

// MemoryThreat records a detected fileless/memory-based attack technique
// on a host. Events flow from Agent (DataType 3004) through Kafka consumer.
type MemoryThreat struct {
	TenantID   string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint      `gorm:"primarykey" json:"id"`
	HostID     string    `gorm:"type:varchar(64);index" json:"host_id"`
	Hostname   string    `gorm:"type:varchar(255)" json:"hostname"`
	ThreatType string    `gorm:"type:varchar(50);index" json:"threat_type"` // memfd_exec / deleted_exe / anonymous_exec
	Severity   string    `gorm:"type:varchar(20);default:high" json:"severity"`
	PID        string    `gorm:"type:varchar(20)" json:"pid"`
	PPID       string    `gorm:"type:varchar(20)" json:"ppid"`
	UID        string    `gorm:"type:varchar(20)" json:"uid"`
	Exe        string    `gorm:"type:varchar(512)" json:"exe"`
	Cmdline    string    `gorm:"type:text" json:"cmdline"`
	Detail     string    `gorm:"type:text" json:"detail"`                     // threat-specific detail
	Status     string    `gorm:"type:varchar(20);default:open" json:"status"` // open / resolved / false_positive
	StoryID    string    `gorm:"type:varchar(64);index" json:"story_id"`      // link to attack storyline
	ResolvedBy string    `gorm:"type:varchar(100)" json:"resolved_by,omitempty"`
	CreatedAt  LocalTime `json:"created_at"`
	UpdatedAt  LocalTime `json:"updated_at"`
}

func (MemoryThreat) TableName() string { return "memory_threats" }
