package model

// BehaviorAlert stores a BDE (Behavior Detection Engine) anomaly alert.
// Generated when a host's behavior profile deviates significantly from its baseline.
type BehaviorAlert struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primarykey" json:"id"`
	HostID    string    `gorm:"type:varchar(64);index" json:"host_id"`
	Hostname  string    `gorm:"type:varchar(255)" json:"hostname"`
	RiskScore float64   `gorm:"type:decimal(5,1)" json:"risk_score"`         // 0-100
	Metric    string    `gorm:"type:varchar(50)" json:"metric"`              // e.g. "proc_fork_rate"
	Value     float64   `gorm:"type:decimal(15,4)" json:"value"`             // observed value
	Mean      float64   `gorm:"type:decimal(15,4)" json:"mean"`              // baseline mean
	Stddev    float64   `gorm:"type:decimal(15,4)" json:"stddev"`            // baseline stddev
	ZScore    float64   `gorm:"type:decimal(8,2)" json:"z_score"`            // deviation z-score
	Status    string    `gorm:"type:varchar(20);default:open" json:"status"` // open/resolved/ignored
	CreatedAt LocalTime `json:"created_at"`
	UpdatedAt LocalTime `json:"updated_at"`
}

func (BehaviorAlert) TableName() string { return "behavior_alerts" }

// HostBaselineState persists BDE baseline statistics for crash recovery.
// Welford mean/m2 arrays are stored as JSON text to avoid 13 columns per metric.
type HostBaselineState struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primarykey" json:"id"`
	HostID    string    `gorm:"type:varchar(64);uniqueIndex" json:"host_id"`
	Phase     string    `gorm:"type:varchar(20);default:learning" json:"phase"` // learning/active
	Samples   int       `json:"samples"`
	FirstSeen LocalTime `json:"first_seen"`
	MeanJSON  string    `gorm:"type:text" json:"-"` // JSON array [13]float64
	M2JSON    string    `gorm:"type:text" json:"-"` // JSON array [13]float64
	CreatedAt LocalTime `json:"created_at"`
	UpdatedAt LocalTime `json:"updated_at"`
}

func (HostBaselineState) TableName() string { return "host_baseline_states" }
