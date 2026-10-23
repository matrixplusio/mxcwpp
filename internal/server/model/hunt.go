package model

// HuntQuery represents a saved threat hunting query.
type HuntQuery struct {
	TenantID    string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint       `gorm:"primarykey" json:"id"`
	Name        string     `gorm:"type:varchar(200);uniqueIndex" json:"name"`
	Description string     `gorm:"type:text" json:"description"`
	MQL         string     `gorm:"type:text;not null" json:"mql"`
	Category    string     `gorm:"type:varchar(50)" json:"category"` // reconnaissance, persistence, exfiltration, etc
	Severity    string     `gorm:"type:varchar(20);default:medium" json:"severity"`
	Owner       string     `gorm:"type:varchar(100)" json:"owner"`
	IsBuiltin   bool       `gorm:"default:false" json:"is_builtin"` // built-in template queries
	LastRunAt   *LocalTime `json:"last_run_at,omitempty"`
	LastHits    int        `json:"last_hits"`
	CreatedAt   LocalTime  `json:"created_at"`
	UpdatedAt   LocalTime  `json:"updated_at"`
}

func (HuntQuery) TableName() string { return "hunt_queries" }
