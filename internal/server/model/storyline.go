package model

// Storyline represents an attack narrative spanning multiple related events
// on a single host. Events are correlated by story_id assigned at the Agent.
type Storyline struct {
	TenantID    string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint       `gorm:"primarykey" json:"id"`
	StoryID     string     `gorm:"type:varchar(64);uniqueIndex" json:"story_id"`
	HostID      string     `gorm:"type:varchar(64);index" json:"host_id"`
	Hostname    string     `gorm:"type:varchar(255)" json:"hostname"`
	Severity    string     `gorm:"type:varchar(20)" json:"severity"`              // critical/high/medium/low
	Status      string     `gorm:"type:varchar(20);default:active" json:"status"` // active/resolved/investigating
	Phase       string     `gorm:"type:varchar(50)" json:"phase"`                 // MITRE ATT&CK phase (e.g. initial_access)
	Summary     string     `gorm:"type:text" json:"summary"`                      // auto-generated summary
	RuleNames   string     `gorm:"type:text" json:"rule_names"`                   // comma-separated matched rules
	EventCount  int        `json:"event_count"`                                   // total events in storyline
	AlertCount  int        `json:"alert_count"`                                   // events that triggered rules
	RiskScore   float64    `gorm:"type:decimal(5,1)" json:"risk_score"`           // 0-100
	FirstSeenAt LocalTime  `json:"first_seen_at"`
	LastSeenAt  LocalTime  `json:"last_seen_at"`
	ResolvedAt  *LocalTime `json:"resolved_at,omitempty"`
	ResolvedBy  string     `gorm:"type:varchar(100)" json:"resolved_by,omitempty"`
	CreatedAt   LocalTime  `json:"created_at"`
	UpdatedAt   LocalTime  `json:"updated_at"`
}

func (Storyline) TableName() string { return "storylines" }

// StorylineEvent links an individual event to a storyline.
// Stores denormalized event fields for quick timeline rendering without ClickHouse query.
type StorylineEvent struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primarykey" json:"id"`
	StoryID   string    `gorm:"type:varchar(64);index:idx_story_ts" json:"story_id"`
	HostID    string    `gorm:"type:varchar(64)" json:"host_id"`
	DataType  int32     `json:"data_type"`                          // 3000-3003
	EventType string    `gorm:"type:varchar(50)" json:"event_type"` // process_exec, file_write, etc
	PID       string    `gorm:"type:varchar(20)" json:"pid"`
	Exe       string    `gorm:"type:varchar(512)" json:"exe"`
	Detail    string    `gorm:"type:text" json:"detail"`            // JSON of key event fields
	RuleName  string    `gorm:"type:varchar(200)" json:"rule_name"` // matched rule (empty if none)
	Severity  string    `gorm:"type:varchar(20)" json:"severity"`   // from agent_severity
	Timestamp LocalTime `gorm:"index:idx_story_ts" json:"timestamp"`
	CreatedAt LocalTime `json:"created_at"`
}

func (StorylineEvent) TableName() string { return "storyline_events" }
