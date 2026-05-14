package model

// AgentRestartStatus Agent 重启记录状态
type AgentRestartStatus string

const (
	AgentRestartStatusPending AgentRestartStatus = "pending"
	AgentRestartStatusPushing AgentRestartStatus = "pushing"
	AgentRestartStatusSuccess AgentRestartStatus = "success"
	AgentRestartStatusPartial AgentRestartStatus = "partial"
	AgentRestartStatusFailed  AgentRestartStatus = "failed"
)

// AgentRestartRecord Agent 重启记录
type AgentRestartRecord struct {
	ID           uint               `gorm:"primaryKey" json:"id"`
	TargetType   string             `gorm:"size:32;not null" json:"target_type"` // all / selected
	TargetHosts  StringArray        `gorm:"type:json" json:"target_hosts"`
	Status       AgentRestartStatus `gorm:"size:32;default:pending" json:"status"`
	TotalCount   int                `gorm:"default:0" json:"total_count"`
	SuccessCount int                `gorm:"default:0" json:"success_count"`
	FailedCount  int                `gorm:"default:0" json:"failed_count"`
	FailedHosts  StringArray        `gorm:"type:json" json:"failed_hosts"`
	Message      string             `gorm:"type:text" json:"message"`
	CreatedBy    string             `gorm:"size:64" json:"created_by"`
	PushedAt     *LocalTime         `json:"pushed_at,omitempty"`
	CreatedAt    LocalTime          `json:"created_at"`
	UpdatedAt    LocalTime          `json:"updated_at"`
	CompletedAt  *LocalTime         `json:"completed_at,omitempty"`
}
