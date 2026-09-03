package model

// RemediationPolicy 修复策略模板
type RemediationPolicy struct {
	TenantID    string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name        string     `gorm:"column:name;type:varchar(100);not null" json:"name"`
	Description string     `gorm:"column:description;type:text" json:"description"`
	TargetType  string     `gorm:"column:target_type;type:varchar(20)" json:"targetType"`   // all / business_line / tag / host_ids
	TargetValue string     `gorm:"column:target_value;type:text" json:"targetValue"`        // JSON: 业务线ID / 标签名 / 主机ID列表
	SeverityMin string     `gorm:"column:severity_min;type:varchar(20)" json:"severityMin"` // 最低严重级别
	PriorityMin float64    `gorm:"column:priority_min;type:decimal(5,3);default:0" json:"priorityMin"`
	AutoConfirm bool       `gorm:"column:auto_confirm;default:false" json:"autoConfirm"`
	MaxParallel int        `gorm:"column:max_parallel;default:10" json:"maxParallel"`
	RolloutType string     `gorm:"column:rollout_type;type:varchar(20);default:'immediate'" json:"rolloutType"` // immediate / canary / rolling
	CanaryRatio int        `gorm:"column:canary_ratio;default:10" json:"canaryRatio"`                           // 金丝雀比例（%）
	Enabled     bool       `gorm:"column:enabled;default:true" json:"enabled"`
	LastRunAt   *LocalTime `gorm:"column:last_run_at;type:timestamp" json:"lastRunAt"`
	CreatedBy   string     `gorm:"column:created_by;type:varchar(64)" json:"createdBy"`
	CreatedAt   LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (RemediationPolicy) TableName() string {
	return "remediation_policies"
}

// RemediationPolicyExecution 修复策略执行记录
type RemediationPolicyExecution struct {
	TenantID   string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	PolicyID   uint       `gorm:"column:policy_id;not null;index" json:"policyId"`
	Status     string     `gorm:"column:status;type:varchar(16);not null;default:running" json:"status"`
	HostCount  int        `gorm:"column:host_count" json:"hostCount"`
	VulnCount  int        `gorm:"column:vuln_count" json:"vulnCount"`
	TaskCount  int        `gorm:"column:task_count" json:"taskCount"`
	ErrorMsg   string     `gorm:"column:error_msg;type:text" json:"errorMsg"`
	CreatedBy  string     `gorm:"column:created_by;type:varchar(100)" json:"createdBy"`
	Duration   int        `gorm:"column:duration" json:"duration"`
	StartedAt  LocalTime  `gorm:"column:started_at;type:timestamp;not null" json:"startedAt"`
	FinishedAt *LocalTime `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
}

// TableName 指定表名
func (RemediationPolicyExecution) TableName() string {
	return "remediation_policy_executions"
}
