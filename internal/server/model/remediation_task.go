package model

// RemediationTask 漏洞修复任务
type RemediationTask struct {
	ID           uint       `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	VulnID       uint       `gorm:"column:vuln_id;not null;index" json:"vulnId"`
	CveID        string     `gorm:"column:cve_id;type:varchar(50);not null" json:"cveId"`
	HostID       string     `gorm:"column:host_id;type:varchar(64);not null;index" json:"hostId"`
	Hostname     string     `gorm:"column:hostname;type:varchar(200)" json:"hostname"`
	IP           string     `gorm:"column:ip;type:varchar(45)" json:"ip"`
	Component    string     `gorm:"column:component;type:varchar(200)" json:"component"`
	FixedVersion string     `gorm:"column:fixed_version;type:varchar(100)" json:"fixedVersion"`
	Command      string     `gorm:"column:command;type:text" json:"command"`
	Status       string     `gorm:"column:status;type:varchar(20);not null;default:'pending';index" json:"status"`
	ExecOutput   string     `gorm:"column:exec_output;type:text" json:"execOutput"`
	ExitCode     *int       `gorm:"column:exit_code;type:int" json:"exitCode"`
	CreatedBy    string     `gorm:"column:created_by;type:varchar(64)" json:"createdBy"`
	ConfirmedBy  string     `gorm:"column:confirmed_by;type:varchar(64)" json:"confirmedBy"`
	ConfirmedAt  *LocalTime `gorm:"column:confirmed_at;type:timestamp" json:"confirmedAt"`
	StartedAt    *LocalTime `gorm:"column:started_at;type:timestamp" json:"startedAt"`
	FinishedAt   *LocalTime `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
	CreatedAt    LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (RemediationTask) TableName() string {
	return "remediation_tasks"
}
