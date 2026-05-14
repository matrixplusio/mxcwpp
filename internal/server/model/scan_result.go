package model

// ResultStatus 检测结果状态
type ResultStatus string

const (
	ResultStatusPass  ResultStatus = "pass"
	ResultStatusFail  ResultStatus = "fail"
	ResultStatusError ResultStatus = "error"
	ResultStatusNA    ResultStatus = "na" // 不适用
)

// ScanResult 检测结果模型
// 复合主键 (task_id, host_id, rule_id) — 一次任务中每台主机的每条规则只有一条结果
type ScanResult struct {
	TaskID        string       `gorm:"primaryKey;column:task_id;type:varchar(64);not null" json:"task_id"`
	HostID        string       `gorm:"primaryKey;column:host_id;type:varchar(64);not null" json:"host_id"`
	RuleID        string       `gorm:"primaryKey;column:rule_id;type:varchar(64);not null" json:"rule_id"`
	Hostname      string       `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	PolicyID      string       `gorm:"column:policy_id;type:varchar(64);index" json:"policy_id"`
	PolicyName    string       `gorm:"column:policy_name;type:varchar(255)" json:"policy_name"`
	Status        ResultStatus `gorm:"column:status;type:varchar(20);not null" json:"status"`
	Severity      string       `gorm:"column:severity;type:varchar(20)" json:"severity"`
	Category      string       `gorm:"column:category;type:varchar(50)" json:"category"`
	Title         string       `gorm:"column:title;type:varchar(255)" json:"title"`
	Actual        string       `gorm:"column:actual;type:text" json:"actual"`
	Expected      string       `gorm:"column:expected;type:text" json:"expected"`
	FixSuggestion string       `gorm:"column:fix_suggestion;type:text" json:"fix_suggestion"`
	CheckedAt     LocalTime    `gorm:"column:checked_at;type:timestamp;not null" json:"checked_at"`
	CreatedAt     LocalTime    `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`

	// 关联关系（可选，主要用于查询时预加载）
	Host Host `gorm:"foreignKey:HostID;references:HostID" json:"host,omitempty"`
	Rule Rule `gorm:"foreignKey:RuleID;references:RuleID" json:"rule,omitempty"`
}

// TableName 指定表名
func (ScanResult) TableName() string {
	return "scan_results"
}
