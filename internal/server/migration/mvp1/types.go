// Package mvp1 提供 MVP1 → MVP2 数据迁移能力
package mvp1

// MVP1 API 响应结构（与 MVP2 model 独立，避免耦合）

// mvp1User MVP1 用户
type mvp1User struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// mvp1BusinessLine MVP1 业务线
type mvp1BusinessLine struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
	Contact     string `json:"contact"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// mvp1Host MVP1 主机
type mvp1Host struct {
	HostID        string   `json:"host_id"`
	Hostname      string   `json:"hostname"`
	OSFamily      string   `json:"os_family"`
	OSVersion     string   `json:"os_version"`
	KernelVersion string   `json:"kernel_version"`
	Arch          string   `json:"arch"`
	IPv4          []string `json:"ipv4"`
	IPv6          []string `json:"ipv6"`
	PublicIPv4    []string `json:"public_ipv4"`
	PublicIPv6    []string `json:"public_ipv6"`
	Status        string   `json:"status"`
	BusinessLine  string   `json:"business_line"`
	AgentVersion  string   `json:"agent_version"`
	Tags          []string `json:"tags"`
	CPUInfo       string   `json:"cpu_info"`
	MemorySize    string   `json:"memory_size"`
	DiskInfo      string   `json:"disk_info"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

// mvp1Policy MVP1 策略
type mvp1Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	OSFamily    []string `json:"os_family"`
	OSVersion   string   `json:"os_version"`
	Enabled     bool     `json:"enabled"`
	GroupID     string   `json:"group_id"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// mvp1Rule MVP1 规则
type mvp1Rule struct {
	RuleID      string      `json:"rule_id"`
	PolicyID    string      `json:"policy_id"`
	Category    string      `json:"category"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
	Enabled     bool        `json:"enabled"`
	CheckConfig interface{} `json:"check_config"`
	FixConfig   interface{} `json:"fix_config"`
	CreatedAt   string      `json:"created_at"`
	UpdatedAt   string      `json:"updated_at"`
}

// mvp1ScanTask MVP1 扫描任务
type mvp1ScanTask struct {
	TaskID         string      `json:"task_id"`
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	TargetType     string      `json:"target_type"`
	TargetConfig   interface{} `json:"target_config"`
	PolicyID       string      `json:"policy_id"`
	PolicyIDs      []string    `json:"policy_ids"`
	RuleIDs        []string    `json:"rule_ids"`
	Status         string      `json:"status"`
	TimeoutMinutes int         `json:"timeout_minutes"`
	CreatedAt      string      `json:"created_at"`
	UpdatedAt      string      `json:"updated_at"`
	ExecutedAt     *string     `json:"executed_at"`
	CompletedAt    *string     `json:"completed_at"`
}

// mvp1ScanResult MVP1 扫描结果
type mvp1ScanResult struct {
	ResultID      string `json:"result_id"`
	HostID        string `json:"host_id"`
	Hostname      string `json:"hostname"`
	PolicyID      string `json:"policy_id"`
	PolicyName    string `json:"policy_name"`
	RuleID        string `json:"rule_id"`
	TaskID        string `json:"task_id"`
	Status        string `json:"status"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	Title         string `json:"title"`
	Actual        string `json:"actual"`
	Expected      string `json:"expected"`
	FixSuggestion string `json:"fix_suggestion"`
	CheckedAt     string `json:"checked_at"`
	CreatedAt     string `json:"created_at"`
}

// mvp1Notification MVP1 通知配置
type mvp1Notification struct {
	ID          uint        `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Type        string      `json:"type"`
	Severities  []string    `json:"severities"`
	Scope       string      `json:"scope"`
	ScopeValue  string      `json:"scope_value"`
	FrontendURL string      `json:"frontend_url"`
	Config      interface{} `json:"config"`
	CreatedAt   string      `json:"created_at"`
	UpdatedAt   string      `json:"updated_at"`
}

// TableReport 单表迁移报告
type TableReport struct {
	Table       string   `json:"table"`
	Total       int      `json:"total"`
	Created     int      `json:"created"`
	Skipped     int      `json:"skipped"`
	Failed      int      `json:"failed"`
	SkipReasons []string `json:"skip_reasons,omitempty"`
	FailErrors  []string `json:"fail_errors,omitempty"`
}
