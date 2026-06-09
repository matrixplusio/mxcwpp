package model

// HoneypotPolicy 定义诱饵投放策略 (Server 下发 → Agent 部署)。
//
// 一台主机可绑定一条 policy (按 host_label / tenant 匹配);
// policy 决定:
//   - 是否在该主机投放诱饵
//   - 投放哪些目录 / 哪些诱饵类型
//   - 是否允许合法备份进程 (白名单)
//
// 设计参考: ref/07-病毒.md §5 + docs/operating-modes.md
type HoneypotPolicy struct {
	TenantID    string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	Name        string `gorm:"column:name;type:varchar(128);not null;uniqueIndex:uk_tenant_name,priority:2" json:"name"`
	Description string `gorm:"column:description;type:varchar(512)" json:"description"`
	// 匹配规则
	HostLabelSelector string `gorm:"column:host_label_selector;type:varchar(512)" json:"host_label_selector"` // e.g. "env=prod,role=db"
	// 部署配置
	TargetDirsJSON string `gorm:"column:target_dirs;type:text" json:"target_dirs"` // JSON array
	DecoyKindsJSON string `gorm:"column:decoy_kinds;type:text" json:"decoy_kinds"` // JSON array
	NameSeed       string `gorm:"column:name_seed;type:varchar(64)" json:"name_seed"`
	// 白名单 (合法备份/运维进程 exe 匹配)
	WhitelistExeJSON string `gorm:"column:whitelist_exe;type:text" json:"whitelist_exe"` // JSON array of exe paths/regex
	// 状态
	Enabled   bool      `gorm:"column:enabled;type:tinyint(1);default:1;index" json:"enabled"`
	UpdatedBy string    `gorm:"column:updated_by;type:varchar(100)" json:"updated_by"`
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 表名。
func (HoneypotPolicy) TableName() string { return "honeypot_policies" }

// DefaultHoneypotWhitelist 内置合法备份/运维进程白名单。
//
// 命中白名单的诱饵触发不告警 (避免日常备份误报)。
// 客户可在 policy 层 override / 追加。
var DefaultHoneypotWhitelist = []string{
	"/usr/bin/rsync",
	"/usr/bin/tar",
	"/usr/bin/gzip",
	"/usr/bin/borg", // BorgBackup
	"/usr/bin/restic",
	"/usr/bin/duplicati",
	"/usr/bin/duplicity",
	"/usr/bin/rclone",
	"/usr/bin/find", // 运维巡检
	"/usr/bin/grep",
	"/usr/sbin/clamscan",           // 老牌 AV
	"/opt/mxsec/agent/bin/scanner", // 我们自己的 scanner
}

// HoneypotDeploymentRecord 记录单台主机的诱饵部署快照。
//
// Agent 投放后回报 → 落本表 → Server 列表展示。
// 命中触发时关联本表查询 decoy 元信息。
type HoneypotDeploymentRecord struct {
	TenantID     string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	HostID       string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	PolicyID     uint      `gorm:"column:policy_id;not null;index" json:"policy_id"`
	DecoyPath    string    `gorm:"column:decoy_path;type:varchar(512);not null;uniqueIndex:uk_host_path,priority:2" json:"decoy_path"`
	DecoyKind    string    `gorm:"column:decoy_kind;type:varchar(32);not null" json:"decoy_kind"`
	Size         int64     `gorm:"column:size;type:bigint;not null" json:"size"`
	DeployedAt   LocalTime `gorm:"column:deployed_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"deployed_at"`
	LastSeenAt   LocalTime `gorm:"column:last_seen_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"last_seen_at"`
	TriggerCount int       `gorm:"column:trigger_count;not null;default:0" json:"trigger_count"`
}

// TableName 表名。
func (HoneypotDeploymentRecord) TableName() string { return "honeypot_deployments" }
