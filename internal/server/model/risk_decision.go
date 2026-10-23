package model

// RiskDecision 实体风险累积的一次判断（影子阶段只记录、不告警）。
//
// 单个弱信号不该单独打扰值班。风险累积把同一个实体（主机 + 进程血缘根）在一段时间内的
// 信号按 ATT&CK 战术叠加，凑出攻击形态时才算「本会告警」。影子阶段把每个跨两个战术以上的
// 实体都记下来，连同它为什么够格或不够格，用来对照现有告警与研判结论、确定阈值。
//
// 追加写：判断每变化一次就新增一行，不覆盖。一段活动只存一行的话，后来的判断要么抹掉之前的
// 「本会告警」，要么被峰值挡住写不进去，事后无法重放「什么时候、因为哪些信号够了线」。
type RiskDecision struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	// EntityKey 血缘层为「主机|根进程号@首次看到的时间」，主机层为「host:主机」。
	EntityKey string `gorm:"column:entity_key;type:varchar(191);not null;index:idx_risk_entity_episode,priority:1" json:"entity_key"`
	// Level lineage（主机 + 血缘根）或 host（整台主机，兜底层，阈值更严）。
	Level string `gorm:"column:level;type:varchar(16);not null;index" json:"level"`
	// EpisodeStart 这段连续活动的开始：实体的信号全部滑出窗口后，再来的信号算新的一段。
	EpisodeStart LocalTime `gorm:"column:episode_start;type:timestamp;not null;index:idx_risk_entity_episode,priority:2" json:"episode_start"`
	HostID       string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	RootPID      string    `gorm:"column:root_pid;type:varchar(32)" json:"root_pid"`
	RootExe      string    `gorm:"column:root_exe;type:varchar(512)" json:"root_exe"`
	RootCmdline  string    `gorm:"column:root_cmdline;type:varchar(1024)" json:"root_cmdline"`
	FirstSeen    LocalTime `gorm:"column:first_seen;type:timestamp;not null" json:"first_seen"`
	LastSeen     LocalTime `gorm:"column:last_seen;type:timestamp;not null;index" json:"last_seen"`
	// Tactics 窗口内出现过的战术（逗号分隔）。
	Tactics     string  `gorm:"column:tactics;type:varchar(512)" json:"tactics"`
	TacticCount int     `gorm:"column:tactic_count;not null" json:"tactic_count"`
	Score       float64 `gorm:"column:score;not null" json:"score"`
	// BaseScore 乘普遍性系数之前的分值，影子期离线重定阈值用。
	BaseScore float64 `gorm:"column:base_score;not null" json:"base_score"`
	// WouldAlert 按当前阈值，这个实体是否会产生一条风险告警。
	WouldAlert bool `gorm:"column:would_alert;not null;index" json:"would_alert"`
	// Signals 贡献分值的信号明细（JSON 数组，最多 20 条）。
	Signals   string    `gorm:"column:signals;type:text" json:"signals"`
	Mode      string    `gorm:"column:mode;type:varchar(16);not null" json:"mode"`
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"created_at"`
}

// TableName 指定表名。
func (RiskDecision) TableName() string { return "risk_decisions" }

// SignalPrevalence 一个「规则 + 程序」在近 7 天里出现在多少台登记主机上，由 consumer 每小时从
// 信号表统计。风险累积用它降低普遍行为的分值：几乎每台机器都在做的事，单独出现时说明不了什么。
//
// 只数登记过的主机：信号里的主机号来自上报方，若把未登记的也算进去，伪造大量主机号就能把一个
// 恶意程序刷成「很普遍」，从而压低它的分值。
type SignalPrevalence struct {
	ID     uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	RuleID string `gorm:"column:rule_id;type:varchar(64);not null;uniqueIndex:uk_signal_prevalence,priority:1" json:"rule_id"`
	// Exe 程序路径。超长的截断到 255 字节后作为键。
	Exe        string    `gorm:"column:exe;type:varchar(255);not null;uniqueIndex:uk_signal_prevalence,priority:2" json:"exe"`
	Hosts      int       `gorm:"column:hosts;not null" json:"hosts"`
	TotalHosts int       `gorm:"column:total_hosts;not null" json:"total_hosts"`
	UpdatedAt  LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名。
func (SignalPrevalence) TableName() string { return "signal_prevalence" }
