package model

// RemediationTask 漏洞修复任务
//
// Status 完整生命周期（P5.6 扩展）：
//
//	pending → confirmed → running → success
//	                           ↓ (P5.6 改：success 改为 success_pending_verify 等 user 确认)
//	                    success_pending_verify
//	                           ↓ (user 点 "确认已执行")
//	                       verifying  (server 触发该 host_vuln pre-check 复测)
//	                           ↓ (pre-check 回报)
//	               verified / verify_failed / verify_blocked
//
// 兼容性：历史 status='success' 视为已 verified（legacy），新任务走完整 5 状态。
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
	Status       string     `gorm:"column:status;type:varchar(30);not null;default:'pending';index" json:"status"`
	ExecOutput   string     `gorm:"column:exec_output;type:text" json:"execOutput"`
	ExitCode     *int       `gorm:"column:exit_code;type:int" json:"exitCode"`
	CreatedBy    string     `gorm:"column:created_by;type:varchar(64)" json:"createdBy"`
	ConfirmedBy  string     `gorm:"column:confirmed_by;type:varchar(64)" json:"confirmedBy"`
	ConfirmedAt  *LocalTime `gorm:"column:confirmed_at;type:timestamp" json:"confirmedAt"`
	StartedAt    *LocalTime `gorm:"column:started_at;type:timestamp" json:"startedAt"`
	FinishedAt   *LocalTime `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
	// P5.6 复测字段
	ExecConfirmedBy string     `gorm:"column:exec_confirmed_by;type:varchar(64)" json:"execConfirmedBy"` // user 点"确认已执行"
	ExecConfirmedAt *LocalTime `gorm:"column:exec_confirmed_at;type:timestamp" json:"execConfirmedAt"`
	VerifyStatus    string     `gorm:"column:verify_status;type:varchar(30);default:''" json:"verifyStatus"` // pending_user / verifying / verified / verify_failed / verify_blocked
	VerifyMessage   string     `gorm:"column:verify_message;type:varchar(500)" json:"verifyMessage"`         // 复测说明（如 "仓库版本仍 < 修复版本"）
	VerifiedAt      *LocalTime `gorm:"column:verified_at;type:timestamp" json:"verifiedAt"`
	CreatedAt       LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt       LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// RemediationTask 主状态枚举（写入 task.status；与 event.stage 解耦）。
// P5.6 新增 SuccessPendingVerify / Verifying / Verified / VerifyFailed / VerifyBlocked。
// 已有 RemTaskStatusPending/Confirmed/Verifying/Failed 在 remediation_task_event.go 定义为 stage 用，
// 主状态借用名时复用同值，新增的用 RemTaskMain* 前缀避免冲突。
const (
	RemTaskMainRunning              = "running"
	RemTaskMainSuccess              = "success"                // legacy / 直接成功
	RemTaskMainSuccessPendingVerify = "success_pending_verify" // P5.6: agent exit 0，等 user 确认
	RemTaskMainVerifying            = "main_verifying"         // P5.6: user 已确认，复测中（区别于 stage verifying）
	RemTaskMainVerified             = "verified"               // P5.6: 复测通过
	RemTaskMainVerifyFailed         = "verify_failed"          // P5.6: 复测发现仍 unpatched
	RemTaskMainVerifyBlocked        = "verify_blocked"         // P5.6: 复测无法判定
	RemTaskMainCancelled            = "cancelled"
)

// TableName 指定表名
func (RemediationTask) TableName() string {
	return "remediation_tasks"
}
