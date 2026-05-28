package model

// 11 state lifecycle for RemediationTask：
//
//	created  → pending → confirmed → dispatched → received
//	         → pre_check → downloading → installing → verifying
//	         → completed / failed / rolled_back
//
// 每次 state 转换写入 RemediationTaskEvent，供 UI 实时拉取（SSE/WebSocket）+ 审计。
const (
	RemTaskStatusCreated    = "created"     // UI 创建未确认
	RemTaskStatusPending    = "pending"     // 等 user confirm
	RemTaskStatusConfirmed  = "confirmed"   // user 已 confirm
	RemTaskStatusDispatched = "dispatched"  // AC 已下发命令给 agent
	RemTaskStatusReceived   = "received"    // agent 已接收
	RemTaskStatusPreCheck   = "pre_check"   // 3 阶段精确预检中
	RemTaskStatusDownload   = "downloading" // pkg manager 拉包
	RemTaskStatusInstall    = "installing"  // pkg manager 装包
	RemTaskStatusVerifying  = "verifying"   // 验证版本翻转
	RemTaskStatusCompleted  = "completed"   // 成功
	RemTaskStatusFailed     = "failed"      // 失败
	RemTaskStatusRolledBack = "rolled_back" // 已回滚
)

// RemediationTaskEvent 修复任务生命周期事件流。
//
// 每次 plugin 上报 progress（DataType 9201）或 manager 内部 state 转换都 append 一行，
// task_id + sequence 唯一，按 sequence 排序还原完整生命周期。
//
// UI WebSocket/SSE 订阅 task_id 的 events，30s 内 stream 全部 stage 转换。
type RemediationTaskEvent struct {
	ID        uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	TaskID    uint      `gorm:"column:task_id;not null;index:idx_rte_task_seq,priority:1" json:"taskId"`
	Sequence  uint      `gorm:"column:sequence;not null;index:idx_rte_task_seq,priority:2" json:"sequence"`
	Stage     string    `gorm:"column:stage;type:varchar(32);not null" json:"stage"` // 11 state 之一
	Message   string    `gorm:"column:message;type:varchar(500)" json:"message"`     // 简短描述
	Detail    string    `gorm:"column:detail;type:text" json:"detail"`               // 长输出/错误堆栈
	Source    string    `gorm:"column:source;type:varchar(32)" json:"source"`        // manager / agent / plugin
	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"createdAt"`
}

// TableName 指定表名。
func (RemediationTaskEvent) TableName() string {
	return "remediation_task_events"
}
