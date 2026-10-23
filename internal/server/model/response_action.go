package model

// 处置动作生命周期。
//
// 处置是不可逆或代价高昂的操作——隔离一台主机会切断业务流量。
// 因此执行必须发生在审批之后，而不是"调用了接口就执行"。
const (
	ResponseStatusPending    = "pending"     // 已申请，待审批
	ResponseStatusApproved   = "approved"    // 已审批，待执行
	ResponseStatusRejected   = "rejected"    // 已驳回，不会执行
	ResponseStatusExecuted   = "executed"    // 已执行
	ResponseStatusFailed     = "failed"      // 执行失败
	ResponseStatusRolledBack = "rolled_back" // 已回滚
)

// 处置动作类型。
const (
	ResponseActionIsolateHost = "isolate_host"
	ResponseActionReleaseHost = "release_host"
)

// ResponseAction 是一次人工处置的完整记录：谁申请、谁批准、做了什么、结果如何、能否回滚。
//
// 建这张表的理由不是流程好看，而是三件事此前都做不到：
//   - **审批**：隔离主机原先是一次 API 调用即刻生效，没有第二个人看过；
//   - **幂等**：重试或重复点击会重复执行，而处置动作重复执行的后果不对称
//     （多隔离一次可能切断本已恢复的业务）；
//   - **追溯**：事后无法回答"这台机器当时为什么被隔离、谁批的"。
type ResponseAction struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`

	// IdempotencyKey 由调用方给出，同一 key 只会产生一次执行。
	// 唯一索引是幂等的实现本身，而不只是校验——并发重复提交由数据库挡住。
	IdempotencyKey string `gorm:"column:idempotency_key;type:varchar(128);uniqueIndex;not null" json:"idempotency_key"`

	Action string `gorm:"column:action;type:varchar(40);not null;index" json:"action"`
	Target string `gorm:"column:target;type:varchar(128);not null;index" json:"target"` // 主机 ID 等
	// IncidentID 关联事件，处置结果回流为该事件的证据。
	IncidentID string `gorm:"column:incident_id;type:varchar(128);index" json:"incident_id,omitempty"`

	Status string `gorm:"column:status;type:varchar(20);not null;default:'pending';index" json:"status"`
	Reason string `gorm:"column:reason;type:text" json:"reason"` // 申请理由，必填

	RequestedBy string     `gorm:"column:requested_by;type:varchar(100);not null" json:"requested_by"`
	RequestedAt LocalTime  `gorm:"column:requested_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"requested_at"`
	ApprovedBy  string     `gorm:"column:approved_by;type:varchar(100)" json:"approved_by,omitempty"`
	ApprovedAt  *LocalTime `gorm:"column:approved_at;type:timestamp" json:"approved_at,omitempty"`
	// RejectReason 驳回原因。驳回同样要留下依据，否则申请人不知道该改什么。
	RejectReason string `gorm:"column:reject_reason;type:text" json:"reject_reason,omitempty"`

	ExecutedAt *LocalTime `gorm:"column:executed_at;type:timestamp" json:"executed_at,omitempty"`
	// Result 执行结果摘要，作为证据留存。
	Result string `gorm:"column:result;type:text" json:"result,omitempty"`
	// ErrorMsg 执行失败原因。失败必须能与"未执行"区分。
	ErrorMsg string `gorm:"column:error_msg;type:text" json:"error_msg,omitempty"`

	RolledBackAt *LocalTime `gorm:"column:rolled_back_at;type:timestamp" json:"rolled_back_at,omitempty"`
	RolledBackBy string     `gorm:"column:rolled_back_by;type:varchar(100)" json:"rolled_back_by,omitempty"`

	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (ResponseAction) TableName() string { return "response_actions" }

// Executable 判断该动作当前是否允许执行。
//
// 只有已审批的动作可以执行。这个判断刻意做成模型上的方法而不是散在调用方：
// 任何执行路径都必须经过它，新增执行入口时不会"忘了检查审批"。
func (r *ResponseAction) Executable() bool {
	return r.Status == ResponseStatusApproved
}
