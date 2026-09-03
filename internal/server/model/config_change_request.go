package model

// ConfigChangeRequest 配置中心变更审批 (M1-5/P1-1)。
//
// 流程:
//
//  1. 用户 (ops) 提交变更: target_key/old_value/proposed_value/reason
//  2. 审批人 (admin/security_lead) review → approve/reject
//  3. approved → manager 后台 worker apply (FeatureFlag.UpdateBy=approver)
//  4. 整个生命周期落 audit_log
//
// 与 FeatureFlag 关系:
//   - 同 key 同时只允一个 status=pending 的请求
//   - approved 后 manager 用 proposed_value 覆盖 FeatureFlag.Value
//   - rejected → 仅保留记录, 不动 FeatureFlag
//
// 关键审批闸门: 高敏感 key (data_source.* / 全局 mode / KMS 字段) 强制
// 双审批 (request 同 approval_required_count=2) 实现 four-eyes principle。
type ConfigChangeRequest struct {
	TenantID            string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID                  uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TargetTable         string    `gorm:"column:target_table;type:varchar(64);not null;index" json:"target_table"`
	TargetKey           string    `gorm:"column:target_key;type:varchar(128);not null;index" json:"target_key"`
	OldValue            string    `gorm:"column:old_value;type:text" json:"old_value"`
	ProposedValue       string    `gorm:"column:proposed_value;type:text;not null" json:"proposed_value"`
	Reason              string    `gorm:"column:reason;type:text;not null" json:"reason"`
	Status              string    `gorm:"column:status;type:varchar(16);not null;index;default:'pending'" json:"status"`
	RequestedBy         string    `gorm:"column:requested_by;type:varchar(100);not null" json:"requested_by"`
	ApprovalRequiredCnt int       `gorm:"column:approval_required_count;not null;default:1" json:"approval_required_count"`
	ApprovedCount       int       `gorm:"column:approved_count;not null;default:0" json:"approved_count"`
	Approvers           string    `gorm:"column:approvers;type:text" json:"approvers"`
	RejectedBy          string    `gorm:"column:rejected_by;type:varchar(100)" json:"rejected_by"`
	RejectReason        string    `gorm:"column:reject_reason;type:text" json:"reject_reason"`
	AppliedAt           LocalTime `gorm:"column:applied_at;type:timestamp" json:"applied_at"`
	CreatedAt           LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt           LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 表名。
func (ConfigChangeRequest) TableName() string { return "config_change_requests" }

// HighSensitivityKeyPrefixes 高敏感 key 前缀, 命中强制双审批。
var HighSensitivityKeyPrefixes = []string{
	"data_source.",
	"mode.global",
	"npatch.enforce.",
	"kms.",
	"isolation.",
}

// RequiredApprovalCount 给定 key 应该要的审批数 (1 或 2).
func RequiredApprovalCount(key string) int {
	for _, p := range HighSensitivityKeyPrefixes {
		if len(key) >= len(p) && key[:len(p)] == p {
			return 2
		}
	}
	return 1
}
