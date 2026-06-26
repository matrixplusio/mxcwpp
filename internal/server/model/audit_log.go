// Package model 提供数据库模型定义
package model

// 审计参与方类型
const (
	ActorTypeUser   = "user"   // 控制台用户操作
	ActorTypeSystem = "system" // 系统自动任务（调度器/定时任务）
	ActorTypeAgent  = "agent"  // Agent 端事件（注册/上线/命令）
)

// 审计结果
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// AuditLog 操作审计日志模型
type AuditLog struct {
	TenantID     string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID           uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ActorType    string    `gorm:"column:actor_type;type:varchar(20);not null;index;default:'user'" json:"actor_type"` // 参与方：user/system/agent
	Username     string    `gorm:"column:username;type:varchar(100);not null;index" json:"username"`
	Action       string    `gorm:"column:action;type:varchar(64);not null;index" json:"action"`                     // 语义动词，如 user.login/role.delete/vuln.scan
	Outcome      string    `gorm:"column:outcome;type:varchar(20);not null;index;default:'success'" json:"outcome"` // 结果：success/failure
	ResourceType string    `gorm:"column:resource_type;type:varchar(100);not null;index" json:"resource_type"`      // 资源类型，如 hosts/policies/rules
	ResourceID   string    `gorm:"column:resource_id;type:varchar(100)" json:"resource_id"`                         // 资源 ID
	TargetName   string    `gorm:"column:target_name;type:varchar(255)" json:"target_name"`                         // 资源可读名称，如角色名/用户名/主机名
	Path         string    `gorm:"column:path;type:varchar(255);not null" json:"path"`                              // 请求路径
	IP           string    `gorm:"column:ip;type:varchar(50)" json:"ip"`                                            // 操作 IP
	Detail       string    `gorm:"column:detail;type:text" json:"detail"`                                           // 操作详情（请求体摘要）
	ChangeDetail string    `gorm:"column:change_detail;type:text" json:"change_detail"`                             // 变更详情 before→after
	StatusCode   int       `gorm:"column:status_code;type:int" json:"status_code"`                                  // HTTP 响应码
	CreatedAt    LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP;index" json:"created_at"`
}

// TableName 指定表名
func (AuditLog) TableName() string {
	return "audit_logs"
}
