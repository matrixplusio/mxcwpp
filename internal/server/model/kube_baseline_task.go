package model

// KubeBaselineTaskStatus 基线检查任务状态
type KubeBaselineTaskStatus string

const (
	BaselineTaskPending KubeBaselineTaskStatus = "pending" // 已入队，等待 worker 执行
	BaselineTaskRunning KubeBaselineTaskStatus = "running"
	BaselineTaskDone    KubeBaselineTaskStatus = "done"
	BaselineTaskFailed  KubeBaselineTaskStatus = "failed"
)

// KubeBaselineTask 一次基线检查任务（每次检测 = 一个任务，结果挂在 task 下）
type KubeBaselineTask struct {
	TenantID    string                 `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint                   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	ClusterID   uint                   `gorm:"column:cluster_id;not null;index" json:"clusterId"`
	ClusterName string                 `gorm:"column:cluster_name;type:varchar(255)" json:"clusterName"`
	Status      KubeBaselineTaskStatus `gorm:"column:status;type:varchar(20);default:'running';index" json:"status"`
	Total       int                    `gorm:"column:total;default:0" json:"total"`
	Passed      int                    `gorm:"column:passed;default:0" json:"passed"`
	Failed      int                    `gorm:"column:failed;default:0" json:"failed"`
	ErrorCnt    int                    `gorm:"column:error_cnt;default:0" json:"errorCnt"`
	PassRate    float64                `gorm:"column:pass_rate;type:decimal(5,2);default:0" json:"passRate"`
	ErrorMsg    string                 `gorm:"column:error_msg;type:text" json:"errorMsg"`
	StartedAt   LocalTime              `gorm:"column:started_at;type:timestamp" json:"startedAt"`
	FinishedAt  *LocalTime             `gorm:"column:finished_at;type:timestamp" json:"finishedAt"`
	CreatedAt   LocalTime              `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

func (KubeBaselineTask) TableName() string {
	return "kube_baseline_tasks"
}
