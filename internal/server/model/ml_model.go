package model

// MLModelSpec 是 ML 模型的元信息 (复用 Component/ComponentVersion/ComponentPackage 存包体)。
//
// 设计:
//   - ML 模型作为一种 Component (type=ml-model) 走完整 component 上传/分发流程
//   - 本表附加 ML 专属字段: framework / input/output shape / class labels
//   - 一条 spec 对应一个 component_version (1:1 by component_id+version)
type MLModelSpec struct {
	TenantID    string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint   `gorm:"primaryKey" json:"id"`
	ComponentID uint   `gorm:"not null;uniqueIndex:uk_comp_ver,priority:1" json:"component_id"`
	VersionID   uint   `gorm:"not null;uniqueIndex:uk_comp_ver,priority:2" json:"version_id"`
	// 模型属性
	Kind       string `gorm:"size:32;not null;index" json:"kind"` // anomaly / process_classify / login_risk / webshell
	Framework  string `gorm:"size:32;not null" json:"framework"`  // onnx / tflite / treelite
	InputDim   string `gorm:"size:128" json:"input_dim"`          // e.g. "1x32" or "1x3x224x224"
	OutputDim  string `gorm:"size:128" json:"output_dim"`
	ClassLabel string `gorm:"size:512" json:"class_label"` // JSON array, 分类模型用
	// 训练元信息
	TrainedAt     LocalTime `gorm:"type:timestamp" json:"trained_at"`
	TrainSamples  int64     `gorm:"not null;default:0" json:"train_samples"`
	ValidAccuracy float64   `gorm:"type:decimal(5,4)" json:"valid_accuracy"`
	// 部署门控 (G5 模型验证闸门)
	ApprovedBy string    `gorm:"size:64" json:"approved_by"`
	ApprovedAt LocalTime `gorm:"type:timestamp" json:"approved_at"`
	Approved   bool      `gorm:"not null;default:false;index" json:"approved"`
	// 元数据
	CreatedAt LocalTime `json:"created_at"`
	UpdatedAt LocalTime `json:"updated_at"`
}

// TableName 表名。
func (MLModelSpec) TableName() string { return "ml_model_specs" }

// MLModelSubscription 主机/标签订阅模型 (Manager 决定哪些主机加载哪些模型)。
type MLModelSubscription struct {
	TenantID      string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID            uint      `gorm:"primaryKey" json:"id"`
	SpecID        uint      `gorm:"not null;index" json:"spec_id"`
	HostID        string    `gorm:"size:64;index" json:"host_id"`   // 单主机订阅; 空则按 label
	LabelSelector string    `gorm:"size:512" json:"label_selector"` // e.g. "env=prod,role=web"
	Enabled       bool      `gorm:"not null;default:true;index" json:"enabled"`
	CreatedAt     LocalTime `json:"created_at"`
	UpdatedAt     LocalTime `json:"updated_at"`
}

// TableName 表名。
func (MLModelSubscription) TableName() string { return "ml_model_subscriptions" }

// MLModelDeploymentStatus 单主机模型部署状态 (Agent 拉取后回报)。
type MLModelDeploymentStatus struct {
	TenantID    string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint      `gorm:"primaryKey" json:"id"`
	HostID      string    `gorm:"size:64;not null;index;uniqueIndex:uk_host_spec,priority:1" json:"host_id"`
	SpecID      uint      `gorm:"not null;uniqueIndex:uk_host_spec,priority:2" json:"spec_id"`
	Status      string    `gorm:"size:16;not null" json:"status"` // pending / downloading / ready / failed / outdated
	SHA256Local string    `gorm:"size:64" json:"sha256_local"`
	ErrorMsg    string    `gorm:"size:512" json:"error_msg"`
	DeployedAt  LocalTime `gorm:"type:timestamp" json:"deployed_at"`
	UpdatedAt   LocalTime `json:"updated_at"`
}

// TableName 表名。
func (MLModelDeploymentStatus) TableName() string { return "ml_model_deployment_status" }
