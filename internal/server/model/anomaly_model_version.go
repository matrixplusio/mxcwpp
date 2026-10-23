package model

// AnomalyModelVersion 是一次成功训练产出的模型版本。
//
// 规划明写「任何晋级前必须可一键回滚到上一模型版本」。没有版本就没有回滚：
// 一旦某次重训学坏了（环境突变、数据被污染、特征采集异常），此前唯一的补救方式
// 是等下一个 30 分钟周期，赌它这次能学好——而在那之前检测已经在用坏模型打分。
//
// 保留多份而不是只存最新：只存最新等于"回滚到自己"，仍然没有退路。
type AnomalyModelVersion struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	// ModelName 模型标识，与 AnomalyModelState 同名。
	ModelName string `gorm:"column:model_name;type:varchar(64);not null;index" json:"model_name"`
	// Version 单调递增的版本号，同一 ModelName 内唯一。
	Version int `gorm:"column:version;not null;uniqueIndex:ux_model_version" json:"version"`
	// ModelNameIdx 与 Version 组成唯一索引。
	ModelNameIdx string `gorm:"column:model_name_idx;type:varchar(64);not null;uniqueIndex:ux_model_version" json:"-"`

	// Payload 序列化后的森林（JSON）。
	Payload string `gorm:"column:payload;type:longtext" json:"-"`
	// Samples 训练所用样本数。
	Samples int `gorm:"column:samples;not null;default:0" json:"samples"`
	// MaxDriftSigma 该版本训练时相对长期参照的最大偏移，用于事后判断
	// 「这个版本是在什么环境下学出来的」。
	MaxDriftSigma float64 `gorm:"column:max_drift_sigma;type:double;default:0" json:"max_drift_sigma"`
	// Active 是否为当前生效版本。回滚即把 Active 移到旧版本上。
	Active bool `gorm:"column:active;not null;default:false;index" json:"active"`
	// RolledBackFrom 记录该版本是被哪个版本回滚回来的，空表示正常训练产生。
	RolledBackFrom int `gorm:"column:rolled_back_from;default:0" json:"rolled_back_from,omitempty"`

	CreatedAt LocalTime `gorm:"type:timestamp;default:CURRENT_TIMESTAMP;index" json:"created_at"`
}

// TableName 指定表名。
func (AnomalyModelVersion) TableName() string { return "anomaly_model_versions" }

// MaxRetainedModelVersions 保留的历史版本数。
//
// 5 个版本对应约 2.5 小时的训练历史（30 分钟一轮）。再多的价值有限：
// 更久之前的模型面对的已经是另一个环境，回滚到它未必比重新训练更好。
const MaxRetainedModelVersions = 5
