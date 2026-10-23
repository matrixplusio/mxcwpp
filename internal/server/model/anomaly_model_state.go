package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// FloatArray 浮点数组，存为 JSON 列。
type FloatArray []float64

// Value 实现 driver.Valuer。
func (a FloatArray) Value() (driver.Value, error) {
	return json.Marshal(a)
}

// Scan 实现 sql.Scanner。
//
// 类型不符时返回错误而不是静默置空：这个字段存的是参照基线，
// 悄悄变成空数组意味着投毒防护失效，而不会有任何人发现。
func (a *FloatArray) Scan(value any) error {
	if value == nil {
		*a = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, a)
	case string:
		return json.Unmarshal([]byte(v), a)
	default:
		return fmt.Errorf("FloatArray: 无法从 %T 读取", value)
	}
}

// AnomalyModelState 持久化异常检测模型的训练状态。
//
// 此前模型只活在内存里：进程一重启，样本缓冲清空，要重新攒够样本再等一个重训周期
// 才恢复检测能力。这段时间里检测器照常运行、指标照常上报，只是什么都发现不了——
// 又一个"看起来在工作"的空窗。发布、扩容、崩溃重启都会触发它。
//
// 存的是长期参照基线与训练元数据，不存森林本身：森林可以用缓冲样本快速重建，
// 而参照基线一旦丢失就再也长不回来（它必须来自一段未被污染的历史）。
type AnomalyModelState struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	// ModelName 模型标识，当前只有一个 iforest_host_metrics。
	ModelName string `gorm:"column:model_name;type:varchar(64);not null;uniqueIndex" json:"model_name"`

	// ReferenceMean / ReferenceStdev 长期参照基线，JSON 存浮点数组。
	ReferenceMean  FloatArray `gorm:"column:reference_mean;type:json" json:"reference_mean"`
	ReferenceStdev FloatArray `gorm:"column:reference_stdev;type:json" json:"reference_stdev"`
	// ReferenceSamples 建立参照时使用的样本数。
	ReferenceSamples int `gorm:"column:reference_samples;default:0" json:"reference_samples"`
	// ReferenceBuiltAt 参照建立时间。参照越老越可信（覆盖的正常行为更全），
	// 但也越可能与当前环境脱节，因此必须可见。
	ReferenceBuiltAt *LocalTime `gorm:"column:reference_built_at;type:timestamp;null" json:"reference_built_at,omitempty"`

	// LastTrainedAt 上次成功训练时间。被拒绝的重训不更新它。
	LastTrainedAt *LocalTime `gorm:"column:last_trained_at;type:timestamp;null" json:"last_trained_at,omitempty"`
	// RejectedRetrains 累计被拒绝的重训次数，用于判断模型是否长期学不进新数据。
	RejectedRetrains int `gorm:"column:rejected_retrains;default:0" json:"rejected_retrains"`

	CreatedAt LocalTime `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt LocalTime `gorm:"type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名。
func (AnomalyModelState) TableName() string { return "anomaly_model_states" }
