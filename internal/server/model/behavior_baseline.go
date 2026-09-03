package model

// BehaviorAlert stores a BDE (Behavior Detection Engine) anomaly alert.
// Generated when a host's behavior profile deviates significantly from its baseline.
type BehaviorAlert struct {
	TenantID  string  `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint    `gorm:"primarykey" json:"id"`
	HostID    string  `gorm:"type:varchar(64);index" json:"host_id"`
	Hostname  string  `gorm:"type:varchar(255)" json:"hostname"`
	RiskScore float64 `gorm:"type:decimal(5,1)" json:"risk_score"`         // 0-100
	Metric    string  `gorm:"type:varchar(50)" json:"metric"`              // e.g. "proc_fork_rate"
	Value     float64 `gorm:"type:decimal(15,4)" json:"value"`             // observed value
	Mean      float64 `gorm:"type:decimal(15,4)" json:"mean"`              // baseline mean
	Stddev    float64 `gorm:"type:decimal(15,4)" json:"stddev"`            // baseline stddev
	ZScore    float64 `gorm:"type:decimal(8,2)" json:"z_score"`            // deviation z-score
	Status    string  `gorm:"type:varchar(20);default:open" json:"status"` // open/resolved/ignored
	// HitCount 同 (host_id, metric) 稳态偏离每次复发累加，不新增行(去重)。
	// 唯一索引 ux_behavior_alerts_host_metric(tenant_id,host_id,metric) 在 migration 手建，
	// 不用 struct tag，避免 AutoMigrate 在存量重复行上建唯一索引失败。
	HitCount  int       `gorm:"default:1" json:"hit_count"`
	CreatedAt LocalTime `json:"created_at"`
	UpdatedAt LocalTime `json:"updated_at"`
}

func (BehaviorAlert) TableName() string { return "behavior_alerts" }

// HostBaselineState persists BDE baseline statistics for crash recovery.
// Welford mean/m2 arrays are stored as JSON text to avoid 13 columns per metric.
type HostBaselineState struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primarykey" json:"id"`
	HostID    string    `gorm:"type:varchar(64);uniqueIndex" json:"host_id"`
	Phase     string    `gorm:"type:varchar(20);default:learning" json:"phase"` // learning/active
	Samples   int       `json:"samples"`
	FirstSeen LocalTime `json:"first_seen"`
	// Algo 标识 M2JSON/BM2JSON 内容的统计口径：
	//   "" 或 "welford" = 旧算法，M2JSON 存 sum of squared deviations（累加型，样本大后基线冻结）；
	//   "ewma"         = 指数加权，M2JSON 存 variance（自适应，跟随常态漂移）。
	// 加载旧行时按 (samples-1) 把 m2 换算成 variance 作为 EWMA 种子（见 persistence.loadFromDB）。
	Algo     string `gorm:"column:algo;type:varchar(16);default:''" json:"-"`
	MeanJSON string `gorm:"type:text" json:"-"` // JSON array [13]float64（扁平基线 mean）
	M2JSON   string `gorm:"type:text" json:"-"` // JSON array [13]float64（EWMA 存 variance；旧行存 m2）
	// 时段分桶基线（P1-A）。旧行无此列 → 加载时桶为空，回退扁平，下次 checkpoint 重建。
	BMeanJSON    string    `gorm:"type:text" json:"-"` // JSON [NumTimeBuckets][13]float64
	BM2JSON      string    `gorm:"type:text" json:"-"` // JSON [NumTimeBuckets][13]float64
	BSamplesJSON string    `gorm:"type:text" json:"-"` // JSON [NumTimeBuckets]int
	CreatedAt    LocalTime `json:"created_at"`
	UpdatedAt    LocalTime `json:"updated_at"`
}

func (HostBaselineState) TableName() string { return "host_baseline_states" }

// BDEMetricTuning 存 BDE 各指标的动态阈值倍率（反馈闭环 M1）。
// 周期统计 behavior_alerts 中该指标的 ignored 率（analyst 标误报），高则抬阈值抑制、
// 低则缓降恢复灵敏；evaluate 读此倍率叠加在静态 metricThresholdMult 上，实现检测→处置→调参闭环。
type BDEMetricTuning struct {
	Metric        string    `gorm:"column:metric;type:varchar(50);primaryKey" json:"metric"`
	ThresholdMult float64   `gorm:"column:threshold_mult;type:decimal(5,2);default:1" json:"threshold_mult"`
	IgnoredRate   float64   `gorm:"column:ignored_rate;type:decimal(5,3)" json:"ignored_rate"` // 上次计算的 ignored 率（观测）
	Samples       int       `gorm:"column:samples" json:"samples"`                             // 上次计算的样本数（ignored+resolved）
	UpdatedAt     LocalTime `json:"updated_at"`
}

func (BDEMetricTuning) TableName() string { return "bde_metric_tunings" }
