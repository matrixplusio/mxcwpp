package model

import (
	"database/sql/driver"
)

// AnomalyTriggerContext 描述异常告警的触发证据：触发的指标值 + 攻击链 IOC。
// 仅在 Correlation/IForest 告警生成时填充，给 SOC 分析师定位"为什么报"以及"攻击链上看到什么"。
type AnomalyTriggerContext struct {
	// ElevatedMetrics: 触发判定的具体指标（值 + 历史均值 + 偏离倍率）
	ElevatedMetrics []ElevatedMetric `json:"elevated_metrics,omitempty"`

	// MetricSnapshot: 触发时刻的全部 13 维 BDE 特征快照
	MetricSnapshot map[string]float64 `json:"metric_snapshot,omitempty"`

	// 攻击链 IOC（按 pattern 类型回查 ebpf_events 5 分钟窗口聚合）
	SuspiciousIPs     []string `json:"suspicious_ips,omitempty"`     // 关联可疑远端 IP
	SuspiciousDomains []string `json:"suspicious_domains,omitempty"` // 关联可疑 DNS 域名
	SensitiveFiles    []string `json:"sensitive_files,omitempty"`    // 命中的敏感文件路径
	ProcessChain      []string `json:"process_chain,omitempty"`      // 高频执行的进程 exe 路径
	ScannedPorts      []string `json:"scanned_ports,omitempty"`      // 扫描的远端端口

	// SourceEventIDs: 取样的原始 ebpf_events row 标识（host_id + timestamp，最多 N 条）
	SourceEventIDs []string `json:"source_event_ids,omitempty"`

	// WindowStart/End: 证据采样的时间窗（用于 UI 跳转到 EDR 列表过滤）
	WindowStart string `json:"window_start,omitempty"`
	WindowEnd   string `json:"window_end,omitempty"`
}

// ElevatedMetric 单个触发指标的详细信息
type ElevatedMetric struct {
	Name     string  `json:"name"`     // proc_exec_count 等 13 个 BDE 特征名
	Current  float64 `json:"current"`  // 当前观察值
	Baseline float64 `json:"baseline"` // 主机历史均值
	Ratio    float64 `json:"ratio"`    // current / baseline
}

// Value 实现 driver.Valuer：GORM 写入时序列化为 JSON。
func (c AnomalyTriggerContext) Value() (driver.Value, error) { return JSONValue(c) }

// Scan 实现 sql.Scanner：GORM 读取时反序列化 JSON。
func (c *AnomalyTriggerContext) Scan(value any) error { return JSONScan(c, value) }

// AnomalyAlert represents an ML-detected behavioral anomaly.
type AnomalyAlert struct {
	TenantID       string                `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID             uint                  `gorm:"primarykey" json:"id"`
	HostID         string                `gorm:"type:varchar(64);index" json:"host_id"`
	Hostname       string                `gorm:"type:varchar(255)" json:"hostname"`
	AlertType      string                `gorm:"type:varchar(50);index" json:"alert_type"`        // isolation_forest / correlation
	PatternName    string                `gorm:"type:varchar(100)" json:"pattern_name"`           // correlation pattern name (c2_beacon, etc)
	Severity       string                `gorm:"type:varchar(20);default:medium" json:"severity"` // critical/high/medium/low
	AnomalyScore   float64               `gorm:"type:double;default:0" json:"anomaly_score"`      // 0.0-1.0
	TopMetric      string                `gorm:"type:varchar(100)" json:"top_metric"`             // most anomalous metric name
	TopValue       float64               `gorm:"type:double;default:0" json:"top_value"`          // observed value of top metric
	Description    string                `gorm:"type:text" json:"description"`
	TriggerContext AnomalyTriggerContext `gorm:"type:text" json:"trigger_context,omitempty"`  // 触发证据 + IOC（JSON 文本列）
	Status         string                `gorm:"type:varchar(20);default:open" json:"status"` // open/confirmed/false_positive
	ResolvedBy     string                `gorm:"type:varchar(100)" json:"resolved_by,omitempty"`
	CreatedAt      LocalTime             `json:"created_at"`
	UpdatedAt      LocalTime             `json:"updated_at"`
}

func (AnomalyAlert) TableName() string { return "anomaly_alerts" }
