package model

import (
	"errors"

	"gorm.io/gorm"
)

// ResultStatus 检测结果状态
type ResultStatus string

const (
	ResultStatusPass  ResultStatus = "pass"
	ResultStatusFail  ResultStatus = "fail"
	ResultStatusError ResultStatus = "error"
	ResultStatusNA    ResultStatus = "na" // 不适用
)

// ScanResult 检测结果模型
// 复合主键 (task_id, host_id, rule_id) — 一次任务中每台主机的每条规则只有一条结果
//
// 每次复扫都追加整套新行。IsLatest 标出每主机每规则 checked_at 最新的那一行，
// 由写入方维护：读「当前状态」的统计直接按它过滤，不必每次用窗口函数全表重排。
type ScanResult struct {
	TenantID      string       `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	TaskID        string       `gorm:"primaryKey;column:task_id;type:varchar(64);not null" json:"task_id"`
	HostID        string       `gorm:"primaryKey;column:host_id;type:varchar(64);not null" json:"host_id"`
	RuleID        string       `gorm:"primaryKey;column:rule_id;type:varchar(64);not null" json:"rule_id"`
	Hostname      string       `gorm:"column:hostname;type:varchar(255)" json:"hostname"`
	PolicyID      string       `gorm:"column:policy_id;type:varchar(64);index;index:idx_scan_results_latest,priority:3" json:"policy_id"`
	PolicyName    string       `gorm:"column:policy_name;type:varchar(255)" json:"policy_name"`
	Status        ResultStatus `gorm:"column:status;type:varchar(20);not null;index:idx_scan_results_latest,priority:2" json:"status"`
	Severity      string       `gorm:"column:severity;type:varchar(20);index:idx_scan_results_latest,priority:4" json:"severity"`
	Category      string       `gorm:"column:category;type:varchar(50)" json:"category"`
	Title         string       `gorm:"column:title;type:varchar(255)" json:"title"`
	Actual        string       `gorm:"column:actual;type:text" json:"actual"`
	Expected      string       `gorm:"column:expected;type:text" json:"expected"`
	FixSuggestion string       `gorm:"column:fix_suggestion;type:text" json:"fix_suggestion"`
	CheckedAt     LocalTime    `gorm:"column:checked_at;type:timestamp;not null" json:"checked_at"`
	CreatedAt     LocalTime    `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	IsLatest      bool         `gorm:"column:is_latest;not null;default:false;index:idx_scan_results_latest,priority:1" json:"is_latest"`

	// 关联关系（可选，主要用于查询时预加载）
	Host Host `gorm:"foreignKey:HostID;references:HostID" json:"host,omitempty"`
	Rule Rule `gorm:"foreignKey:RuleID;references:RuleID" json:"rule,omitempty"`
}

// TableName 指定表名
func (ScanResult) TableName() string {
	return "scan_results"
}

// MarkLatestScanResult 重算某主机某规则哪一行是最新结果（checked_at 最大，同时刻取 task_id 大者）。
//
// 按 checked_at 重算而不是"刚写入的就是最新"：结果可能乱序到达，晚到的旧扫描不能顶掉新结果。
// 须在写入该行的同一事务里调用，否则并发读会短暂看到没有或多于一条最新行。
func MarkLatestScanResult(tx *gorm.DB, hostID, ruleID string) error {
	var latest ScanResult
	err := tx.Select("task_id").
		Where("host_id = ? AND rule_id = ?", hostID, ruleID).
		Order("checked_at DESC, task_id DESC").
		Limit(1).Take(&latest).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := tx.Model(&ScanResult{}).
		Where("host_id = ? AND rule_id = ? AND is_latest = ? AND task_id <> ?", hostID, ruleID, true, latest.TaskID).
		Update("is_latest", false).Error; err != nil {
		return err
	}
	return tx.Model(&ScanResult{}).
		Where("host_id = ? AND rule_id = ? AND task_id = ? AND is_latest = ?", hostID, ruleID, latest.TaskID, false).
		Update("is_latest", true).Error
}
