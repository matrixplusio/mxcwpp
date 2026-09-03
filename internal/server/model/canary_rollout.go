package model

import (
	"database/sql/driver"
	"time"
)

// RolloutType 灰度发布类型
type RolloutType string

const (
	RolloutTypeAgent     RolloutType = "agent"         // Agent 版本升级 (v1 已有)
	RolloutTypeRule      RolloutType = "rule"          // 规则推送 (v1 已有)
	RolloutTypeBaseline  RolloutType = "baseline_fix"  // v2: 基线修复批量执行
	RolloutTypeVulnFix   RolloutType = "vuln_fix"      // v2: 漏洞修复 (补丁/包升级)
	RolloutTypeAntivirus RolloutType = "antivirus_act" // v2: 病毒处置 (隔离/还原/删除)
	RolloutTypeConfig    RolloutType = "config_change" // v2: 配置变更 (运行模式/规则启停)
)

// RolloutStatus 灰度发布状态
type RolloutStatus string

const (
	RolloutStatusPending   RolloutStatus = "pending"   // 等待开始
	RolloutStatusRolling   RolloutStatus = "rolling"   // 正在滚动发布
	RolloutStatusPaused    RolloutStatus = "paused"    // 已暂停（手动或自动）
	RolloutStatusCompleted RolloutStatus = "completed" // 全部完成
	RolloutStatusRollback  RolloutStatus = "rollback"  // 已回滚
	RolloutStatusFailed    RolloutStatus = "failed"    // 失败
)

// CanaryRollout 灰度发布记录
type CanaryRollout struct {
	ID      uint          `gorm:"primaryKey" json:"id"`
	Type    RolloutType   `gorm:"type:varchar(20);not null;index" json:"type"`
	Status  RolloutStatus `gorm:"type:varchar(20);not null;default:pending" json:"status"`
	Version string        `gorm:"type:varchar(50);not null" json:"version"`

	// Batch strategy: staged percentage rollout.
	BatchStages   IntArray `gorm:"type:json" json:"batch_stages"`      // e.g. [10, 30, 100]
	CurrentStage  int      `gorm:"default:0" json:"current_stage"`     // index into BatchStages
	StageDelaySec int      `gorm:"default:300" json:"stage_delay_sec"` // wait time between stages (seconds)

	// Health check: auto-rollback if failure rate exceeds threshold.
	FailureThreshold float64 `gorm:"default:0.1" json:"failure_threshold"` // e.g. 0.1 = 10% failure → rollback

	// Progress tracking.
	TotalAgents   int `gorm:"default:0" json:"total_agents"`
	PushedAgents  int `gorm:"default:0" json:"pushed_agents"`
	SuccessAgents int `gorm:"default:0" json:"success_agents"`
	FailedAgents  int `gorm:"default:0" json:"failed_agents"`

	// Metadata.
	CreatedBy       string     `gorm:"type:varchar(100)" json:"created_by"`
	Message         string     `gorm:"type:text" json:"message"`
	StageAdvancedAt *LocalTime `json:"stage_advanced_at"`
	CreatedAt       LocalTime  `json:"created_at"`
	UpdatedAt       LocalTime  `json:"updated_at"`
	CompletedAt     *LocalTime `json:"completed_at"`
}

// TableName 指定表名
func (CanaryRollout) TableName() string {
	return "canary_rollouts"
}

// IntArray 整数数组类型（JSON 存储）
type IntArray []int

// Value implements driver.Valuer.
func (a IntArray) Value() (driver.Value, error) {
	return JSONValue(a)
}

// Scan implements sql.Scanner.
func (a *IntArray) Scan(value any) error {
	return JSONScan(a, value)
}

// CurrentBatchPercent returns the current stage's rollout percentage.
func (r *CanaryRollout) CurrentBatchPercent() int {
	if r.CurrentStage >= len(r.BatchStages) {
		return 100
	}
	return r.BatchStages[r.CurrentStage]
}

// IsComplete returns true if all stages are done.
func (r *CanaryRollout) IsComplete() bool {
	return r.CurrentStage >= len(r.BatchStages)
}

// ShouldAdvance returns true if enough time has passed since last stage advance.
func (r *CanaryRollout) ShouldAdvance() bool {
	if r.StageAdvancedAt == nil {
		return true
	}
	elapsed := time.Since(time.Time(*r.StageAdvancedAt))
	return elapsed >= time.Duration(r.StageDelaySec)*time.Second
}

// FailureRate returns the current failure rate.
func (r *CanaryRollout) FailureRate() float64 {
	if r.PushedAgents == 0 {
		return 0
	}
	return float64(r.FailedAgents) / float64(r.PushedAgents)
}
