package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ensureScanResultsDashboardIndex 为 scan_results 创建 (host_id, rule_id, checked_at) 复合索引。
//
// Dashboard 合规率/Top3 与基线评分均按 ROW_NUMBER() OVER (PARTITION BY host_id, rule_id
// ORDER BY checked_at DESC) 取「每主机每规则最新结果」。该索引使分区天然有序，省去 576k 行
// 全表 filesort，是窗口函数查询的关键加速。复合主键 (task_id, host_id, rule_id) 以 task_id
// 打头，无法服务此分区，需独立索引。
func ensureScanResultsDashboardIndex(db *gorm.DB, logger *zap.Logger) error {
	if !db.Migrator().HasTable("scan_results") {
		return nil
	}
	const idxName = "idx_scan_results_host_rule_checked"
	if db.Migrator().HasIndex("scan_results", idxName) {
		return nil
	}
	stmt := "CREATE INDEX " + idxName +
		" ON scan_results (host_id, rule_id, checked_at)"
	if err := db.Exec(stmt).Error; err != nil {
		logger.Warn("创建 scan_results dashboard 索引失败（可能已存在）", zap.Error(err))
		return nil
	}
	logger.Info("已创建 scan_results dashboard 索引")
	return nil
}
