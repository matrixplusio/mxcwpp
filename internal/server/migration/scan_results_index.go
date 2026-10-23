package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ensureScanResultsDashboardIndex 为 scan_results 创建 (host_id, rule_id, checked_at) 复合索引。
//
// 写入方重算最新行标记、基线评分按 (host_id, rule_id) 取 checked_at 最新的结果，
// 都靠它定位「每主机每规则最新结果」。该索引使分区天然有序，省去 576k 行
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

// syncScanResultsLatestFlag 按 checked_at 校正 scan_results.is_latest，只改与事实不符的行。
//
// 新列上线时全为 0，需要回填一次；写入方升级前后的空档里落库的结果也会缺标记。
// 每次启动都跑一遍做自愈：结果集已按保留期封顶，只更新不一致的行，成本是一次排序。
// 依赖 MySQL 的多表 UPDATE，其它方言跳过（测试库由写入方逐行维护）。
func syncScanResultsLatestFlag(db *gorm.DB, logger *zap.Logger) error {
	if db.Dialector.Name() != "mysql" || !db.Migrator().HasColumn("scan_results", "is_latest") {
		return nil
	}
	res := db.Exec(`
		UPDATE scan_results s
		JOIN (
			SELECT task_id, host_id, rule_id,
				ROW_NUMBER() OVER (PARTITION BY host_id, rule_id ORDER BY checked_at DESC, task_id DESC) = 1 AS want
			FROM scan_results
		) r ON r.task_id = s.task_id AND r.host_id = s.host_id AND r.rule_id = s.rule_id
		SET s.is_latest = r.want
		WHERE s.is_latest <> r.want`)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		logger.Info("已校正 scan_results 最新结果标记", zap.Int64("rows", res.RowsAffected))
	}
	return nil
}

// dropSupersededIndexes 删掉已被新索引取代的旧索引。AutoMigrate 只增不减，旧索引不删就一直占着写入开销。
func dropSupersededIndexes(db *gorm.DB, logger *zap.Logger) {
	for _, idx := range []struct{ table, name string }{
		// 按风险排序的索引只在窗口内故事线很多时快；窗口内不足所需条数时要把该主机全部历史读完。
		// 已改回按时间取最近若干条（idx_story_host_seen），这个索引不再使用。
		{"storylines", "idx_story_host_risk_seen"},
	} {
		if !db.Migrator().HasTable(idx.table) || !db.Migrator().HasIndex(idx.table, idx.name) {
			continue
		}
		if err := db.Migrator().DropIndex(idx.table, idx.name); err != nil {
			logger.Warn("删除旧索引失败", zap.String("table", idx.table), zap.String("index", idx.name), zap.Error(err))
			continue
		}
		logger.Info("已删除被取代的旧索引", zap.String("table", idx.table), zap.String("index", idx.name))
	}
}
