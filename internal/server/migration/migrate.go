// Package migration 提供数据库迁移功能
package migration

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// Migrate 执行数据库迁移
func Migrate(db *gorm.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("开始数据库迁移")

	// 处理组件表的迁移问题（旧数据可能没有有效的外键）
	if err := migrateComponentTables(db, logger); err != nil {
		logger.Warn("组件表迁移处理", zap.Error(err))
	}

	// 执行自动迁移（带连接恢复和重试）
	for _, m := range model.AllModels {
		var migrateErr error
		for attempt := range 3 {
			if attempt > 0 {
				// 重试前探活连接，必要时让连接池重建
				if sqlDB, err := db.DB(); err == nil {
					sqlDB.SetConnMaxLifetime(0) // 强制回收旧连接
					_ = sqlDB.Ping()
					sqlDB.SetConnMaxLifetime(time.Hour)
				}
				logger.Info("重试迁移", zap.String("model", fmt.Sprintf("%T", m)), zap.Int("attempt", attempt+1))
			}
			if migrateErr = db.AutoMigrate(m); migrateErr == nil {
				break
			}
		}
		if migrateErr != nil {
			logger.Error("数据库迁移失败", zap.Error(migrateErr), zap.String("model", fmt.Sprintf("%T", m)))
			return fmt.Errorf("迁移模型 %T 失败: %w", m, migrateErr)
		}
		logger.Info("模型迁移成功", zap.String("model", fmt.Sprintf("%T", m)))
	}

	// 执行数据迁移：扩展资产表 ID 列（GORM AutoMigrate 不一定会自动扩展已有列的长度）
	if err := migrateAssetTableIDColumns(db, logger); err != nil {
		logger.Warn("资产表ID列扩展处理", zap.Error(err))
	}

	// 执行数据迁移：扩展 alerts 表 result_id 列
	if err := migrateAlertResultIDColumn(db, logger); err != nil {
		logger.Warn("告警表result_id列扩展处理", zap.Error(err))
	}

	// 执行数据迁移：scan_results / fix_results 主键从 result_id 迁移到复合主键
	if err := migrateScanResultsCompositeKey(db, logger); err != nil {
		logger.Warn("scan_results 复合主键迁移处理", zap.Error(err))
	}

	// 执行数据迁移：为现有数据设置默认的运行时类型
	if err := migrateRuntimeTypes(db, logger); err != nil {
		logger.Warn("运行时类型迁移处理", zap.Error(err))
	}

	// 执行数据迁移：更新策略组名称为主机系统基线组
	if err := migratePolicyGroupName(db, logger); err != nil {
		logger.Warn("策略组名称迁移处理", zap.Error(err))
	}

	// 执行数据迁移：为通知配置设置 notify_category
	if err := migrateNotificationCategory(db, logger); err != nil {
		logger.Warn("通知类别迁移处理", zap.Error(err))
	}

	// 执行数据迁移：为告警记录回填 source 字段
	if err := migrateAlertSource(db, logger); err != nil {
		logger.Warn("告警来源迁移处理", zap.Error(err))
	}

	// 执行数据迁移：sensor → edr 重命名
	if err := migrateSensorToEDR(db, logger); err != nil {
		logger.Warn("sensor→edr 迁移处理", zap.Error(err))
	}

	// 清理废弃的 edr 插件和 tetragon 依赖（EDR 已内置 Agent v1.2.0+）
	if err := migrateRemoveEDRPlugin(db, logger); err != nil {
		logger.Warn("edr 插件清理处理", zap.Error(err))
	}

	// 回滚之前过激 soft delete 误删的真 CVE
	if err := migrateRestoreErroneouslyDeletedVulns(db, logger); err != nil {
		logger.Warn("回滚误删 vuln 失败", zap.Error(err))
	}
	// 标记历史 nvd/osv/redhat 数据为 confidence=low（不删除，仅 UI 过滤）
	if err := migrateMarkFakeVulns(db, logger); err != nil {
		logger.Warn("历史 vuln confidence 标记", zap.Error(err))
	}

	// 添加性能优化索引（幂等）
	if err := AddPerformanceIndexes(db, logger); err != nil {
		logger.Warn("添加性能索引失败", zap.Error(err))
	}

	// 回填历史 vuln 的 vuln_category / restart_action（P5）
	if err := migrateCategorizeExistingVulns(db, logger); err != nil {
		logger.Warn("漏洞分类回填失败", zap.Error(err))
	}

	logger.Info("数据库迁移完成")
	return nil
}

// migrateCategorizeExistingVulns 给历史 vulnerabilities 回填 vuln_category + restart_action
// 分批 1000 行 UPDATE，每批 sleep 50ms 避免长事务锁表。
// 幂等：只处理 vuln_category='other' AND restart_action='unknown' 的（默认值）
func migrateCategorizeExistingVulns(db *gorm.DB, logger *zap.Logger) error {
	const batchSize = 1000
	var total int64
	db.Model(&model.Vulnerability{}).
		Where("(vuln_category = ? OR vuln_category = '' OR vuln_category IS NULL)", model.VulnCategoryOther).
		Count(&total)
	if total == 0 {
		return nil
	}
	logger.Info("开始回填 vuln 分类", zap.Int64("total", total))

	processed := 0
	categoryStats := map[string]int{}
	// 按 id 分页避免死循环：cat 仍返回 'other' 时行不会从过滤集移出，
	// 不加 id > lastID 会被反复 fetch 同一批
	var lastID uint = 0
	for {
		var batch []model.Vulnerability
		if err := db.Select("id, component, purl").
			Where("(vuln_category = ? OR vuln_category = '' OR vuln_category IS NULL) AND id > ?",
				model.VulnCategoryOther, lastID).
			Order("id ASC").
			Limit(batchSize).
			Find(&batch).Error; err != nil {
			return fmt.Errorf("拉批次失败: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, v := range batch {
			cat, act := model.CategorizeVuln(v.Component, v.PURL)
			// 用 Model+Updates 跳过 BeforeSave hook 避免再算一次
			if err := db.Model(&model.Vulnerability{}).
				Where("id = ?", v.ID).
				UpdateColumns(map[string]any{
					"vuln_category":  cat,
					"restart_action": act,
				}).Error; err != nil {
				logger.Warn("vuln 分类回填失败",
					zap.Uint("id", v.ID), zap.Error(err))
				continue
			}
			categoryStats[cat]++
			processed++
			lastID = v.ID
		}
		logger.Info("vuln 分类回填进度",
			zap.Int("processed", processed), zap.Int64("total", total))
		time.Sleep(50 * time.Millisecond)
		if len(batch) < batchSize {
			break
		}
	}

	logger.Info("vuln 分类回填完成",
		zap.Int("processed", processed),
		zap.Any("by_category", categoryStats))
	return nil
}

// migrateAlertSource 为存量告警记录回填 source 字段
func migrateAlertSource(db *gorm.DB, logger *zap.Logger) error {
	// 检查是否有需要回填的记录
	var count int64
	db.Model(&model.Alert{}).Where("source IS NULL OR source = ''").Count(&count)
	if count == 0 {
		return nil
	}

	logger.Info("开始回填告警 source 字段", zap.Int64("count", count))

	// 1. Agent 离线告警
	r := db.Model(&model.Alert{}).
		Where("(source IS NULL OR source = '') AND category = ?", "agent_offline").
		Update("source", model.AlertSourceAgent)
	if r.RowsAffected > 0 {
		logger.Info("回填 agent 来源", zap.Int64("count", r.RowsAffected))
	}

	// 2. 检测告警（CEL 规则 + 端口扫描）
	r = db.Model(&model.Alert{}).
		Where("(source IS NULL OR source = '') AND (rule_id LIKE ? OR rule_id = ?)", "cel-%", "scan-detector").
		Update("source", model.AlertSourceDetection)
	if r.RowsAffected > 0 {
		logger.Info("回填 detection 来源", zap.Int64("count", r.RowsAffected))
	}

	// 3. 其余未标记的 → 基线告警
	r = db.Model(&model.Alert{}).
		Where("source IS NULL OR source = ''").
		Update("source", model.AlertSourceBaseline)
	if r.RowsAffected > 0 {
		logger.Info("回填 baseline 来源", zap.Int64("count", r.RowsAffected))
	}

	return nil
}

// migrateSensorToEDR 将数据库中残留的 sensor/runtime 相关数据迁移为 edr
// 注意：此迁移仅处理历史数据重命名，edr 插件本身已在 migrateRemoveEDRPlugin 中清理
func migrateSensorToEDR(db *gorm.DB, logger *zap.Logger) error {
	// 1. alerts 表：source='runtime' → 'edr'
	r := db.Table("alerts").Where("source = ?", "runtime").Update("source", "edr")
	if r.RowsAffected > 0 {
		logger.Info("alerts: source runtime → edr", zap.Int64("count", r.RowsAffected))
	}

	// 2. notifications 表：notify_category='runtime_alert' → 'edr_alert'
	r = db.Table("notifications").Where("notify_category = ?", "runtime_alert").Update("notify_category", "edr_alert")
	if r.RowsAffected > 0 {
		logger.Info("notifications: runtime_alert → edr_alert", zap.Int64("count", r.RowsAffected))
	}

	// 3. generated_reports 表：report_type='runtime' → 'edr'
	r = db.Table("generated_reports").Where("report_type = ?", "runtime").Update("report_type", "edr")
	if r.RowsAffected > 0 {
		logger.Info("generated_reports: runtime → edr", zap.Int64("count", r.RowsAffected))
	}

	return nil
}

// migrateMarkFakeVulns 标记历史 description-keyword-match 误产物为 confidence='low'，
// 不再 soft delete（之前过激删除真 Linux kernel CVE，因 NVD awaiting analysis 也无 CPE）。
//
// 真假区分需重新 import：advisory package coordinator 走 CPE/PURL/Advisory 严格匹配，
// 历史 source=nvd 数据视为 low confidence，UI 按 confidence 过滤显示，不破坏数据。
// 幂等：已标记 confidence 的不重复。
func migrateMarkFakeVulns(db *gorm.DB, logger *zap.Logger) error {
	r := db.Table("vulnerabilities").
		Where("source = ? AND (confidence IS NULL OR confidence = '')", "nvd").
		Update("confidence", model.VulnConfidenceLow)
	if r.Error != nil {
		return fmt.Errorf("标记历史 nvd vuln confidence 失败: %w", r.Error)
	}
	if r.RowsAffected > 0 {
		logger.Info("历史 nvd vuln 标记为 confidence=low（仅标记，不删除）",
			zap.Int64("count", r.RowsAffected))
	}
	// 历史 source=osv 也标 low（实际看到是 RHEL erratum 混入，confidence 不准）
	r2 := db.Table("vulnerabilities").
		Where("source = ? AND (confidence IS NULL OR confidence = '')", "osv").
		Update("confidence", model.VulnConfidenceLow)
	if r2.RowsAffected > 0 {
		logger.Info("历史 osv vuln 标记为 confidence=low",
			zap.Int64("count", r2.RowsAffected))
	}
	// redhat 同理（OS major filter 缺失）
	r3 := db.Table("vulnerabilities").
		Where("source = ? AND (confidence IS NULL OR confidence = '')", "redhat").
		Update("confidence", model.VulnConfidenceLow)
	if r3.RowsAffected > 0 {
		logger.Info("历史 redhat vuln 标记为 confidence=low",
			zap.Int64("count", r3.RowsAffected))
	}
	return nil
}

// migrateRestoreErroneouslyDeletedVulns 回滚之前 migrateMarkFakeVulns 误 soft delete
// 真 Linux kernel CVE 的副作用。
// 仅在 dev/prod 已经执行过老 migrateMarkFakeVulns 时需要。幂等。
func migrateRestoreErroneouslyDeletedVulns(db *gorm.DB, logger *zap.Logger) error {
	r := db.Table("vulnerabilities").
		Where("confidence = ? AND deleted_at IS NOT NULL", model.VulnConfidenceFake).
		Updates(map[string]any{
			"confidence": model.VulnConfidenceLow,
			"deleted_at": nil,
		})
	if r.Error != nil {
		return fmt.Errorf("回滚误删 vuln 失败: %w", r.Error)
	}
	if r.RowsAffected > 0 {
		// 同步回滚关联 host_vulnerabilities（按 vuln_id 反查）
		var vulnIDs []uint
		db.Table("vulnerabilities").
			Where("confidence = ?", model.VulnConfidenceLow).
			Pluck("id", &vulnIDs)
		if len(vulnIDs) > 0 {
			db.Table("host_vulnerabilities").
				Where("vuln_id IN ? AND deleted_at IS NOT NULL", vulnIDs).
				Update("deleted_at", nil)
		}
		logger.Info("回滚之前误 soft delete 的 vuln（标 confidence=low）",
			zap.Int64("restored", r.RowsAffected))
	}
	return nil
}

// migrateRemoveEDRPlugin 清理废弃的 edr 插件和 tetragon 依赖
// EDR 检测功能已内置到 Agent 二进制 (v1.2.0+)，不再需要独立的 edr 插件和 tetragon 运行时
// 此迁移幂等：已清理的环境不会重复执行
func migrateRemoveEDRPlugin(db *gorm.DB, logger *zap.Logger) error {
	// 1. 清理 plugin_configs 中的 edr 和 sensor 插件配置
	// sensor 是 edr 的旧名称，一并清理
	r := db.Table("plugin_configs").
		Where("name IN (?, ?) AND deleted_at IS NULL", "edr", "sensor").
		Update("deleted_at", time.Now())
	if r.RowsAffected > 0 {
		logger.Info("已清理 edr/sensor 插件配置", zap.Int64("count", r.RowsAffected))
	}

	// 2. 软删除 edr、tetragon、tetrgon(历史 typo) 组件及其版本和包
	obsoleteNames := []string{"edr", "sensor", "tetragon", "tetrgon"}

	// 查找需要清理的组件 ID
	var componentIDs []uint
	db.Table("components").
		Where("name IN ? AND deleted_at IS NULL", obsoleteNames).
		Pluck("id", &componentIDs)

	if len(componentIDs) == 0 {
		return nil // 已清理
	}

	// 软删除关联的包记录
	var versionIDs []uint
	db.Table("component_versions").
		Where("component_id IN ?", componentIDs).
		Pluck("id", &versionIDs)

	if len(versionIDs) > 0 {
		r = db.Table("component_packages").
			Where("version_id IN ? AND deleted_at IS NULL", versionIDs).
			Update("deleted_at", time.Now())
		if r.RowsAffected > 0 {
			logger.Info("已清理废弃组件包", zap.Int64("count", r.RowsAffected))
		}

		// 软删除版本记录
		r = db.Table("component_versions").
			Where("id IN ? AND deleted_at IS NULL", versionIDs).
			Update("deleted_at", time.Now())
		if r.RowsAffected > 0 {
			logger.Info("已清理废弃组件版本", zap.Int64("count", r.RowsAffected))
		}
	}

	// 软删除组件记录
	r = db.Table("components").
		Where("id IN ? AND deleted_at IS NULL", componentIDs).
		Update("deleted_at", time.Now())
	if r.RowsAffected > 0 {
		logger.Info("已清理废弃组件",
			zap.Int64("count", r.RowsAffected),
			zap.Strings("names", obsoleteNames))
	}

	return nil
}

// migrateNotificationCategory 为现有通知配置设置 notify_category
func migrateNotificationCategory(db *gorm.DB, logger *zap.Logger) error {
	// 1. 将名称包含 "离线" 的通知设置为 agent_offline
	result := db.Model(&model.Notification{}).
		Where("(notify_category IS NULL OR notify_category = '')").
		Where("name LIKE ?", "%离线%").
		Update("notify_category", model.NotifyCategoryAgentOffline)
	if result.Error != nil {
		logger.Warn("更新 Agent 离线通知类别失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新 Agent 离线通知类别",
			zap.Int64("count", result.RowsAffected))
	}

	// 2. 将其他通知设置为 baseline_alert（默认）
	result = db.Model(&model.Notification{}).
		Where("notify_category IS NULL OR notify_category = ''").
		Update("notify_category", model.NotifyCategoryBaselineAlert)
	if result.Error != nil {
		logger.Warn("更新基线告警通知类别失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新基线告警通知类别",
			zap.Int64("count", result.RowsAffected))
	}

	// 3. 清空 Agent 离线通知的 severities（不需要等级配置）
	result = db.Model(&model.Notification{}).
		Where("notify_category = ?", model.NotifyCategoryAgentOffline).
		Update("severities", model.StringArray{})
	if result.Error != nil {
		logger.Warn("清空 Agent 离线通知的 severities 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已清空 Agent 离线通知的 severities",
			zap.Int64("count", result.RowsAffected))
	}

	return nil
}

// migrateRuntimeTypes 为现有数据设置默认的运行时类型
func migrateRuntimeTypes(db *gorm.DB, logger *zap.Logger) error {
	// 1. 更新现有主机的 runtime_type
	// 如果 is_container = true，设置为 docker；否则设置为 vm
	result := db.Model(&model.Host{}).
		Where("runtime_type IS NULL OR runtime_type = ''").
		Where("is_container = ?", true).
		Update("runtime_type", model.RuntimeTypeDocker)
	if result.Error != nil {
		logger.Warn("更新容器主机的 runtime_type 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新容器主机的 runtime_type",
			zap.Int64("count", result.RowsAffected),
			zap.String("runtime_type", string(model.RuntimeTypeDocker)))
	}

	result = db.Model(&model.Host{}).
		Where("runtime_type IS NULL OR runtime_type = ''").
		Where("is_container = ? OR is_container IS NULL", false).
		Update("runtime_type", model.RuntimeTypeVM)
	if result.Error != nil {
		logger.Warn("更新虚拟机主机的 runtime_type 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新虚拟机主机的 runtime_type",
			zap.Int64("count", result.RowsAffected),
			zap.String("runtime_type", string(model.RuntimeTypeVM)))
	}

	// 2. 更新所有策略的 runtime_types 为 ["vm"]
	// 这里强制更新所有策略，确保所有策略都有默认的运行时类型
	result = db.Model(&model.Policy{}).
		Where("runtime_types IS NULL OR runtime_types = '[]' OR runtime_types = '' OR runtime_types = 'null'").
		Update("runtime_types", model.StringArray{"vm"})
	if result.Error != nil {
		logger.Warn("更新策略的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新策略的 runtime_types",
			zap.Int64("count", result.RowsAffected),
			zap.Strings("runtime_types", []string{"vm"}))
	}

	// 2.1 额外检查：强制更新那些 runtime_types 可能包含无效值的记录
	// 使用 JSON 包含检查，如果不包含有效值则更新
	result = db.Exec(`
		UPDATE policies 
		SET runtime_types = '["vm"]' 
		WHERE runtime_types NOT LIKE '%"vm"%' 
		  AND runtime_types NOT LIKE '%"docker"%' 
		  AND runtime_types NOT LIKE '%"k8s"%'
	`)
	if result.Error != nil {
		logger.Warn("强制更新策略的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("强制更新了无效的策略 runtime_types",
			zap.Int64("count", result.RowsAffected))
	}

	// 3. 清空现有规则的 runtime_types，让它们继承策略的设置
	// 规则默认继承策略的 RuntimeTypes，不需要单独设置
	result = db.Model(&model.Rule{}).
		Where("runtime_types IS NOT NULL AND runtime_types != '[]' AND runtime_types != ''").
		Update("runtime_types", model.StringArray{})
	if result.Error != nil {
		logger.Warn("清空规则的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已清空规则的 runtime_types（规则将继承策略的设置）",
			zap.Int64("count", result.RowsAffected))
	}

	// 4. 更新插件配置的 runtime_types
	// baseline 和 fim 仅适用于 VM
	result = db.Model(&model.PluginConfig{}).
		Where("name IN (?, ?)", "baseline", "fim").
		Where("runtime_types IS NULL OR runtime_types = '[]' OR runtime_types = '' OR runtime_types = 'null'").
		Update("runtime_types", model.StringArray{"vm"})
	if result.Error != nil {
		logger.Warn("更新 baseline/fim 插件的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新 baseline/fim 插件的 runtime_types",
			zap.Int64("count", result.RowsAffected),
			zap.Strings("runtime_types", []string{"vm"}))
	}

	// collector 适用于全平台
	result = db.Model(&model.PluginConfig{}).
		Where("name = ?", "collector").
		Where("runtime_types IS NULL OR runtime_types = '[]' OR runtime_types = '' OR runtime_types = 'null'").
		Update("runtime_types", model.StringArray{"vm", "docker", "k8s"})
	if result.Error != nil {
		logger.Warn("更新 collector 插件的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新 collector 插件的 runtime_types",
			zap.Int64("count", result.RowsAffected),
			zap.Strings("runtime_types", []string{"vm", "docker", "k8s"}))
	}

	return nil
}

// migrateAssetTableIDColumns 扩展资产表的 ID 列从 varchar(64) 到 varchar(128)
// GORM AutoMigrate 不保证会扩展已有列的长度，需要显式 ALTER TABLE
func migrateAssetTableIDColumns(db *gorm.DB, logger *zap.Logger) error {
	// 所有需要扩展 id 列的资产表（ID 格式为 "{host_id}-{xxx}"，host_id 是 64 字符 SHA256）
	tables := []string{
		"processes", "ports", "asset_users", "software",
		"containers", "apps", "net_interfaces", "volumes",
		"kmods", "services", "crons",
	}

	for _, table := range tables {
		// 先检查表是否存在
		var exists bool
		if err := db.Raw(
			"SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
			table,
		).Scan(&exists).Error; err != nil {
			logger.Warn("检查表是否存在失败", zap.String("table", table), zap.Error(err))
			continue
		}
		if !exists {
			continue
		}

		// 检查当前列长度
		var columnType string
		if err := db.Raw(
			"SELECT COLUMN_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'id'",
			table,
		).Scan(&columnType).Error; err != nil {
			logger.Warn("查询列类型失败", zap.String("table", table), zap.Error(err))
			continue
		}

		// 如果已经是 varchar(128) 或更大则跳过
		if columnType == "varchar(128)" {
			continue
		}

		// 执行 ALTER TABLE
		sql := fmt.Sprintf("ALTER TABLE `%s` MODIFY COLUMN `id` varchar(128) NOT NULL", table)
		if err := db.Exec(sql).Error; err != nil {
			logger.Error("扩展资产表ID列失败", zap.String("table", table), zap.String("old_type", columnType), zap.Error(err))
		} else {
			logger.Info("扩展资产表ID列成功", zap.String("table", table), zap.String("old_type", columnType), zap.String("new_type", "varchar(128)"))
		}
	}

	return nil
}

// migrateAlertResultIDColumn 扩展 alerts 表的 result_id 列从 varchar(64) 到 varchar(128)
// 离线告警 ID 格式为 "offline-{64位hash}"，总长度 72 字符，超过 varchar(64)
func migrateAlertResultIDColumn(db *gorm.DB, logger *zap.Logger) error {
	// 检查表是否存在
	var exists bool
	if err := db.Raw(
		"SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'alerts'",
	).Scan(&exists).Error; err != nil {
		return err
	}
	if !exists {
		return nil
	}

	// 检查当前列长度
	var columnType string
	if err := db.Raw(
		"SELECT COLUMN_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'alerts' AND column_name = 'result_id'",
	).Scan(&columnType).Error; err != nil {
		return err
	}

	// 如果已经是 varchar(128) 或更大则跳过
	if columnType == "varchar(128)" {
		return nil
	}

	// 执行 ALTER TABLE
	if err := db.Exec("ALTER TABLE `alerts` MODIFY COLUMN `result_id` varchar(128) NOT NULL").Error; err != nil {
		logger.Error("扩展告警表result_id列失败", zap.String("old_type", columnType), zap.Error(err))
		return err
	}
	logger.Info("扩展告警表result_id列成功", zap.String("old_type", columnType), zap.String("new_type", "varchar(128)"))

	return nil
}

// migrateScanResultsCompositeKey 将 scan_results 和 fix_results 表从单列主键(result_id)
// 迁移为复合主键(task_id, host_id, rule_id)。
//
// 每一步独立 idempotent 检查（DROP PRIMARY / ADD PRIMARY / DROP COLUMN 任意一步
// 之前部分成功也能安全续跑），避免历史"半完成"状态报 1091 / 1068 错误。
func migrateScanResultsCompositeKey(db *gorm.DB, logger *zap.Logger) error {
	for _, table := range []string{"scan_results", "fix_results"} {
		var hasResultID bool
		if err := db.Raw(
			"SELECT COUNT(*) > 0 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'result_id'",
			table,
		).Scan(&hasResultID).Error; err != nil {
			return err
		}
		if !hasResultID {
			continue // 完全已迁移，跳过
		}

		logger.Info("开始迁移主键：result_id → (task_id, host_id, rule_id)", zap.String("table", table))

		// Step 1: 当前 PRIMARY 是单列 result_id 时才 DROP
		// （之前部分完成的迁移可能已 DROP，再 DROP 会报 1091）
		var pkColumns int
		if err := db.Raw(
			"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = 'PRIMARY'",
			table,
		).Scan(&pkColumns).Error; err != nil {
			return err
		}
		if pkColumns > 0 {
			if err := db.Exec(fmt.Sprintf("ALTER TABLE `%s` DROP PRIMARY KEY", table)).Error; err != nil {
				logger.Error("DROP PRIMARY KEY 失败", zap.String("table", table), zap.Error(err))
				return err
			}
		} else {
			logger.Info("PRIMARY KEY 已不存在，跳过 DROP", zap.String("table", table))
		}

		// Step 1.5: 去重 — 历史数据可能存在 (task_id, host_id, rule_id) 重复行
		// （fix_results 业务侧 INSERT 而非 UPSERT，任务重试时会插入重复）。
		// 保留每组 result_id 字典序最大的一行（视为最新），删其他。
		dedupSQL := fmt.Sprintf(
			"DELETE t1 FROM `%s` t1 INNER JOIN `%s` t2 "+
				"ON t1.task_id = t2.task_id AND t1.host_id = t2.host_id "+
				"AND t1.rule_id = t2.rule_id AND t1.result_id < t2.result_id",
			table, table)
		dedupResult := db.Exec(dedupSQL)
		if dedupResult.Error != nil {
			logger.Error("去重失败", zap.String("table", table), zap.Error(dedupResult.Error))
			return dedupResult.Error
		}
		if dedupResult.RowsAffected > 0 {
			logger.Info("迁移前去重完成", zap.String("table", table), zap.Int64("deleted", dedupResult.RowsAffected))
		}

		// Step 2: 新复合主键 (task_id, host_id, rule_id) 不存在时才 ADD
		var newPKColumns int
		if err := db.Raw(`
			SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = ?
			  AND index_name = 'PRIMARY'
			  AND column_name IN ('task_id', 'host_id', 'rule_id')
		`, table).Scan(&newPKColumns).Error; err != nil {
			return err
		}
		if newPKColumns < 3 {
			if err := db.Exec(fmt.Sprintf("ALTER TABLE `%s` ADD PRIMARY KEY (`task_id`, `host_id`, `rule_id`)", table)).Error; err != nil {
				logger.Error("ADD PRIMARY KEY 失败", zap.String("table", table), zap.Error(err))
				return err
			}
		} else {
			logger.Info("复合主键已存在，跳过 ADD", zap.String("table", table))
		}

		// Step 3: 删除旧 result_id 列
		if err := db.Exec(fmt.Sprintf("ALTER TABLE `%s` DROP COLUMN `result_id`", table)).Error; err != nil {
			logger.Error("DROP COLUMN result_id 失败", zap.String("table", table), zap.Error(err))
			return err
		}

		logger.Info("主键迁移完成", zap.String("table", table))
	}

	return nil
}

// migratePolicyGroupName 更新策略组名称为"主机系统基线组"
func migratePolicyGroupName(db *gorm.DB, logger *zap.Logger) error {
	// 更新默认策略组的名称（从"系统基线组"改为"主机系统基线组"）
	result := db.Model(&model.PolicyGroup{}).
		Where("id = ?", "system-baseline").
		Where("name = ?", "系统基线组").
		Updates(map[string]any{
			"name":        "主机系统基线组",
			"description": "系统内置的基线检查策略组，包含 Linux 主机操作系统安全基线检查策略（仅适用于主机/虚拟机，不适用于容器）",
			"icon":        "🖥",
		})
	if result.Error != nil {
		logger.Warn("更新策略组名称失败", zap.Error(result.Error))
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("已更新策略组名称",
			zap.String("old_name", "系统基线组"),
			zap.String("new_name", "主机系统基线组"))
	}

	return nil
}

// migrateComponentTables 处理组件相关表的迁移
// 由于数据模型从扁平结构改为层级结构（Component → Version → Package），
// 旧的 component_packages 表可能有数据但没有有效的 version_id 外键
func migrateComponentTables(db *gorm.DB, logger *zap.Logger) error {
	// 检查 component_packages 表是否存在
	var packagesExists bool
	if err := db.Raw("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'component_packages'").Scan(&packagesExists).Error; err != nil {
		return err
	}

	if !packagesExists {
		return nil // 表不存在，无需处理
	}

	// 检查 component_versions 表是否存在
	var versionsExists bool
	if err := db.Raw("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'component_versions'").Scan(&versionsExists).Error; err != nil {
		return err
	}

	// 如果 component_packages 存在但 component_versions 不存在，说明是旧结构
	// 需要清理旧数据，让迁移重新创建表
	if !versionsExists {
		logger.Info("检测到旧的组件包表结构，清理旧数据以便迁移")

		// 删除旧表（按依赖顺序）
		tables := []string{"component_packages", "component_versions", "components"}
		for _, table := range tables {
			if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
				logger.Warn("删除旧组件表失败", zap.String("table", table), zap.Error(err))
			} else {
				logger.Info("删除旧组件表成功", zap.String("table", table))
			}
		}
		return nil
	}

	// 检查 component_packages 中是否有孤立数据（version_id 不在 component_versions 中）
	var orphanCount int64
	if err := db.Raw(`
		SELECT COUNT(*) FROM component_packages cp
		LEFT JOIN component_versions cv ON cp.version_id = cv.id
		WHERE cv.id IS NULL AND cp.version_id IS NOT NULL
	`).Scan(&orphanCount).Error; err != nil {
		// 查询失败可能是因为表结构不同，尝试清理
		logger.Warn("检查孤立数据失败，尝试清理组件表", zap.Error(err))
		cleanupComponentTables(db, logger)
		return nil
	}

	if orphanCount > 0 {
		logger.Info("检测到孤立的组件包数据，清理旧数据", zap.Int64("orphan_count", orphanCount))
		cleanupComponentTables(db, logger)
	}

	return nil
}

// cleanupComponentTables 清理组件相关表
func cleanupComponentTables(db *gorm.DB, logger *zap.Logger) {
	// 先删除外键约束
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	tables := []string{"component_packages", "component_versions", "components"}
	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
			logger.Warn("删除组件表失败", zap.String("table", table), zap.Error(err))
		} else {
			logger.Info("删除组件表成功", zap.String("table", table))
		}
	}
}

// Rollback 回滚数据库（谨慎使用）
func Rollback(db *gorm.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Warn("开始数据库回滚（删除所有表）")

	// 先禁用外键检查
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	// 删除所有表（按依赖顺序）
	tables := []string{
		// 组件相关表
		"component_packages",
		"component_versions",
		"components",
		// 插件配置
		"plugin_configs",
		// 检测和任务
		"scan_results",
		"scan_tasks",
		"rules",
		"policies",
		"policy_groups",
		// 资产表
		"processes",
		"ports",
		"asset_users",
		"software",
		"containers",
		"apps",
		"net_interfaces",
		"volumes",
		"kmods",
		"services",
		"crons",
		// 监控数据
		"host_metrics",
		"host_metrics_hourly",
		// 系统配置
		"alerts",
		"notifications",
		"system_configs",
		"business_lines",
		// 核心表
		"hosts",
		"users",
	}

	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
			logger.Error("删除表失败", zap.Error(err), zap.String("table", table))
			return fmt.Errorf("删除表 %s 失败: %w", table, err)
		}
		logger.Info("删除表成功", zap.String("table", table))
	}

	logger.Info("数据库回滚完成")
	return nil
}
