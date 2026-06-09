package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// dropHostIsolationsHostIDUnique 移除 host_isolations.host_id 旧版 UNIQUE 索引.
//
// 旧版 model.HostIsolation 把 host_id 标 uniqueIndex, 实际语义是事件流 (每次 isolate/release
// 写一条记录), 不应 UNIQUE. 旧索引会导致 "Duplicate entry for key
// host_isolations.idx_host_isolations_host_id" 阻止同主机第二次 isolate.
//
// 本迁移:
//  1. 检测旧 UNIQUE 索引是否存在; 不存在则跳过 (新表已 OK)
//  2. DROP 旧 UNIQUE
//  3. 让后续 AutoMigrate 重建为普通 INDEX
//
// 幂等: 多次运行无副作用.
func dropHostIsolationsHostIDUnique(db *gorm.DB, logger *zap.Logger) error {
	// 表不存在 (新部署还没建表) 直接跳过
	if !db.Migrator().HasTable("host_isolations") {
		return nil
	}

	var count int64
	if err := db.Raw(`
		SELECT COUNT(*) FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE()
		  AND TABLE_NAME = 'host_isolations'
		  AND INDEX_NAME = 'idx_host_isolations_host_id'
		  AND NON_UNIQUE = 0
	`).Scan(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return nil
	}

	logger.Info("发现旧版 host_isolations.host_id UNIQUE 索引, 转普通索引")
	if err := db.Exec("ALTER TABLE host_isolations DROP INDEX idx_host_isolations_host_id").Error; err != nil {
		return err
	}
	// 重建普通索引 (GORM AutoMigrate 也会建, 但 explicit 一次更稳)
	if err := db.Exec("ALTER TABLE host_isolations ADD INDEX idx_host_isolations_host_id (host_id)").Error; err != nil {
		return err
	}
	logger.Info("host_isolations.host_id UNIQUE → INDEX 转换完成")
	return nil
}
