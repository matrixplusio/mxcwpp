// Package database 提供数据库连接管理
package database

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/common/tenant"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/migration"
)

// DB 是全局数据库实例
var DB *gorm.DB

// mapLogLevel 将应用日志级别映射为 GORM 日志级别
func mapLogLevel(level string) gormLogger.LogLevel {
	switch level {
	case "debug", "info":
		return gormLogger.Warn // debug/info 模式下只记录慢查询和错误
	case "warn", "warning":
		return gormLogger.Warn
	case "error", "dpanic", "panic", "fatal":
		return gormLogger.Error // error 及以上只记录错误
	default:
		return gormLogger.Warn
	}
}

// Init 初始化数据库连接
func Init(cfg config.DatabaseConfig, zapLogger *zap.Logger, logCfg ...config.LogConfig) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	// 根据应用日志级别确定 GORM 日志级别
	gormLogLevel := gormLogger.Warn
	if len(logCfg) > 0 && logCfg[0].Level != "" {
		gormLogLevel = mapLogLevel(logCfg[0].Level)
	}

	// 配置 Gorm 日志
	var gormLog gormLogger.Interface
	if zapLogger != nil {
		// 将 Zap logger 适配为 Gorm logger
		gormLog = gormLogger.New(
			&zapWriter{logger: zapLogger},
			gormLogger.Config{
				SlowThreshold:             1 * time.Second,
				LogLevel:                  gormLogLevel,
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		)
	} else {
		gormLog = gormLogger.Default
	}

	// 根据数据库类型创建连接
	switch cfg.Type {
	case "mysql":
		db, err = gorm.Open(mysql.Open(cfg.MySQL.DSN()), &gorm.Config{
			Logger: gormLog,
		})
		if err != nil {
			return nil, fmt.Errorf("连接 MySQL 失败: %w", err)
		}

		// 配置连接池
		sqlDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("获取数据库实例失败: %w", err)
		}
		sqlDB.SetMaxIdleConns(cfg.MySQL.MaxIdleConns)
		sqlDB.SetMaxOpenConns(cfg.MySQL.MaxOpenConns)
		sqlDB.SetConnMaxLifetime(cfg.MySQL.ConnMaxLifetime)

	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.Postgres.DSN()), &gorm.Config{
			Logger: gormLog,
		})
		if err != nil {
			return nil, fmt.Errorf("连接 PostgreSQL 失败: %w", err)
		}

		// 配置连接池
		sqlDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("获取数据库实例失败: %w", err)
		}
		sqlDB.SetMaxIdleConns(cfg.Postgres.MaxIdleConns)
		sqlDB.SetMaxOpenConns(cfg.Postgres.MaxOpenConns)
		sqlDB.SetConnMaxLifetime(cfg.Postgres.ConnMaxLifetime)

	default:
		return nil, fmt.Errorf("不支持的数据库类型: %s", cfg.Type)
	}

	// 执行数据库迁移（用 MySQL user-level lock 串行化多进程并发迁移）
	//
	// 背景：mxctl deploy 同时启动 manager + agentcenter + consumer 3 进程，
	// 各自 gorm.AutoMigrate 同表 ALTER → MySQL deadlock (Error 1213) → fatal exit。
	// 解决：用 GET_LOCK('mxcwpp_migration', 120) 互斥，串行迁移；其他进程等待。
	// 仅 MySQL 支持 GET_LOCK；其他 driver 跳过。
	if err := runMigrationWithLock(db, cfg.Type, zapLogger); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	// 注册 Prometheus 埋点 callback（gorm 每次 SQL 后记录耗时 histogram）
	// 失败仅警告，不阻塞启动（监控埋点非关键路径）
	if err := RegisterPromCallback(db); err != nil && zapLogger != nil {
		zapLogger.Warn("注册 gorm Prometheus callback 失败", zap.Error(err))
	}

	// 注册多租户 INSERT 自动注入 hook（v2.0 多租户安全网）
	// model 有 TenantID 字段时，从 ctx 自动注入；调用方显式赋值不会覆盖。
	// 详见 docs/multi-tenant.md §3.3
	if err := tenant.RegisterAutoInjectHook(db); err != nil && zapLogger != nil {
		zapLogger.Warn("注册 tenant auto-inject hook 失败", zap.Error(err))
	}

	// 保存全局实例
	DB = db

	if zapLogger != nil {
		zapLogger.Info("数据库连接成功", zap.String("type", cfg.Type))
	}

	return db, nil
}

// runMigrationWithLock 在 MySQL user-level lock 保护下跑迁移。
//
// 多进程同时启动时，只有持锁者跑 AutoMigrate，其他等待。
// 锁基于 client session（持锁连接独立 Conn，保证 GET_LOCK/RELEASE_LOCK 同 session）。
// 锁超时 120s（覆盖单次迁移最长时间）；超时则降级跑迁移（最坏情况退回 deadlock 重试逻辑）。
func runMigrationWithLock(db *gorm.DB, dbType string, zapLogger *zap.Logger) error {
	// 非 MySQL 直接迁移
	if dbType != "mysql" {
		return migration.Migrate(db, zapLogger)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取 *sql.DB 失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()

	// 独立 Conn 用于持锁（与 gorm 内部 pool 隔离）
	lockConn, err := sqlDB.Conn(ctx)
	if err != nil {
		if zapLogger != nil {
			zapLogger.Warn("无法获取迁移锁连接，跳过锁直接迁移", zap.Error(err))
		}
		return migration.Migrate(db, zapLogger)
	}
	defer lockConn.Close()

	const lockName = "mxcwpp_migration"
	const lockTimeoutSec = 120

	var got int
	if err := lockConn.QueryRowContext(ctx,
		"SELECT GET_LOCK(?, ?)", lockName, lockTimeoutSec).Scan(&got); err != nil {
		if zapLogger != nil {
			zapLogger.Warn("GET_LOCK 失败，降级直接迁移", zap.Error(err))
		}
		return migration.Migrate(db, zapLogger)
	}
	if got != 1 {
		if zapLogger != nil {
			zapLogger.Warn("GET_LOCK 等待超时，降级直接迁移",
				zap.Int("got", got),
				zap.Int("timeout_sec", lockTimeoutSec))
		}
		return migration.Migrate(db, zapLogger)
	}

	if zapLogger != nil {
		zapLogger.Info("已获取迁移锁，开始迁移", zap.String("lock", lockName))
	}

	// 持锁期间跑迁移；锁连接独立，gorm 走自己的 pool 跑 ALTER
	migErr := migration.Migrate(db, zapLogger)

	// 释放锁（即使迁移失败也要释放，避免阻塞下一个进程）
	if _, relErr := lockConn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", lockName); relErr != nil && zapLogger != nil {
		zapLogger.Warn("RELEASE_LOCK 失败（连接 Close 时会自动释放）", zap.Error(relErr))
	}

	return migErr
}

// Close 关闭数据库连接
func Close() error {
	if DB == nil {
		return nil
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

// zapWriter 将 Zap logger 适配为 Gorm logger.Writer
type zapWriter struct {
	logger *zap.Logger
}

func (w *zapWriter) Printf(format string, args ...interface{}) {
	w.logger.Info(fmt.Sprintf(format, args...))
}

// Write 实现 io.Writer 接口（兼容性）
func (w *zapWriter) Write(p []byte) (n int, err error) {
	w.logger.Info(string(p))
	return len(p), nil
}

// 确保 zapWriter 实现了所有必要的接口
var (
	_ io.Writer         = (*zapWriter)(nil)
	_ gormLogger.Writer = (*zapWriter)(nil)
)
