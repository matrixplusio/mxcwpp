// Package database 提供 ClickHouse 客户端初始化
package database

import (
	"fmt"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

var globalCHConn chdriver.Conn

// InitClickHouse 初始化 ClickHouse 连接（原生协议）
// 当 cfg.Enabled=false 时返回 (nil, nil)，调用方需判断 nil
func InitClickHouse(cfg config.ClickHouseConfig, logger *zap.Logger) (chdriver.Conn, error) {
	if !cfg.Enabled {
		logger.Info("ClickHouse 未启用，跳过初始化")
		return nil, nil
	}

	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	maxOpenConns := cfg.MaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = 10
	}
	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 5
	}
	connMaxLifetime := cfg.ConnMaxLifetime
	if connMaxLifetime == 0 {
		connMaxLifetime = 10 * time.Minute
	}

	conn, err := openClickHouse(cfg, cfg.Username, cfg.Password, maxOpenConns, maxIdleConns, connMaxLifetime, dialTimeout, readTimeout)
	if err != nil {
		return nil, err
	}

	globalCHConn = conn
	logger.Info("ClickHouse 已连接",
		zap.Strings("addrs", cfg.Addrs),
		zap.String("database", cfg.Database),
	)
	return conn, nil
}

// InitClickHouseAuthWriter 用 auth_writer 账号另开一个连接，只给 auth_events 的写入用。
// 没配这个账号时返回 nil, nil，调用方沿用主连接。
func InitClickHouseAuthWriter(cfg config.ClickHouseConfig, logger *zap.Logger) (chdriver.Conn, error) {
	if !cfg.Enabled || cfg.AuthWriter.Username == "" {
		return nil, nil
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	// 认证事件量小，批量写入一次只占一个连接。
	conn, err := openClickHouse(cfg, cfg.AuthWriter.Username, cfg.AuthWriter.Password, 2, 1, 10*time.Minute, dialTimeout, readTimeout)
	if err != nil {
		return nil, err
	}
	logger.Info("auth_events 使用独立的写入账号", zap.String("username", cfg.AuthWriter.Username))
	return conn, nil
}

func openClickHouse(cfg config.ClickHouseConfig, username, password string, maxOpen, maxIdle int,
	lifetime, dialTimeout, readTimeout time.Duration) (chdriver.Conn, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: cfg.Addrs,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: username,
			Password: password,
		},
		MaxOpenConns:    maxOpen,
		MaxIdleConns:    maxIdle,
		ConnMaxLifetime: lifetime,
		DialTimeout:     dialTimeout,
		ReadTimeout:     readTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("初始化 ClickHouse 连接失败: %w", err)
	}
	return conn, nil
}

// CloseClickHouse 关闭全局 ClickHouse 连接
func CloseClickHouse() error {
	if globalCHConn != nil {
		return globalCHConn.Close()
	}
	return nil
}
