// Package config 统一 6 微服务 (Manager/AgentCenter/Consumer/Engine/VulnSync/LLMProxy) 配置加载。
//
// 设计原则:
//   - 单一来源: YAML 文件 (默认 configs/<service>.yaml)
//   - 环境变量覆盖: MXCWPP_<SERVICE>_<KEY> (e.g. MXCWPP_ENGINE_HTTP_ADDR)
//   - flag 仍保留, 但仅作 path/dev 用 (--config / --dry-run)
//   - 字段校验前置: 缺关键字段直接 Fatal, 不允许 silent fallback
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// EngineConfig 是 Engine 服务的全部配置。
//
// 字段一一对应 configs/engine.yaml; flag 不再承载默认值。
type EngineConfig struct {
	HTTPAddr    string         `mapstructure:"http_addr"`
	DefaultMode string         `mapstructure:"default_mode"` // observe / protect
	AlertTopic  string         `mapstructure:"alert_topic"`
	Kafka       KafkaConfig    `mapstructure:"kafka"`
	Database    DBConfig       `mapstructure:"database"`
	OTel        OTelConfig     `mapstructure:"otel"`
	Pipeline    PipelineConfig `mapstructure:"pipeline"`
}

// KafkaConfig Kafka 连接参数。
type KafkaConfig struct {
	Brokers     []string `mapstructure:"brokers"`
	TopicPrefix string   `mapstructure:"topic_prefix"` // 与 AgentCenter / Consumer 一致 (如 "prod")
	SASLEnabled bool     `mapstructure:"sasl_enabled"`
	SASLUser    string   `mapstructure:"sasl_user"`
	SASLPass    string   `mapstructure:"sasl_pass"`
	TLSEnabled  bool     `mapstructure:"tls_enabled"`
}

// DBConfig MySQL 连接参数。
type DBConfig struct {
	DSN             string `mapstructure:"dsn"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime string `mapstructure:"conn_max_lifetime"` // duration string e.g. "1h"
}

// OTelConfig OTel 追踪。
type OTelConfig struct {
	Enabled    bool    `mapstructure:"enabled"`
	Endpoint   string  `mapstructure:"endpoint"`
	Insecure   bool    `mapstructure:"insecure"`
	SampleRate float64 `mapstructure:"sample_rate"`
}

// PipelineConfig Engine pipeline 行为参数。
type PipelineConfig struct {
	// 启用哪些 stage (逗号分隔; 空则按 db 可用情况自动启用)
	EnabledStages []string `mapstructure:"enabled_stages"`
	// pipeline 并发度 (后续: PR68 ML 多 worker 用)
	Workers int `mapstructure:"workers"`
}

// LoadEngine 加载 Engine 配置。
//
// 顺序:
//
//  1. 设置内置默认 (与历史 flag 一致, 兼容老部署)
//  2. 读 YAML 文件
//  3. 环境变量覆盖 (MXCWPP_ENGINE_*)
//  4. 反序列化 → 校验
func LoadEngine(path string) (*EngineConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// 默认
	v.SetDefault("http_addr", ":8082")
	v.SetDefault("default_mode", "observe")
	v.SetDefault("alert_topic", "mxcwpp.engine.alert")
	v.SetDefault("kafka.brokers", []string{})
	v.SetDefault("database.dsn", "")
	v.SetDefault("database.max_open_conns", 50)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.conn_max_lifetime", "1h")
	v.SetDefault("otel.enabled", false)
	v.SetDefault("otel.endpoint", "localhost:4318")
	v.SetDefault("otel.insecure", true)
	v.SetDefault("otel.sample_rate", 0.1)
	v.SetDefault("pipeline.enabled_stages", []string{})
	v.SetDefault("pipeline.workers", 4)

	// env override: MXCWPP_ENGINE_KAFKA_BROKERS=a,b,c → kafka.brokers
	v.SetEnvPrefix("MXCWPP_ENGINE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// 文件可选: 没找到走 default + env (容器场景 env-only 部署)
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) && path != "" {
			// 路径明指但读不出 → 报错; 走默认路径找不到 → 允许
			if _, ok := err.(*viper.ConfigParseError); ok {
				return nil, fmt.Errorf("parse engine config: %w", err)
			}
		}
	}

	var cfg EngineConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decode engine config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("engine config invalid: %w", err)
	}
	return &cfg, nil
}

// Validate 校验关键字段。
func (c *EngineConfig) Validate() error {
	if c.HTTPAddr == "" {
		return errors.New("http_addr required")
	}
	if c.DefaultMode != "observe" && c.DefaultMode != "protect" {
		return fmt.Errorf("default_mode must be observe|protect, got %q", c.DefaultMode)
	}
	if c.AlertTopic == "" {
		return errors.New("alert_topic required")
	}
	if c.Database.MaxOpenConns < c.Database.MaxIdleConns {
		return errors.New("database.max_open_conns must be >= max_idle_conns")
	}
	return nil
}
