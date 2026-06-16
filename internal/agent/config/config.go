// Package config 提供 Agent 配置管理功能
package config

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/viper"
)

// Config 是 Agent 的配置结构
// 分为本地配置（LocalConfig）和远程配置（RemoteConfig）
// 本地配置：Agent 启动时从文件读取，用于连接 Server
// 远程配置：由 Server 下发，支持热更新
type Config struct {
	Local         LocalConfig  `mapstructure:"local"`
	Remote        RemoteConfig // 由 Server 下发，初始为空
	remoteMu      sync.RWMutex // 保护 Remote 字段的并发读写
	BuildVersion  string       // 构建时嵌入的版本（优先级最高）
	SignPublicKey string       // Ed25519 公钥（base64），构建时嵌入
}

// LocalConfig 是本地配置（最小配置）
// 注意：Server 地址可以通过构建时嵌入（-ldflags），配置文件是可选的
type LocalConfig struct {
	// Agent ID 文件路径
	IDFile string `mapstructure:"id_file"`
	// Server 连接配置（可选，如果通过构建时嵌入则不需要）
	Server ServerConfig `mapstructure:"server"`
	// TLS 配置（证书由 Server 下发，这里只存储路径）
	TLS TLSConfig `mapstructure:"tls"`
	// 日志配置（本地日志，避免日志系统本身出问题时无法记录）
	Log LogConfig `mapstructure:"log"`
}

// RemoteConfig 是远程配置（由 Server 下发）
type RemoteConfig struct {
	// 心跳间隔
	HeartbeatInterval time.Duration
	// 工作目录
	WorkDir string
	// 产品名称
	Product string
	// 版本
	Version string
	// 额外配置
	Extra map[string]string
	// 是否已从 Server 获取配置
	Loaded bool
}

// ServerConfig 是 Server 连接配置
type ServerConfig struct {
	ServiceDiscovery ServiceDiscoveryConfig `mapstructure:"service_discovery"`
	AgentCenter      AgentCenterConfig      `mapstructure:"agent_center"`
}

// ServiceDiscoveryConfig 是服务发现配置
type ServiceDiscoveryConfig struct {
	URL string `mapstructure:"url"`
}

// AgentCenterConfig 是 AgentCenter 配置
type AgentCenterConfig struct {
	PrivateHost string   `mapstructure:"private_host"`
	PublicHost  string   `mapstructure:"public_host"`
	Addresses   []string `mapstructure:"addresses"` // 静态 AC 地址列表（SD 不可用时轮转）
}

// TLSConfig 是 TLS 配置
type TLSConfig struct {
	CAFile   string `mapstructure:"ca_file"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`

	// CAFingerprint 是 AC CA 证书的 SHA256 指纹（hex，可含冒号）。
	// 随安装包下发。本地尚无 CA 文件时，agent 首连用它 pin 住 AC，杜绝中间人冒充 AC 下发恶意证书。
	// 为空时回退到旧的 InsecureSkipVerify 首连（仅兼容期，受控内网）。
	CAFingerprint string `mapstructure:"ca_fingerprint"`
	// EnrollToken 是 enroll 引导令牌，经 gRPC metadata 上报 AC，换取单机证书。
	EnrollToken string `mapstructure:"enroll_token"`
}

// LogConfig 是日志配置（已简化，不再需要，保留用于兼容）
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
	MaxAge int    `mapstructure:"max_age"` // 保留天数
}

// Load 从文件加载本地配置（可选，如果使用构建时嵌入则不需要配置文件）
func Load(configPath string) (*Config, error) {
	// 如果配置文件不存在，使用默认配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return LoadDefaults(), nil
	}

	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// 设置默认值
	setDefaults()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var local LocalConfig
	if err := viper.Unmarshal(&local); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	cfg := &Config{
		Local: local,
		Remote: RemoteConfig{
			Loaded: false,
		},
	}

	return cfg, nil
}

// LoadDefaults 加载默认配置（使用标准 Linux 目录结构）
func LoadDefaults() *Config {
	return &Config{
		Local: LocalConfig{
			IDFile: "/var/lib/mxsec-agent/agent_id",
			Server: ServerConfig{
				AgentCenter: AgentCenterConfig{
					PrivateHost: "", // 必须通过构建时嵌入
				},
			},
			TLS: TLSConfig{
				CAFile:   "/var/lib/mxsec-agent/certs/ca.crt",
				CertFile: "/var/lib/mxsec-agent/certs/client.crt",
				KeyFile:  "/var/lib/mxsec-agent/certs/client.key",
			},
			Log: LogConfig{
				Level:  "info",
				Format: "json",
				File:   "/var/log/mxsec-agent/agent.log", // 标准 Linux 日志目录，按天轮转
				MaxAge: 7,                                // 保留7天
			},
		},
		Remote: RemoteConfig{
			Loaded: false,
		},
	}
}

// UpdateRemoteConfig 更新远程配置（由 Server 下发）
func (c *Config) UpdateRemoteConfig(remote *RemoteConfig) {
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	c.Remote = *remote
	c.Remote.Loaded = true
}

// GetHeartbeatInterval 获取心跳间隔（优先使用远程配置）
func (c *Config) GetHeartbeatInterval() time.Duration {
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	if c.Remote.Loaded && c.Remote.HeartbeatInterval > 0 {
		return c.Remote.HeartbeatInterval
	}
	return 60 * time.Second
}

// GetWorkDir 获取工作目录（优先使用远程配置）
func (c *Config) GetWorkDir() string {
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	if c.Remote.Loaded && c.Remote.WorkDir != "" {
		return c.Remote.WorkDir
	}
	return "/var/lib/mxsec-agent"
}

// GetProduct 获取产品名称（优先使用远程配置）
func (c *Config) GetProduct() string {
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	if c.Remote.Loaded && c.Remote.Product != "" {
		return c.Remote.Product
	}
	return "mxsec-agent"
}

// GetVersion 获取版本（优先级：构建时嵌入 > 远程配置 > 默认值）
func (c *Config) GetVersion() string {
	// 1. 优先使用构建时嵌入的版本
	if c.BuildVersion != "" {
		return c.BuildVersion
	}
	// 2. 使用远程配置的版本
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	if c.Remote.Loaded && c.Remote.Version != "" {
		return c.Remote.Version
	}
	return "1.0.0"
}

// setDefaults 设置默认配置值（仅本地配置）
func setDefaults() {
	// Agent ID 文件路径
	viper.SetDefault("local.id_file", "/var/lib/mxsec-agent/agent_id")

	// Server 配置（通常通过构建时嵌入，这里只是默认值）
	viper.SetDefault("local.server.service_discovery.url", "http://localhost:8088")
	viper.SetDefault("local.server.agent_center.private_host", "")
	viper.SetDefault("local.server.agent_center.public_host", "")

	// TLS 默认配置（证书路径，证书由 Server 下发）
	viper.SetDefault("local.tls.ca_file", "/var/lib/mxsec-agent/certs/ca.crt")
	viper.SetDefault("local.tls.cert_file", "/var/lib/mxsec-agent/certs/client.crt")
	viper.SetDefault("local.tls.key_file", "/var/lib/mxsec-agent/certs/client.key")

	// 日志默认配置（标准 Linux 日志目录，按天轮转，保留30天）
	viper.SetDefault("local.log.level", "info")
	viper.SetDefault("local.log.format", "json")
	viper.SetDefault("local.log.file", "/var/log/mxsec-agent/agent.log")
	viper.SetDefault("local.log.max_age", 30)
}
