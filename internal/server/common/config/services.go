package config

// 5 个微服务的 viper 配置 schema (P1-5)。
//
// Manager / AgentCenter / Consumer / VulnSync / LLMProxy 各自独立配置,
// 共享 Database / Kafka / OTel 子结构。

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// CommonInfra 共享基础设施配置 (5 个服务都用)。
type CommonInfra struct {
	Database DBConfig    `mapstructure:"database"`
	Redis    RedisConfig `mapstructure:"redis"`
	Kafka    KafkaConfig `mapstructure:"kafka"`
	OTel     OTelConfig  `mapstructure:"otel"`
}

// RedisConfig Redis 连接参数。
type RedisConfig struct {
	Addr     string `mapstructure:"addr"` // host:port
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// ManagerConfig Manager 微服务配置。
type ManagerConfig struct {
	HTTPAddr       string `mapstructure:"http_addr"`
	JWTSecret      string `mapstructure:"jwt_secret"`
	InternalSecret string `mapstructure:"internal_secret"`
	UploadDir      string `mapstructure:"upload_dir"`
	CommonInfra    `mapstructure:",squash"`
	ClickHouse     CHConfig      `mapstructure:"clickhouse"`
	Plugins        PluginsConfig `mapstructure:"plugins"`
}

// CHConfig ClickHouse.
type CHConfig struct {
	Addr     string `mapstructure:"addr"`
	Database string `mapstructure:"database"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

// PluginsConfig 插件下载相关.
type PluginsConfig struct {
	BaseURL string `mapstructure:"base_url"`
}

// AgentCenterConfig AC 微服务配置.
type AgentCenterConfig struct {
	GRPCAddr        string `mapstructure:"grpc_addr"`
	HTTPAddr        string `mapstructure:"http_addr"`
	MaxAgents       int    `mapstructure:"max_agents"`
	ManagerEndpoint string `mapstructure:"manager_endpoint"`
	InternalSecret  string `mapstructure:"internal_secret"`
	TLSCertFile     string `mapstructure:"tls_cert_file"`
	TLSKeyFile      string `mapstructure:"tls_key_file"`
	CAFile          string `mapstructure:"ca_file"`
	CommonInfra     `mapstructure:",squash"`
}

// ConsumerConfig Consumer 微服务配置.
type ConsumerConfig struct {
	HTTPAddr       string `mapstructure:"http_addr"`
	AnalysisEnable bool   `mapstructure:"analysis_enabled"`
	ConsumerGroup  string `mapstructure:"consumer_group"`
	BatchSize      int    `mapstructure:"batch_size"`
	BatchTimeout   string `mapstructure:"batch_timeout"` // duration string
	CommonInfra    `mapstructure:",squash"`
	ClickHouse     CHConfig `mapstructure:"clickhouse"`
}

// VulnSyncConfig VulnSync 微服务配置.
type VulnSyncConfig struct {
	HTTPAddr      string   `mapstructure:"http_addr"`
	Sources       []string `mapstructure:"sources"`       // 启用的源列表
	NVDAPIKey     string   `mapstructure:"nvd_api_key"`   // NVD API key
	SyncInterval  string   `mapstructure:"sync_interval"` // duration string
	AdvisoryTopic string   `mapstructure:"advisory_topic"`
	CommonInfra   `mapstructure:",squash"`
}

// LLMProxyConfig LLMProxy 微服务配置.
type LLMProxyConfig struct {
	HTTPAddr    string                       `mapstructure:"http_addr"`
	Providers   map[string]LLMProviderConfig `mapstructure:"providers"`
	Quota       LLMQuotaConfig               `mapstructure:"quota"`
	CommonInfra `mapstructure:",squash"`
}

// LLMProviderConfig 单 provider 配置.
type LLMProviderConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
	BaseURL string `mapstructure:"base_url"`
	Model   string `mapstructure:"model"`
}

// LLMQuotaConfig 配额.
type LLMQuotaConfig struct {
	DailyTokensPerTenant int64 `mapstructure:"daily_tokens_per_tenant"`
	RPSPerTenant         int   `mapstructure:"rps_per_tenant"`
}

// LoadManager 加载 Manager 配置。
func LoadManager(path string) (*ManagerConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	v.SetDefault("http_addr", ":8080")
	v.SetDefault("upload_dir", "./uploads")
	v.SetDefault("database.max_open_conns", 100)
	v.SetDefault("database.max_idle_conns", 20)
	v.SetDefault("database.conn_max_lifetime", "1h")
	v.SetDefault("otel.enabled", false)
	v.SetDefault("otel.sample_rate", 0.1)

	v.SetEnvPrefix("MXCWPP_MANAGER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.ReadInConfig() // 文件可选

	var cfg ManagerConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decode manager config: %w", err)
	}
	if cfg.HTTPAddr == "" {
		return nil, errors.New("manager.http_addr required")
	}
	if cfg.JWTSecret == "" || len(cfg.JWTSecret) < 32 {
		return nil, errors.New("manager.jwt_secret required (>= 32 chars)")
	}
	return &cfg, nil
}

// LoadAgentCenter 加载 AC 配置.
func LoadAgentCenter(path string) (*AgentCenterConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	v.SetDefault("grpc_addr", ":6751")
	v.SetDefault("http_addr", ":6752")
	v.SetDefault("max_agents", 50000)
	v.SetDefault("manager_endpoint", "http://localhost:8080")
	v.SetDefault("database.max_open_conns", 50)
	v.SetDefault("database.max_idle_conns", 10)

	v.SetEnvPrefix("MXCWPP_AC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.ReadInConfig()

	var cfg AgentCenterConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decode ac config: %w", err)
	}
	if cfg.ManagerEndpoint == "" {
		return nil, errors.New("ac.manager_endpoint required")
	}
	return &cfg, nil
}

// LoadConsumer 加载 Consumer 配置.
func LoadConsumer(path string) (*ConsumerConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	v.SetDefault("http_addr", ":8081")
	v.SetDefault("analysis_enabled", false)
	v.SetDefault("consumer_group", "mxcwpp-consumer")
	v.SetDefault("batch_size", 500)
	v.SetDefault("batch_timeout", "5s")

	v.SetEnvPrefix("MXCWPP_CONSUMER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.ReadInConfig()

	var cfg ConsumerConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decode consumer config: %w", err)
	}
	if len(cfg.Kafka.Brokers) == 0 {
		return nil, errors.New("consumer.kafka.brokers required")
	}
	return &cfg, nil
}

// LoadVulnSync 加载 VulnSync 配置.
func LoadVulnSync(path string) (*VulnSyncConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	v.SetDefault("http_addr", ":8083")
	v.SetDefault("sync_interval", "6h")
	v.SetDefault("advisory_topic", "mxcwpp.vuln.advisory")
	v.SetDefault("sources", []string{
		"nvd", "osv", "cisa-kev", "epss",
		"redhat", "ubuntu", "debian", "alpine", "suse",
		"openeuler", "anolis", "kylin", "uos", "cnnvd", "edb",
	})

	v.SetEnvPrefix("MXCWPP_VULNSYNC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.ReadInConfig()

	var cfg VulnSyncConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decode vulnsync config: %w", err)
	}
	if cfg.HTTPAddr == "" {
		return nil, errors.New("vulnsync.http_addr required")
	}
	return &cfg, nil
}

// LoadLLMProxy 加载 LLMProxy 配置.
func LoadLLMProxy(path string) (*LLMProxyConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	v.SetDefault("http_addr", ":8085")
	v.SetDefault("quota.daily_tokens_per_tenant", 1000000)
	v.SetDefault("quota.rps_per_tenant", 10)

	v.SetEnvPrefix("MXCWPP_LLMPROXY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.ReadInConfig()

	var cfg LLMProxyConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decode llmproxy config: %w", err)
	}
	if cfg.HTTPAddr == "" {
		return nil, errors.New("llmproxy.http_addr required")
	}
	return &cfg, nil
}
