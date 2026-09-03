package config

import "testing"

func acCfg(host, secret string) *Config {
	c := &Config{}
	c.Server.HTTP.Host = host
	c.Server.HTTP.Port = 8080
	c.Server.InternalSecret = secret
	return c
}

const strongSecret = "b3a1f0c9d8e7a6b5c4d3e2f1a0b9c8d7" // 32 hex chars

func TestValidateInternalSecret(t *testing.T) {
	cases := []struct {
		name, secret string
		wantErr      bool
	}{
		{"empty", "", true},
		{"blank", "   ", true},
		{"placeholder", "__INTERNAL_SECRET__", true},
		{"weak change-me", "change-me-but-quite-long-padding-xxxx", true},
		{"weak changeme", "supersafeCHANGEMEvaluepaddedlong1234", true},
		{"weak exact", "password", true},
		{"weak env example", "mxcwppInternalSecret789", true},
		{"too short 31", "b3a1f0c9d8e7a6b5c4d3e2f1a0b9c8d", true},
		{"exactly 32", strongSecret, false},
		{"long random", "0123456789abcdef0123456789abcdef0123456789", false},
	}
	for _, c := range cases {
		err := ValidateInternalSecret(c.secret)
		if c.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: expected nil, got %v", c.name, err)
		}
	}
}

// TestValidateAgentCenter_SecretGate 隔离 internal_secret 强度闸门。
// 用 insecure_dev_mode + 双回环绑定跳过信任链校验，聚焦密钥规则本身。
func TestValidateAgentCenter_SecretGate(t *testing.T) {
	devCfg := func(secret string) *Config {
		c := &Config{}
		c.Server.HTTP.Host = "127.0.0.1"
		c.Server.HTTP.Port = 8081
		c.Server.GRPC.Host = "127.0.0.1"
		c.Server.GRPC.Port = 6751
		c.Server.InternalSecret = secret
		c.MTLS.InsecureDevMode = true
		return c
	}
	cases := []struct {
		name, secret string
		wantErr      bool
	}{
		{"empty", "", true},
		{"weak", "shortsecret", true},
		{"placeholder", "__INTERNAL_SECRET__", true},
		{"strong", strongSecret, false},
	}
	for _, c := range cases {
		if err := devCfg(c.secret).ValidateAgentCenter(); (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got %v", c.name, c.wantErr, err)
		}
	}
	// 空/弱密钥在非 loopback 绑定同样一律拒绝（不依赖 dev 模式）。
	for _, host := range []string{"0.0.0.0", "10.0.0.5", ""} {
		if err := acCfg(host, "").ValidateAgentCenter(); err == nil {
			t.Errorf("host=%q empty secret 应拒绝", host)
		}
	}
}

// TestValidateAgentCenter_DevModeLoopbackOnly insecure_dev_mode 只能在双回环绑定时使用。
func TestValidateAgentCenter_DevModeLoopbackOnly(t *testing.T) {
	c := &Config{}
	c.Server.HTTP.Host = "0.0.0.0" // 非回环
	c.Server.HTTP.Port = 8081
	c.Server.GRPC.Host = "127.0.0.1"
	c.Server.GRPC.Port = 6751
	c.Server.InternalSecret = strongSecret
	c.MTLS.InsecureDevMode = true
	if err := c.ValidateAgentCenter(); err == nil {
		t.Fatal("insecure_dev_mode 在非回环绑定时应拒绝")
	}
}

// TestValidateAgentCenter_ProdRequiresTrust 非 dev 模式下缺信任配置必须 fail-fast。
func TestValidateAgentCenter_ProdRequiresTrust(t *testing.T) {
	c := acCfg("0.0.0.0", strongSecret) // 强密钥但无 mtls 信任配置
	if err := c.ValidateAgentCenter(); err == nil {
		t.Fatal("生产模式缺 mtls 信任配置应拒绝")
	}
}

// TestValidateManager Manager internal_secret + jwt_secret 的 fail-fast。
func TestValidateManager(t *testing.T) {
	mgrCfg := func(internal, jwt string) *Config {
		c := acCfg("0.0.0.0", internal)
		c.Server.JWTSecret = jwt
		return c
	}
	cases := []struct {
		name, internal, jwt string
		wantErr             bool
	}{
		{"both empty", "", "", true},
		{"weak internal", "changeme", strongSecret, true},
		{"short internal", "shortsecret", strongSecret, true},
		{"empty jwt", strongSecret, "", true},
		{"weak jwt", strongSecret, "changeme", true},
		{"both strong", strongSecret, strongSecret, false},
	}
	for _, c := range cases {
		if err := mgrCfg(c.internal, c.jwt).ValidateManager(); (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got %v", c.name, c.wantErr, err)
		}
	}
}

// TestValidateManager_SecurityRequiresRedis 安全特性启用但缺 Redis 应 fail-fast。
func TestValidateManager_SecurityRequiresRedis(t *testing.T) {
	c := acCfg("0.0.0.0", strongSecret)
	c.Server.JWTSecret = strongSecret
	c.Server.Security.JWTBlacklist.Enabled = true
	c.Redis.Addr = "" // 无 Redis
	if err := c.ValidateManager(); err == nil {
		t.Fatal("jwt_blacklist 启用但无 Redis 应拒绝")
	}
	c.Redis.Addr = "redis:6379"
	if err := c.ValidateManager(); err != nil {
		t.Fatalf("配置 Redis 后应通过: %v", err)
	}
}
