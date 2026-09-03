package config

import (
	"fmt"
	"net"
	"strings"
)

// MinInternalSecretLen 是 internal_secret 的最小长度门槛（商业级要求 ≥32）。
const MinInternalSecretLen = 32

// weakSecretSubstrings 命中即判为弱密钥（模板/常见默认值）。
var weakSecretSubstrings = []string{"change-me", "changeme", "change_me", "changthis", "change-this"}

// weakSecretExact 精确匹配（小写）的常见弱值。
var weakSecretExact = map[string]bool{
	"secret": true, "password": true, "default": true, "test": true, "example": true,
	"mxcwppinternalsecret789": true, // deploy/env.v2.example 历史示例值
}

// validateSecretStrength 是各类密钥/令牌共用的强度策略：非空、非模板占位符、非弱默认值、
// 长度 ≥ MinInternalSecretLen。label 用于把错误定位到具体字段（internal_secret /
// enroll_token / jwt_secret）。三者各自独立取值，仅共用同一套强度判定，不耦合成同一值。
func validateSecretStrength(secret, label string) error {
	s := strings.TrimSpace(secret)
	if s == "" {
		return fmt.Errorf("%s 为空", label)
	}
	if strings.Contains(s, "__") {
		return fmt.Errorf("%s 仍是未替换的模板占位符（%q），请生成真实密钥：openssl rand -hex 32", label, secret)
	}
	low := strings.ToLower(s)
	if weakSecretExact[low] {
		return fmt.Errorf("%s 为常见弱默认值，请生成真实密钥：openssl rand -hex 32", label)
	}
	for _, w := range weakSecretSubstrings {
		if strings.Contains(low, w) {
			return fmt.Errorf("%s 含明显默认标记（%q），请生成真实密钥：openssl rand -hex 32", label, w)
		}
	}
	if len(s) < MinInternalSecretLen {
		return fmt.Errorf("%s 长度不足（%d < %d），请生成足够强度的密钥：openssl rand -hex 32", label, len(s), MinInternalSecretLen)
	}
	return nil
}

// ValidateInternalSecret 校验 internal_secret 强度：非空、非模板占位符、非弱默认值、长度 ≥32。
// Manager↔AgentCenter 管理面鉴权与集群渲染共用同一策略。
func ValidateInternalSecret(secret string) error {
	return validateSecretStrength(secret, "internal_secret")
}

// ValidateEnrollToken 校验 mtls.enroll_token 强度。与 internal_secret 同策略、独立取值。
// AgentCenter 生产模式（非 insecure_dev_mode）要求它必须存在且强，否则拒绝启动。
func ValidateEnrollToken(token string) error {
	return validateSecretStrength(token, "mtls.enroll_token")
}

// ValidateJWTSecret 校验 server.jwt_secret 强度。与 internal_secret 同策略、独立取值。
func ValidateJWTSecret(secret string) error {
	return validateSecretStrength(secret, "server.jwt_secret")
}

// ValidateAgentCenter 校验 AgentCenter 特有的启动前置条件。
//
// 仅由 AgentCenter 初始化调用（Manager 与 AC 共用同一 Config 结构，
// 故此规则不能塞进通用 Config.Validate）。
//
// 网络边界 fail-closed：AC 的 HTTP 管理端口（承载 /command、/dependency/install 等
// 高危接口）一旦绑定到非 loopback 地址（0.0.0.0 / 通配 / 可路由 IP），就必须配置
// 非空、非模板占位符、足够强度的 internal_secret；否则拒绝启动，避免管理面裸奔。
func (c *Config) ValidateAgentCenter() error {
	// 1. 管理面强密钥（原有规则保持）。
	if err := ValidateInternalSecret(c.Server.InternalSecret); err != nil {
		// 无论绑定地址如何都必须有强密钥，否则 AC 受保护接口全部 401、注册/命令下发永久失败——
		// fail-fast，不允许“健康但控制链路失效”的静默半失效。非 loopback 绑定额外强调网络风险。
		if !isLoopbackBind(c.Server.HTTP.Host) {
			return fmt.Errorf("AgentCenter HTTP 管理端口绑定到非 loopback 地址 %q（管理面裸奔风险），且 %w", c.Server.HTTP.Address(), err)
		}
		return fmt.Errorf("AgentCenter 要求强 server.internal_secret（否则 /command 等接口全部 401、AC 注册失败）：%w", err)
	}

	// 2. Agent↔AC 信任链 fail-fast（E-SEC-3）。
	//    显式 insecure_dev_mode 仅供本地/回环开发放行弱信任配置，且必须 gRPC + HTTP 双回环绑定；
	//    官方 prod/deploy/cluster 渲染绝不设置此项。
	if c.MTLS.InsecureDevMode {
		if !isLoopbackBind(c.Server.HTTP.Host) || !isLoopbackBind(c.Server.GRPC.Host) {
			return fmt.Errorf("mtls.insecure_dev_mode 仅允许在 gRPC 与 HTTP 均绑定回环地址时使用（当前 grpc=%q http=%q）",
				c.Server.GRPC.Host, c.Server.HTTP.Host)
		}
		return nil
	}
	return c.validateAgentTrust()
}

// ValidateManager 校验 Manager 启动前置条件：内部路由（/api/v1/internal/*）鉴权
// 要求强 server.internal_secret，缺失即 fail-fast，避免内部链路静默失效。
// 仅由 Manager 专用初始化路径调用，不影响 Consumer/Engine 等共用 Config 的进程。
func (c *Config) ValidateManager() error {
	if err := ValidateInternalSecret(c.Server.InternalSecret); err != nil {
		return fmt.Errorf("manager 要求强 server.internal_secret（内部服务路由鉴权 + AC 命令下发）：%w", err)
	}
	if err := ValidateJWTSecret(c.Server.JWTSecret); err != nil {
		return fmt.Errorf("manager 要求强 server.jwt_secret（登录令牌签发/校验）：%w", err)
	}
	// 安全加固前提 fail-fast：登录限流 / JWT 黑名单均依赖 Redis，缺 Redis 时表面 enabled
	// 实际不工作（静默半失效）。启用则要求配置了 Redis 端点。
	sec := c.Server.Security
	if sec.LoginRateLimit.Enabled || sec.JWTBlacklist.Enabled {
		if strings.TrimSpace(c.Redis.Addr) == "" && !c.Redis.Sentinel && len(c.Redis.SentinelAddrs) == 0 {
			return fmt.Errorf("server.security.login_rate_limit/jwt_blacklist 已启用但未配置 Redis（redis.addr 或 sentinel），拒绝以避免安全策略静默失效")
		}
	}
	return nil
}

// isLoopbackBind 判断监听 host 是否仅回环可达（此时无需强制 internal_secret）。
// 空 host 由 setDefaults 归一为 0.0.0.0（对外可达），按非 loopback 处理。
func isLoopbackBind(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost":
		return true
	case "", "0.0.0.0", "::", "[::]":
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
