// Package main 是 LLMProxy 主程序入口。
//
// LLMProxy 是 v2.0 六微服务架构中的多 LLM 厂商适配网关,职责:
//   - 统一 Provider 抽象 (OpenAI/Anthropic/Gemini/DashScope/DeepSeek/Ollama/vLLM)
//   - 场景路由 (告警分析 / Storyline 总结 / 自然语言转查询 / 规则起草)
//   - Redis 24h 缓存 (入参 SHA256 -> 响应)
//   - 主厂商失败 Fallback (3 次失败黑名单 5min)
//   - 租户级 token 上限 + 月度成本告警 + 审计入 mxcwpp.llm.audit
//
// 设计文档: docs/llmproxy-design.md
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/llmproxy"
	"github.com/matrixplusio/mxcwpp/internal/server/llmproxy/provider"
	"github.com/matrixplusio/mxcwpp/internal/server/llmproxy/redact"
	"github.com/matrixplusio/mxcwpp/internal/server/llmproxy/router"
)

func main() {
	configPath := flag.String("config", "configs/llmproxy.yaml", "path to llmproxy config")
	httpAddr := flag.String("http", ":8084", "HTTP listen address")
	openaiKey := flag.String("openai-key", "", "OpenAI API key (env OPENAI_API_KEY)")
	anthropicKey := flag.String("anthropic-key", "", "Anthropic API key (env ANTHROPIC_API_KEY)")
	geminiKey := flag.String("gemini-key", "", "Google Gemini API key (env GEMINI_API_KEY)")
	dashscopeKey := flag.String("dashscope-key", "", "阿里千问 DashScope API key")
	ollamaURL := flag.String("ollama-url", "", "Ollama 本地端点 (如 http://localhost:11434/v1)")
	internalSecret := flag.String("internal-secret", "", "内部接口共享密钥 (env LLMPROXY_INTERNAL_SECRET)")
	allowEgress := flag.Bool("allow-data-egress", false, "允许把数据外发第三方 LLM (默认关，仅本地模型)")
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	// P3-B: GC 调优
	gctune.Apply("llmproxy", gctune.ProfileServer, logger)

	logger.Info("LLMProxy starting",
		zap.String("config", *configPath),
		zap.String("http_addr", *httpAddr),
		zap.String("version", llmproxy.Version),
	)

	// 1. 构造 Provider Registry + 按环境变量/flag 注册
	reg := provider.NewRegistry()
	registerProviders(reg, providerConfigs{
		openaiKey:    pickEnv("OPENAI_API_KEY", *openaiKey),
		anthropicKey: pickEnv("ANTHROPIC_API_KEY", *anthropicKey),
		geminiKey:    pickEnv("GEMINI_API_KEY", *geminiKey),
		dashscopeKey: pickEnv("DASHSCOPE_API_KEY", *dashscopeKey),
		ollamaURL:    *ollamaURL,
	}, logger)

	// 2. 场景路由配置 (从 config 加载,本 PR 用硬编码默认)
	// 批4 合规：数据出境默认关（仅本地模型），外发前脱敏 IP/主机名。
	egress := *allowEgress || pickEnv("LLMPROXY_ALLOW_DATA_EGRESS", "") == "true"
	routes := defaultScenes(reg.Names())
	rt := router.NewRouter(reg, routes, router.Config{
		AllowDataEgress: egress,
		Desensitizer:    redact.New(nil),
	}, logger)
	logger.Info("LLMProxy 数据出境策略", zap.Bool("allow_data_egress", egress), zap.Bool("desensitize", true))

	// 3. HTTP API
	apiHandler := llmproxy.NewCompleteAPIHandler(rt, logger)

	gin.SetMode(gin.ReleaseMode)
	engineHTTP := gin.New()
	engineHTTP.Use(gin.Recovery())
	engineHTTP.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"service":   "llmproxy",
			"version":   llmproxy.Version,
			"providers": reg.Names(),
		})
	})
	engineHTTP.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "# llmproxy metrics placeholder\n")
	})

	// 内部接口（/complete /embed）加 X-Internal-Secret 鉴权，防未授权直接消费 LLM 配额 / 注入。
	secret := pickEnv("LLMPROXY_INTERNAL_SECRET", *internalSecret)
	apiGroup := engineHTTP.Group("")
	if secret != "" {
		apiGroup.Use(llmproxy.InternalAuth(secret))
		logger.Info("LLMProxy 内部认证已启用 (X-Internal-Secret)")
	} else {
		logger.Warn("LLMProxy 内部认证未启用：未配置 LLMPROXY_INTERNAL_SECRET，/complete /embed 无鉴权")
	}
	apiGroup.POST("/complete", apiHandler.Complete)
	apiGroup.POST("/embed", apiHandler.Embed)

	server := &http.Server{
		Addr:              *httpAddr,
		Handler:           engineHTTP,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("LLMProxy HTTP server listening", zap.String("addr", *httpAddr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("LLMProxy shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("LLMProxy stopped")
}

type providerConfigs struct {
	openaiKey    string
	anthropicKey string
	geminiKey    string
	dashscopeKey string
	ollamaURL    string
}

// registerProviders 按可用 key 注册 provider。
func registerProviders(reg *provider.Registry, cfg providerConfigs, logger *zap.Logger) {
	if cfg.openaiKey != "" {
		_ = reg.Register(provider.NewOpenAI(provider.OpenAIConfig{
			Name:     "openai-gpt-4o-mini",
			BaseURL:  "https://api.openai.com/v1",
			APIKey:   cfg.openaiKey,
			Models:   []string{"gpt-4o-mini", "gpt-4o"},
			Provider: "openai",
		}))
	}
	if cfg.anthropicKey != "" {
		_ = reg.Register(provider.NewAnthropic(provider.AnthropicConfig{
			Name:   "anthropic-haiku",
			APIKey: cfg.anthropicKey,
			Models: []string{"claude-3-5-haiku-latest", "claude-3-5-sonnet-latest"},
		}))
	}
	if cfg.geminiKey != "" {
		_ = reg.Register(provider.NewGemini(provider.GeminiConfig{
			Name:   "gemini-flash",
			APIKey: cfg.geminiKey,
			Models: []string{"gemini-1.5-flash", "gemini-1.5-pro"},
		}))
	}
	if cfg.dashscopeKey != "" {
		_ = reg.Register(provider.NewOpenAI(provider.OpenAIConfig{
			Name:     "dashscope-qwen-turbo",
			BaseURL:  "https://dashscope.aliyuncs.com/compatible-mode/v1",
			APIKey:   cfg.dashscopeKey,
			Models:   []string{"qwen-turbo", "qwen-plus", "qwen-max"},
			Provider: "dashscope",
		}))
	}
	if cfg.ollamaURL != "" {
		_ = reg.Register(provider.NewOpenAI(provider.OpenAIConfig{
			Name:     "ollama-local",
			BaseURL:  cfg.ollamaURL,
			Models:   nil, // 不限定 (Ollama 模型列表动态)
			Provider: "ollama",
		}))
	}
	logger.Info("LLMProxy providers 注册完成",
		zap.Strings("providers", reg.Names()),
	)
	if len(reg.Names()) == 0 {
		logger.Warn("没有可用 provider, /complete 调用将全部 502;请配置 *_API_KEY 或 --ollama-url")
	}
}

// defaultScenes 用注册成功的 provider 构造默认场景路由。
func defaultScenes(names []string) []router.SceneRoute {
	return []router.SceneRoute{
		{Scene: router.SceneAlertExplain, Providers: prefer(names, "openai-gpt-4o-mini", "dashscope-qwen-turbo", "ollama-local")},
		{Scene: router.SceneStorylineSummary, Providers: prefer(names, "anthropic-haiku", "openai-gpt-4o-mini", "ollama-local")},
		{Scene: router.SceneNL2Query, Providers: prefer(names, "openai-gpt-4o-mini", "dashscope-qwen-turbo")},
		{Scene: router.SceneRuleDraft, Providers: prefer(names, "anthropic-haiku", "openai-gpt-4o-mini")},
		{Scene: router.SceneEmbedding, Providers: prefer(names, "openai-gpt-4o-mini", "gemini-flash")},
	}
}

// prefer 在 names 中按 want 顺序挑选可用的;不存在的跳过。
func prefer(names []string, want ...string) []string {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	out := []string{}
	for _, w := range want {
		if have[w] {
			out = append(out, w)
		}
	}
	return out
}

// pickEnv 取环境变量优先, flag 兜底。
func pickEnv(env, fallback string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}
