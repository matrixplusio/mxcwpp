// Package router 是 LLMProxy 的场景路由器。
//
// 把 (scene, tenant_id) 路由到合适的 Provider 列表,
// 主厂商失败时按优先级 fallback。
//
// 设计文档: docs/llmproxy-design.md §3.2 路由 + §3.3 Fallback
package router

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/llmproxy/provider"
	"github.com/matrixplusio/mxcwpp/internal/server/llmproxy/redact"
)

// Scene 是 LLM 调用场景。
type Scene string

const (
	SceneAlertExplain     Scene = "alert_explain"
	SceneStorylineSummary Scene = "storyline_summary"
	SceneNL2Query         Scene = "nl2query"
	SceneRuleDraft        Scene = "rule_draft"
	SceneEmbedding        Scene = "embedding"
)

// SceneRoute 定义场景到 provider 优先级列表的映射。
type SceneRoute struct {
	Scene     Scene
	Providers []string // 按优先级顺序; [0] 失败 → [1] 失败 → [2] ...
}

// Router 场景路由器 + Fallback 黑名单。
type Router struct {
	registry         *provider.Registry
	routes           map[Scene][]string
	blacklistTTL     time.Duration
	failureThreshold int
	logger           *zap.Logger

	allowDataEgress bool
	desensitizer    *redact.Desensitizer

	mu        sync.RWMutex
	blacklist map[string]time.Time // provider name -> blacklisted until
	failures  map[string]int       // provider name -> consecutive failure count
}

// Config 路由器配置。
type Config struct {
	BlacklistTTL     time.Duration // 黑名单存活时间 (默认 5min)
	FailureThreshold int           // 连续失败阈值 (默认 3)

	// 批4 合规：数据出境管控。AllowDataEgress=false 时只路由到本地 provider（ollama 等），
	// 跳过外部厂商；Desensitizer 非 nil 时外发前抹去 IP/主机名。
	AllowDataEgress bool
	Desensitizer    *redact.Desensitizer
}

// NewRouter 构造路由器。
func NewRouter(reg *provider.Registry, routes []SceneRoute, cfg Config, logger *zap.Logger) *Router {
	if cfg.BlacklistTTL <= 0 {
		cfg.BlacklistTTL = 5 * time.Minute
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	r := &Router{
		registry:         reg,
		routes:           make(map[Scene][]string),
		blacklistTTL:     cfg.BlacklistTTL,
		failureThreshold: cfg.FailureThreshold,
		allowDataEgress:  cfg.AllowDataEgress,
		desensitizer:     cfg.Desensitizer,
		logger:           logger,
		blacklist:        make(map[string]time.Time),
		failures:         make(map[string]int),
	}
	for _, route := range routes {
		r.routes[route.Scene] = route.Providers
	}
	return r
}

// ErrNoAvailableProvider 全部 provider 失败 / 不可用。
var ErrNoAvailableProvider = errors.New("router: no available provider")

// Complete 按 scene 路由 + Fallback 链调用。
func (r *Router) Complete(ctx context.Context, scene Scene, req provider.CompletionRequest) (*provider.CompletionResponse, error) {
	providers, ok := r.routes[scene]
	if !ok || len(providers) == 0 {
		return nil, fmt.Errorf("router: scene %q not configured", scene)
	}

	var lastErr error
	for _, name := range providers {
		if r.isBlacklisted(name) {
			continue
		}
		p, ok := r.registry.Get(name)
		if !ok {
			r.logger.Warn("provider 未注册,跳过", zap.String("name", name))
			continue
		}
		// 数据出境管控：未开出境时跳过外部 provider，只走本地模型。
		if !r.allowDataEgress && !isLocalProvider(p) {
			r.logger.Warn("数据出境未开启,跳过外部 provider",
				zap.String("provider", name), zap.String("type", p.Type()))
			continue
		}
		outReq := r.applyEgressPolicy(req, p)
		resp, err := p.Complete(ctx, outReq)
		if err != nil {
			lastErr = err
			r.recordFailure(name)
			r.logger.Warn("provider 调用失败,fallback 下一个",
				zap.String("scene", string(scene)),
				zap.String("provider", name),
				zap.Error(err),
			)
			continue
		}
		r.clearFailure(name)
		return resp, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: last error: %v", ErrNoAvailableProvider, lastErr)
	}
	return nil, ErrNoAvailableProvider
}

// Embed 按 SceneEmbedding 路由 + Fallback。
func (r *Router) Embed(ctx context.Context, text string, model string) ([]float32, error) {
	providers, ok := r.routes[SceneEmbedding]
	if !ok || len(providers) == 0 {
		return nil, fmt.Errorf("router: embedding scene not configured")
	}

	var lastErr error
	for _, name := range providers {
		if r.isBlacklisted(name) {
			continue
		}
		p, ok := r.registry.Get(name)
		if !ok {
			continue
		}
		if !r.allowDataEgress && !isLocalProvider(p) {
			r.logger.Warn("数据出境未开启,跳过外部 embedding provider",
				zap.String("provider", name), zap.String("type", p.Type()))
			continue
		}
		outText := text
		if !isLocalProvider(p) && r.desensitizer != nil {
			outText = r.desensitizer.Redact(text)
		}
		emb, err := p.Embed(ctx, outText, model)
		if err != nil {
			lastErr = err
			r.recordFailure(name)
			continue
		}
		r.clearFailure(name)
		return emb, nil
	}
	return nil, fmt.Errorf("%w: %v", ErrNoAvailableProvider, lastErr)
}

func (r *Router) isBlacklisted(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	until, ok := r.blacklist[name]
	if !ok {
		return false
	}
	return time.Now().Before(until)
}

func (r *Router) recordFailure(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures[name]++
	if r.failures[name] >= r.failureThreshold {
		r.blacklist[name] = time.Now().Add(r.blacklistTTL)
		r.logger.Warn("provider 进入黑名单",
			zap.String("name", name),
			zap.Int("failures", r.failures[name]),
			zap.Duration("blacklist_ttl", r.blacklistTTL),
		)
		r.failures[name] = 0
	}
}

func (r *Router) clearFailure(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, name)
}

// localProviderTypes 是视为本地/内网（数据不出境）的 provider 类型。
var localProviderTypes = map[string]bool{"ollama": true, "vllm": true}

// isLocalProvider 判断 provider 是否本地部署（数据不出境、无需脱敏）。
func isLocalProvider(p provider.Provider) bool {
	return localProviderTypes[p.Type()]
}

// applyEgressPolicy 外发外部 provider 前脱敏 System 与各消息内容；本地 provider 原样返回。
func (r *Router) applyEgressPolicy(req provider.CompletionRequest, p provider.Provider) provider.CompletionRequest {
	if isLocalProvider(p) || r.desensitizer == nil {
		return req
	}
	out := req
	out.System = r.desensitizer.Redact(req.System)
	out.Messages = make([]provider.Message, len(req.Messages))
	for i, m := range req.Messages {
		m.Content = r.desensitizer.Redact(m.Content)
		out.Messages[i] = m
	}
	return out
}
