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

	"github.com/imkerbos/mxsec-platform/internal/server/llmproxy/provider"
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

	mu        sync.RWMutex
	blacklist map[string]time.Time // provider name -> blacklisted until
	failures  map[string]int       // provider name -> consecutive failure count
}

// Config 路由器配置。
type Config struct {
	BlacklistTTL     time.Duration // 黑名单存活时间 (默认 5min)
	FailureThreshold int           // 连续失败阈值 (默认 3)
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
		resp, err := p.Complete(ctx, req)
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
		emb, err := p.Embed(ctx, text, model)
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
