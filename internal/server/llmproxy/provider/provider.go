// Package provider 定义 LLM Provider 抽象与多厂商适配实现。
//
// 支持厂商 (Sprint 2 PR18 起逐步加入):
//   - OpenAI         (GPT-4o / 4o-mini)
//   - Anthropic      (Claude 3.5 Sonnet / Haiku)
//   - Google Gemini  (1.5 Pro / Flash)
//   - 阿里千问 DashScope (Qwen-Max / Plus / Turbo)
//   - 其他 OpenAI-Compatible (DeepSeek / Kimi / 智谱 / Ollama / vLLM)
//
// 设计文档: docs/llmproxy-design.md
package provider

import (
	"context"
	"fmt"
)

// CompletionRequest 是 LLM 补全请求 (统一各厂商差异)。
type CompletionRequest struct {
	Model       string            `json:"model"`
	System      string            `json:"system,omitempty"`
	Messages    []Message         `json:"messages"`
	Temperature float64           `json:"temperature,omitempty"`
	MaxTokens   int               `json:"max_tokens,omitempty"`
	Stream      bool              `json:"stream,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"` // tenant_id / scene / trace_id
}

// Message 是对话消息。Role: system / user / assistant.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// CompletionResponse 是 LLM 补全结果。
type CompletionResponse struct {
	Content      string  `json:"content"`
	Model        string  `json:"model"`
	FinishReason string  `json:"finish_reason"`
	TokensIn     int     `json:"tokens_in"`
	TokensOut    int     `json:"tokens_out"`
	CostUSD      float64 `json:"cost_usd"`
	Provider     string  `json:"provider"`
}

// Provider 是 LLM 厂商驱动的统一接口。
//
// 每种厂商在 provider/ 下独立子包实现 Provider, main 启动时注册到 Router。
type Provider interface {
	// Name 返回 provider 唯一名 (config 用)。
	Name() string

	// Type 返回 provider 类型 (openai/anthropic/gemini/dashscope/ollama)。
	Type() string

	// SupportedModels 返回该 provider 支持的模型列表。
	SupportedModels() []string

	// Complete 单次补全。
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)

	// Embed 计算 embedding (可选; 不支持返回 ErrEmbedNotSupported)。
	Embed(ctx context.Context, text string, model string) ([]float32, error)

	// HealthCheck 探活 (主厂商失败 Fallback 时用)。
	HealthCheck(ctx context.Context) error
}

// 标准错误
var (
	ErrEmbedNotSupported   = fmt.Errorf("provider: embedding not supported")
	ErrModelNotSupported   = fmt.Errorf("provider: model not supported")
	ErrProviderUnavailable = fmt.Errorf("provider: temporarily unavailable")
)

// Registry 是 provider 注册表。
type Registry struct {
	providers map[string]Provider
}

// NewRegistry 构造空 registry。
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Register 注册 provider。同名重复返回错误。
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return fmt.Errorf("provider: must not be nil")
	}
	name := p.Name()
	if name == "" {
		return fmt.Errorf("provider: Name() must not be empty")
	}
	if _, ok := r.providers[name]; ok {
		return fmt.Errorf("provider: %q already registered", name)
	}
	r.providers[name] = p
	return nil
}

// Get 按名取 provider。
func (r *Registry) Get(name string) (Provider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

// Names 列出所有已注册 provider 名。
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.providers))
	for name := range r.providers {
		out = append(out, name)
	}
	return out
}
