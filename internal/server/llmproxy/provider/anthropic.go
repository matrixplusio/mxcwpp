package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicConfig 是 Claude API 驱动配置。
type AnthropicConfig struct {
	Name    string
	BaseURL string // https://api.anthropic.com/v1
	APIKey  string
	Models  []string // claude-3-5-haiku-latest / claude-3-5-sonnet-latest / claude-3-opus-latest
	Version string   // anthropic-version header, 默认 2023-06-01
	Timeout time.Duration
}

// AnthropicProvider 实现 Provider interface (调 /v1/messages 接口)。
type AnthropicProvider struct {
	cfg    AnthropicConfig
	client *http.Client
}

// NewAnthropic 构造 Anthropic Claude provider。
func NewAnthropic(cfg AnthropicConfig) *AnthropicProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com/v1"
	}
	if cfg.Version == "" {
		cfg.Version = "2023-06-01"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &AnthropicProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (p *AnthropicProvider) Name() string              { return p.cfg.Name }
func (p *AnthropicProvider) Type() string              { return "anthropic" }
func (p *AnthropicProvider) SupportedModels() []string { return p.cfg.Models }

func (p *AnthropicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if !p.supports(req.Model) {
		return nil, fmt.Errorf("%w: %s", ErrModelNotSupported, req.Model)
	}

	body := map[string]any{
		"model":      req.Model,
		"max_tokens": maxOr(req.MaxTokens, 4096),
		"messages":   buildAnthropicMessages(req.Messages),
	}
	if req.System != "" {
		body["system"] = req.System
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}

	jb, _ := json.Marshal(body)
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jb))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", p.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", p.cfg.Version)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(rb))
	}

	var raw struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rb, &raw); err != nil {
		return nil, fmt.Errorf("anthropic unmarshal: %w", err)
	}

	var content strings.Builder
	for _, c := range raw.Content {
		if c.Type == "text" {
			content.WriteString(c.Text)
		}
	}
	return &CompletionResponse{
		Content:      content.String(),
		Model:        raw.Model,
		FinishReason: raw.StopReason,
		TokensIn:     raw.Usage.InputTokens,
		TokensOut:    raw.Usage.OutputTokens,
		Provider:     "anthropic",
	}, nil
}

// Embed Anthropic 暂未提供 embedding API。
func (p *AnthropicProvider) Embed(_ context.Context, _ string, _ string) ([]float32, error) {
	return nil, ErrEmbedNotSupported
}

func (p *AnthropicProvider) HealthCheck(ctx context.Context) error {
	// 用一个最小请求探活
	req := CompletionRequest{
		Model:     firstNonEmpty(p.cfg.Models, "claude-3-5-haiku-latest"),
		Messages:  []Message{{Role: "user", Content: "ping"}},
		MaxTokens: 1,
	}
	_, err := p.Complete(ctx, req)
	if err != nil && !strings.Contains(err.Error(), "credit") {
		return err
	}
	return nil
}

func (p *AnthropicProvider) supports(m string) bool {
	if len(p.cfg.Models) == 0 {
		return true
	}
	for _, s := range p.cfg.Models {
		if s == m {
			return true
		}
	}
	return false
}

func buildAnthropicMessages(msgs []Message) []map[string]any {
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		role := m.Role
		if role == "system" {
			continue // system 走 top-level system 字段
		}
		out = append(out, map[string]any{"role": role, "content": m.Content})
	}
	return out
}

func maxOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func firstNonEmpty(list []string, def string) string {
	for _, v := range list {
		if v != "" {
			return v
		}
	}
	return def
}

var _ Provider = (*AnthropicProvider)(nil)
